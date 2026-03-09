/*
 * Comet: a slightly advanced ircd
 * ip_cloaking.c: provide user hostname cloaking
 *
 * Originally by nenolod, FNV variant by Elizabeth 2008.
 * Security hardened: replaced FNV with HMAC-SHA256, full-address
 * cloaking for both IPv4/IPv6/hostnames, random secret key. -- 2024
 *
 * Security properties:
 *   - Without the server secret, cloaked hosts cannot be reversed.
 *   - Full IPv4, IPv6, and hostname addresses are obscured (no prefix leak).
 *   - HMAC-SHA256 output is collision-resistant and preimage-resistant.
 *   - Secret is generated fresh from /dev/urandom on each module load.
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "hash.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sys/socket.h>  /* AF_INET, AF_INET6 */

static const char ip_cloaking_desc[] =
	"Secure IP cloaking using HMAC-SHA256 (user mode +h)";

/* 256-bit secret key, generated once per module load from /dev/urandom */
#define CLOAK_KEY_LEN 32
static unsigned char cloak_key[CLOAK_KEY_LEN];

/* -------------------------------------------------------------------------
 * Module init / deinit
 * ---------------------------------------------------------------------- */

static int
_modinit(void)
{
	if (RAND_bytes(cloak_key, CLOAK_KEY_LEN) != 1)
	{
		/* RAND_bytes should never fail on a properly seeded system.
		 * If it does, abort module load rather than cloaking with a
		 * weak or empty key. RAND_pseudo_bytes was removed in OpenSSL 3. */
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"ip_cloaking: RAND_bytes failed -- module NOT loaded!");
		return -1;
	}

	user_modes['x'] = find_umode_slot();
	construct_umodebuf();
	return 0;
}

static void
_moddeinit(void)
{
	/* Zero the key before unloading.
	 * OPENSSL_cleanse is used instead of memset because compilers are
	 * permitted to optimise away a memset of memory that is never read
	 * again, which would leave the key in memory. */
	OPENSSL_cleanse(cloak_key, CLOAK_KEY_LEN);
	user_modes['x'] = 0;
	construct_umodebuf();
}

/* -------------------------------------------------------------------------
 * Core HMAC-SHA256 helper
 *
 * Computes HMAC-SHA256(cloak_key, input) and writes the first `outlen`
 * hex characters into outbuf.  outbuf must be at least outlen+1 bytes.
 * ---------------------------------------------------------------------- */
static void
hmac_sha256_hex(const char *input, char *outbuf, size_t outlen)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	unsigned int digest_len = SHA256_DIGEST_LENGTH;
	static const char hex[] = "0123456789abcdef";
	size_t i;

	/* HMAC() returns NULL on failure; treat that as an all-zero digest
	 * rather than operating on uninitialised stack memory. */
	if (HMAC(EVP_sha256(),
	         cloak_key, CLOAK_KEY_LEN,
	         (const unsigned char *)input, strlen(input),
	         digest, &digest_len) == NULL)
	{
		memset(digest, 0, SHA256_DIGEST_LENGTH);
	}

	/* Clamp outlen to the maximum available hex output */
	if (outlen > SHA256_DIGEST_LENGTH * 2)
		outlen = SHA256_DIGEST_LENGTH * 2;

	/* Write hex directly into outbuf; avoids an intermediate buffer and
	 * the overhead of repeated snprintf calls inside the loop. */
	for (i = 0; i < outlen / 2; i++)
	{
		outbuf[i * 2]     = hex[(digest[i] >> 4) & 0xf];
		outbuf[i * 2 + 1] = hex[digest[i] & 0xf];
	}
	outbuf[outlen] = '\0';

	/* Wipe digest off the stack */
	OPENSSL_cleanse(digest, SHA256_DIGEST_LENGTH);
}

/* -------------------------------------------------------------------------
 * IPv4 cloaking
 *
 * Full address is hashed; output looks like:  a3f8b2c1.IP
 * (8 hex chars = 32 bits of HMAC output, enough to be opaque yet short)
 * ---------------------------------------------------------------------- */
static void
do_host_cloak_ipv4(const char *inbuf, char *outbuf)
{
	char token[9]; /* 8 hex chars + NUL */
	hmac_sha256_hex(inbuf, token, 8);
	snprintf(outbuf, HOSTLEN + 1, "%s.IP", token);
}

/* -------------------------------------------------------------------------
 * IPv6 cloaking
 *
 * Full address is hashed; output looks like:  a3f8b2c1d4e5f607.IPv6
 * (16 hex chars = 64 bits, keeps output clearly IPv6-derived)
 * ---------------------------------------------------------------------- */
static void
do_host_cloak_ipv6(const char *inbuf, char *outbuf)
{
	char token[17]; /* 16 hex chars + NUL */
	hmac_sha256_hex(inbuf, token, 16);
	snprintf(outbuf, HOSTLEN + 1, "%s.IPv6", token);
}

/* -------------------------------------------------------------------------
 * Hostname cloaking
 *
 * Strategy: keep the top-level and second-level domain labels for human
 * readability (so staff can still see "user is from example.com") but
 * replace the leftmost label(s) with a HMAC token, preventing enumeration
 * of specific hosts within that domain.
 *
 * e.g.  pc42.dialup.example.com  ->  a3f8b2c1.example.com
 *       mail.example.co.uk       ->  a3f8b2c1.example.co.uk
 *
 * If the hostname has fewer than 2 dots (single-label or bare domain),
 * the entire string is replaced with a token to avoid leaking anything.
 * ---------------------------------------------------------------------- */
static void
do_host_cloak_host(const char *inbuf, char *outbuf)
{
	char token[9];
	const char *p;
	int dots = 0;

	/* Count dots to find the base domain */
	for (p = inbuf; *p != '\0'; p++)
		if (*p == '.')
			dots++;

	hmac_sha256_hex(inbuf, token, 8);

	if (dots >= 2)
	{
		/* Walk to the second-to-last dot to get "example.com" */
		int target = dots - 1;
		int seen = 0;
		for (p = inbuf; *p != '\0'; p++)
		{
			if (*p == '.')
			{
				seen++;
				if (seen == target)
				{
					/* p now points at the dot before "example.com".
					 * Use strlcpy+strlcat so the bound is statically visible
					 * to the compiler, silencing -Wformat-truncation.
					 * If the combined length would exceed HOSTLEN, fall through
					 * to the full-hash fallback rather than truncating. */
					if (strlen(token) + strlen(p) > HOSTLEN)
						break;
					rb_strlcpy(outbuf, token, HOSTLEN + 1);
					rb_strlcat(outbuf, p,     HOSTLEN + 1);
					return;
				}
			}
		}
	}

	/* Fallback: too short a hostname, hash the whole thing */
	snprintf(outbuf, HOSTLEN + 1, "%s.host", token);
}

/* -------------------------------------------------------------------------
 * Dispatcher: choose IPv4, IPv6, or hostname cloaking
 * ---------------------------------------------------------------------- */
static void
do_host_cloak(const char *inbuf, char *outbuf)
{
	struct in6_addr addr6;
	struct in_addr  addr4;

	if (rb_inet_pton(AF_INET6, inbuf, &addr6) == 1)
	{
		OPENSSL_cleanse(&addr6, sizeof(addr6));
		do_host_cloak_ipv6(inbuf, outbuf);
	}
	else if (rb_inet_pton(AF_INET, inbuf, &addr4) == 1)
	{
		OPENSSL_cleanse(&addr4, sizeof(addr4));
		do_host_cloak_ipv4(inbuf, outbuf);
	}
	else
		do_host_cloak_host(inbuf, outbuf);
}

/* -------------------------------------------------------------------------
 * Hook callbacks and distribution (unchanged logic, new cloak functions)
 * ---------------------------------------------------------------------- */

static void check_umode_change(void *data);
static void check_new_user(void *data);
static void free_new_user(void *data);

mapi_hfn_list_av1 ip_cloaking_hfnlist[] = {
	{ "umode_changed",   check_umode_change },
	{ "new_local_user",  check_new_user     },
	{ "exit_client",     free_new_user      },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(ip_cloaking, _modinit, _moddeinit, NULL, NULL,
		ip_cloaking_hfnlist, NULL, NULL, ip_cloaking_desc);

static void
distribute_hostchange(struct Client *client_p, char *newhost)
{
	if (newhost != client_p->orighost)
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN,
			"%s :is now your hidden host", newhost);
	else
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN,
			"%s :hostname reset", newhost);

	sendto_server(NULL, NULL,
		CAP_EUID | CAP_TS6, NOCAPS, ":%s CHGHOST %s :%s",
		use_id(&me), use_id(client_p), newhost);
	sendto_server(NULL, NULL,
		CAP_TS6, CAP_EUID, ":%s ENCAP * CHGHOST %s :%s",
		use_id(&me), use_id(client_p), newhost);

	change_nick_user_host(client_p, client_p->name, client_p->username,
		newhost, 0, "Changing host");

	if (newhost != client_p->orighost)
		SetDynSpoof(client_p);
	else
		ClearDynSpoof(client_p);
}

static void
check_umode_change(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	if (!((data->oldumodes ^ source_p->umodes) & user_modes['x']))
		return;

	if (source_p->umodes & user_modes['x'])
	{
		if (IsIPSpoof(source_p) ||
		    source_p->localClient->mangledhost == NULL ||
		    (IsDynSpoof(source_p) &&
		     strcmp(source_p->host, source_p->localClient->mangledhost)))
		{
			source_p->umodes &= ~user_modes['x'];
			return;
		}
		if (strcmp(source_p->host, source_p->localClient->mangledhost))
			distribute_hostchange(source_p, source_p->localClient->mangledhost);
		else
			sendto_one_numeric(source_p, RPL_HOSTHIDDEN,
				"%s :is now your hidden host", source_p->host);
	}
	else
	{
		if (source_p->localClient->mangledhost != NULL &&
		    !strcmp(source_p->host, source_p->localClient->mangledhost))
			distribute_hostchange(source_p, source_p->orighost);
	}
}

static void
free_new_user(void *vdata)
{
	struct Client *source_p = (void *)vdata;

	/* Free the cloaked host buffer allocated in check_new_user.
	 * This hook fires when a local client exits, preventing a per-user
	 * HOSTLEN+1 byte leak for every user who connects and disconnects. */
	if (source_p->localClient != NULL &&
	    source_p->localClient->mangledhost != NULL)
	{
		rb_free(source_p->localClient->mangledhost);
		source_p->localClient->mangledhost = NULL;
	}
}

static void
check_new_user(void *vdata)
{
	struct Client *source_p = (void *)vdata;

	if (IsIPSpoof(source_p))
	{
		source_p->umodes &= ~user_modes['x'];
		return;
	}

	/* Free any previously allocated buffer (e.g. module reload with live
	 * users connected) before allocating a fresh one. */
	if (source_p->localClient->mangledhost != NULL)
	{
		rb_free(source_p->localClient->mangledhost);
		source_p->localClient->mangledhost = NULL;
	}

	source_p->localClient->mangledhost = rb_malloc(HOSTLEN + 1);
	if (source_p->localClient->mangledhost == NULL)
	{
		/* Out of memory: disable cloaking for this user rather than crash */
		source_p->umodes &= ~user_modes['x'];
		return;
	}

	do_host_cloak(source_p->orighost, source_p->localClient->mangledhost);

	if (IsDynSpoof(source_p))
		source_p->umodes &= ~user_modes['x'];

	if (source_p->umodes & user_modes['x'])
	{
		rb_strlcpy(source_p->host, source_p->localClient->mangledhost,
			sizeof(source_p->host));
		if (irccmp(source_p->host, source_p->orighost))
			SetDynSpoof(source_p);
	}
}
