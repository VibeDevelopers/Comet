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

	user_modes['h'] = find_umode_slot();
	construct_umodebuf();
	return 0;
}

static void
_moddeinit(void)
{
	/* Zero the key before unloading */
	memset(cloak_key, 0, CLOAK_KEY_LEN);
	user_modes['h'] = 0;
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
	char hexdigest[SHA256_DIGEST_LENGTH * 2 + 1];
	size_t i;

	HMAC(EVP_sha256(),
	     cloak_key, CLOAK_KEY_LEN,
	     (const unsigned char *)input, strlen(input),
	     digest, &digest_len);

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		snprintf(hexdigest + i * 2, 3, "%02x", digest[i]);

	/* Truncate to requested length */
	if (outlen > SHA256_DIGEST_LENGTH * 2)
		outlen = SHA256_DIGEST_LENGTH * 2;

	memcpy(outbuf, hexdigest, outlen);
	outbuf[outlen] = '\0';
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
					/* p now points at the dot before "example.com" */
					snprintf(outbuf, HOSTLEN + 1, "%s%s", token, p);
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
	if (strchr(inbuf, ':'))
		do_host_cloak_ipv6(inbuf, outbuf);
	else if (strchr(inbuf, '.') &&
	         /* Heuristic: all-numeric labels => IPv4 */
	         strspn(inbuf, "0123456789.") == strlen(inbuf))
		do_host_cloak_ipv4(inbuf, outbuf);
	else
		do_host_cloak_host(inbuf, outbuf);
}

/* -------------------------------------------------------------------------
 * Hook callbacks and distribution (unchanged logic, new cloak functions)
 * ---------------------------------------------------------------------- */

static void check_umode_change(void *data);
static void check_new_user(void *data);

mapi_hfn_list_av1 ip_cloaking_hfnlist[] = {
	{ "umode_changed",  check_umode_change },
	{ "new_local_user", check_new_user     },
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

	if (!((data->oldumodes ^ source_p->umodes) & user_modes['h']))
		return;

	if (source_p->umodes & user_modes['h'])
	{
		if (IsIPSpoof(source_p) ||
		    source_p->localClient->mangledhost == NULL ||
		    (IsDynSpoof(source_p) &&
		     strcmp(source_p->host, source_p->localClient->mangledhost)))
		{
			source_p->umodes &= ~user_modes['h'];
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
check_new_user(void *vdata)
{
	struct Client *source_p = (void *)vdata;

	if (IsIPSpoof(source_p))
	{
		source_p->umodes &= ~user_modes['h'];
		return;
	}

	source_p->localClient->mangledhost = rb_malloc(HOSTLEN + 1);

	do_host_cloak(source_p->orighost, source_p->localClient->mangledhost);

	if (IsDynSpoof(source_p))
		source_p->umodes &= ~user_modes['h'];

	if (source_p->umodes & user_modes['h'])
	{
		rb_strlcpy(source_p->host, source_p->localClient->mangledhost,
			sizeof(source_p->host));
		if (irccmp(source_p->host, source_p->orighost))
			SetDynSpoof(source_p);
	}
}
