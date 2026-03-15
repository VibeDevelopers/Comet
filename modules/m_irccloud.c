/*
 *  ircd-ratbox: IRCCloud ident-based cloak support
 *  - Password-free
 *  - Supports SID/UID wildcard auth blocks
 *  - Uses / separator in cloaks
 *  - Configurable cloak domain per auth block
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu
 *  Copyright (C) 1996-2006 Hybrid/ratbox development team
 *  Adapted for IRCCloud by SnowFields 2025
 *
 *  License: GPL v2 or later
 */

#include "stdinc.h"
#include "client.h"
#include "match.h"
#include "hostmask.h"
#include "send.h"
#include "numeric.h"
#include "ircd.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "s_serv.h"
#include "hash.h"
#include "s_conf.h"
#include "reject.h"
#include "hook.h"
#include <ctype.h>

static const char icloud_desc[] = "IRCCloud ident-based cloak support (SID/UID wildcard, / separator)";

static void apply_cloak(void *data);
static void send_notice(void *data);

mapi_hfn_list_av1 icloud_hfnlist[] = {
    { "new_local_user",   apply_cloak,  HOOK_LOWEST },
    { "introduce_client", send_notice,  HOOK_LOWEST },
    { NULL, NULL }
};

DECLARE_MODULE_AV2(irccloud_cloak, NULL, NULL, NULL, NULL, icloud_hfnlist, NULL, NULL, icloud_desc);

/*
 * is_valid_ident_char - returns 1 if c is safe to embed in a hostname cloak.
 * Permits alphanumerics, hyphen, and underscore only.
 */
static int
is_valid_ident_char(char c)
{
    return (isalnum((unsigned char)c) || c == '-' || c == '_');
}

/*
 * sanitise_ident - copies src into dst, replacing any character that is not
 * safe for embedding in a hostname with '_'.  dst is always NUL-terminated.
 * Returns 0 if the result is empty (i.e. nothing usable in the ident).
 */
static int
sanitise_ident(char *dst, size_t dstlen, const char *src)
{
    size_t i = 0;

    if (EmptyString(src) || dstlen == 0)
        return 0;

    for (; *src && i < dstlen - 1; src++, i++)
        dst[i] = is_valid_ident_char(*src) ? *src : '_';

    dst[i] = '\0';
    return (i > 0);
}

/*
 * is_irccloud_auth - returns 1 if the auth block name looks like an IRCCloud
 * domain.  This prevents the module from touching clients matched to
 * unrelated auth blocks whose name happens to be set to something else
 * (e.g. "NOMATCH" in the test harness).
 */
static int
is_irccloud_auth(const char *name)
{
    return (strstr(name, "irccloud") != NULL);
}

/*
 * apply_cloak - fired by h_new_local_user.
 *
 * Runs D-line and TLS checks, then mutates source_p->host with the
 * ident-based cloak.  No NOTICE is sent here — 001 has not been sent yet
 * and the UID burst to remote servers has not happened yet either, so the
 * mutated host will be picked up cleanly by both.
 *
 * The user-visible NOTICE is deferred to send_notice() which fires on
 * h_introduce_client, after the full registration burst is complete.
 */
static void
apply_cloak(void *data)
{
    struct Client   *source_p = data;
    struct ConfItem *aconf    = source_p->localClient->att_conf;
    struct ConfItem *dconf;
    const char      *cloak_domain;
    char             safe_ident[USERLEN + 1];
    char             cloak[HOSTLEN + 1];
    size_t           needed;

    /* Auth block must exist and have a name (used as cloak domain). */
    if (!aconf || EmptyString(aconf->info.name))
        return;

    /* Only process IRCCloud auth blocks. */
    if (!is_irccloud_auth(aconf->info.name))
        return;

    /* D-line check before touching the client's host or sending anything. */
    dconf = find_dline((struct sockaddr *)&source_p->localClient->ip,
                       GET_SS_FAMILY(&source_p->localClient->ip));
    if (dconf)
    {
        if (!(dconf->status & CONF_EXEMPTDLINE))
        {
            exit_client(source_p, source_p, &me, "D-lined");
            return;
        }
    }

    /* Reject non-TLS connections on auth blocks that require it. */
    if (!IsSecure(source_p) && (aconf->flags & CONF_FLAGS_NEED_SSL))
    {
        exit_client(source_p, source_p, &me, "IRCCloud connections require TLS");
        return;
    }

    /* The auth block's spoof name is used as the cloak domain. */
    cloak_domain = aconf->info.name;

    /* Strip a leading "sid" prefix so the cloak reads as
     * 560670/gateway/irccloud rather than sid560670/gateway/irccloud.
     * uid prefixes are left intact intentionally. */
    const char *ident = source_p->username;
    if (strncasecmp(ident, "sid", 3) == 0)
        ident += 3;

    if (sanitise_ident(safe_ident, sizeof(safe_ident), ident))
    {
        /* Verify the assembled cloak fits before committing.
         * needed = len(safe_ident) + 1 ('/') + len(cloak_domain) + NUL */
        needed = strlen(safe_ident) + 1 + strlen(cloak_domain) + 1;
        if (needed > sizeof(cloak))
        {
            rb_strlcpy(cloak, source_p->sockhost, sizeof(cloak));
            sendto_wallops_flags(UMODE_OPERWALL, &me,
                "IRCCloud cloak overflow for %s!%s -- falling back to sockhost",
                source_p->name, source_p->username);
        }
        else
        {
            rb_strlcpy(cloak, safe_ident,   sizeof(cloak));
            rb_strlcat(cloak, "/",          sizeof(cloak));
            rb_strlcat(cloak, cloak_domain, sizeof(cloak));
        }
    }
    else
    {
        /* No usable ident — fall back to the raw socket address. */
        rb_strlcpy(cloak, source_p->sockhost, sizeof(cloak));
    }

    rb_strlcpy(source_p->host, cloak, sizeof(source_p->host));

    /* NOTICE is deliberately omitted here.
     * It is sent by send_notice() once registration is complete. */
}

/*
 * send_notice - fired by h_introduce_client.
 *
 * h_introduce_client is called at the very end of register_local_user(),
 * after the 001-376 welcome burst has been sent to the client and after
 * the UID has been propagated to remote servers.  It is therefore the
 * correct place to send user-visible output that must follow 001.
 *
 * hdata->client is the server-side client_p (uplink/self).
 * hdata->target is source_p, the user who just registered.
 */
static void
send_notice(void *data)
{
    hook_data_client *hdata    = data;
    struct Client    *source_p = hdata->target;

    /* Only act on local clients. Guard against non-local or
     * already-exited clients defensively. */
    if (!MyClient(source_p) || !source_p->localClient)
        return;

    /* Only notify for IRCCloud auth blocks. */
    struct ConfItem *aconf = source_p->localClient->att_conf;
    if (!aconf || EmptyString(aconf->info.name))
        return;

    if (!is_irccloud_auth(aconf->info.name))
        return;

    sendto_one(source_p, "NOTICE * :IRCCloud cloak set to %s", source_p->host);
}
