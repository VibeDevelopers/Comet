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
#include <ctype.h>

static const char icloud_desc[] = "IRCCloud ident-based cloak support (SID/UID wildcard, . separator)";

static void new_local_user(void *data);

mapi_hfn_list_av1 icloud_hfnlist[] = {
    { "new_local_user", new_local_user, HOOK_LOWEST },
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
 * new_local_user - called when a local client connects.
 * Assigns an ident-based cloak using the / separator.
 * Works for SID/UID wildcard auth blocks whose name begins with "irccloud.".
 */
static void
new_local_user(void *data)
{
    struct Client   *source_p = data;
    struct ConfItem *aconf    = source_p->localClient->att_conf;
    struct ConfItem *dconf;          /* FIX #2: separate pointer for D-line lookup */
    const char      *cloak_domain;
    char             safe_ident[USERLEN + 1];
    char             cloak[HOSTLEN + 1];
    size_t           needed;

    /* Auth block is already locked to uid*@*.irccloud.com so any connection
     * reaching here is an IRCCloud user. No need to re-check the spoof name. */
    if (!aconf || EmptyString(aconf->info.name))
        return;

    /* FIX #5 (part 1): D-line check BEFORE we touch the client's host or
     * send any notice, so a banned user is rejected cleanly.               */
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

    /* FIX #3 / #8: TLS rejection — exit and return immediately; no fall-through
     * to the NOTICE at the bottom.                                          */
    if (!IsSecure(source_p) && (aconf->flags & CONF_FLAGS_NEED_SSL))
    {
        exit_client(source_p, source_p, &me, "IRCCloud connections require TLS");
        return;
    }

    /* Read the cloak domain from the spoof field (fakename).              */
    cloak_domain = aconf->info.name;

    /* Strip leading "uid" prefix so cloak is 560670.free.irccloud.com
     * rather than uid560670.free.irccloud.com                               */
    const char *ident = source_p->username;
    if (strncasecmp(ident, "uid", 3) == 0)
        ident += 3;

    /* Sanitise the ident before embedding it in a hostname.                */
    if (sanitise_ident(safe_ident, sizeof(safe_ident), ident))
    {
        /* Check that the assembled cloak will fit before committing.
         * needed = len(safe_ident) + 1 (for '.') + len(cloak_domain) + NUL  */
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
        /* No usable ident — fall back to the raw socket address.           */
        rb_strlcpy(cloak, source_p->sockhost, sizeof(cloak));
    }

    rb_strlcpy(source_p->host, cloak, sizeof(source_p->host));

    /* FIX #8: NOTICE is only reached when the client has passed every check
     * above and has not been exit_client()'d.                               */
    sendto_one(source_p, "NOTICE * :IRCCloud cloak set to %s", source_p->host);
}
