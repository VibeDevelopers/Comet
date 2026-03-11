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

static const char icloud_desc[] = "IRCCloud ident-based cloak support (SID/UID wildcard, / separator)";

static void new_local_user(void *data);

mapi_hfn_list_av1 icloud_hfnlist[] = {
    { "new_local_user", new_local_user, HOOK_LOWEST },
    { NULL, NULL }
};

DECLARE_MODULE_AV2(irccloud_cloak, NULL, NULL, NULL, NULL, icloud_hfnlist, NULL, NULL, icloud_desc);

/* 
 * new_local_user - called when a local client connects
 * Assigns ident-based cloak using / separator
 * Works for SID/UID wildcard auth blocks
 */
static void
new_local_user(void *data)
{
    struct Client *source_p = data;
    struct ConfItem *aconf = source_p->localClient->att_conf;

    /* Only apply to IRCCloud auth blocks */
    if (!aconf || irccmp(aconf->info.name, "irccloud.") != 0)
        return;

    /* Enforce TLS if required */
    if (!IsSecure(source_p) && (aconf->flags & CONF_FLAGS_NEED_SSL))
    {
        exit_client(source_p, source_p, &me, "IRCCloud connections require TLS");
        return;
    }

    /* Determine cloak domain from auth block info (fallback to default) */
    const char *cloak_domain = !EmptyString(aconf->info.name) ? aconf->info.name : "irccloud/example.com";

    /* Build ident-based cloak using / separator */
    const char *ident = source_p->username;
    char cloak[HOSTLEN+1];

    if (!EmptyString(ident))
    {
        rb_strlcpy(cloak, ident, sizeof(cloak));
        rb_strlcat(cloak, "/", sizeof(cloak));
        rb_strlcat(cloak, cloak_domain, sizeof(cloak));
    }
    else
    {
        rb_strlcpy(cloak, source_p->sockhost, sizeof(cloak));
    }

    rb_strlcpy(source_p->host, cloak, sizeof(source_p->host));

    /* Check D-lines */
    if ((aconf = find_dline((struct sockaddr *)&source_p->localClient->ip,
                            GET_SS_FAMILY(&source_p->localClient->ip))))
    {
        if (!(aconf->status & CONF_EXEMPTDLINE))
        {
            exit_client(source_p, source_p, &me, "D-lined");
            return;
        }
    }

    sendto_one(source_p, "NOTICE * :IRCCloud cloak set to %s", source_p->host);
}
