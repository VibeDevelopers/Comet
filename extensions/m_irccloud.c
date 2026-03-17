/*
 * ircd-ratbox: IRCCloud ident-based cloak support
 *
 * Fully supports auth name, disable_auth yes/no, no_tilde yes/no.
 * Uses / separator in cloaks.
 *
 * Adapted for IRCCloud by SnowFields 2025
 * License: GPL v2 or later
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

static const char icloud_desc[] =
"IRCCloud cloak support (introduce_client hook, auth + UID/SID fallback)";

static void apply_cloak(void *data);
static void send_notice(void *data);

mapi_hfn_list_av1 icloud_hfnlist[] = {
    { "introduce_client", apply_cloak, HOOK_LOWEST },
    { "introduce_client", send_notice, HOOK_LOWEST },
    { NULL, NULL }
};

DECLARE_MODULE_AV2(
    irccloud_cloak,
    NULL,
    NULL,
    NULL,
    NULL,
    icloud_hfnlist,
    NULL,
    NULL,
    icloud_desc
);

/* Strip leading ~ if present */
static const char *get_ident(struct Client *source_p)
{
    const char *ident = source_p->username;
    if (!ident || !*ident)
        return ident;
    if (*ident == '~')
        ident++;
    return ident;
}

/* Only allow alphanumeric, - and _ */
static int is_valid_ident_char(char c)
{
    return (isalnum((unsigned char)c) || c == '-' || c == '_');
}

/* Sanitize ident for hostname */
static int sanitise_ident(char *dst, size_t dstlen, const char *src)
{
    size_t i = 0;
    if (!src || dstlen == 0)
        return 0;

    for (; *src && i < dstlen - 1; src++, i++)
        dst[i] = is_valid_ident_char(*src) ? *src : '_';

    dst[i] = '\0';
    return (i > 0);
}

/* Apply cloak when client is fully introduced */
static void apply_cloak(void *data)
{
    hook_data_client *hdata = data;
    struct Client *source_p;
    char safe_ident[USERLEN+1];
    char cloak[HOSTLEN+1];
    const char *ident;
    const char *cloak_domain;

    if (!hdata || !(source_p = hdata->target))
        return;

    if (!MyClient(source_p) || !source_p->localClient)
        return;

    ident = get_ident(source_p);
    if (!ident || !*ident)
        return;

    /* Only cloak UID/SID clients */
    if (strncasecmp(ident,"uid",3) != 0 && strncasecmp(ident,"sid",3) != 0)
        return;

    /* Strip SID prefix */
    if (strncasecmp(ident,"sid",3) == 0)
        ident += 3;

    /* Determine cloak domain */
    if (source_p->localClient->att_conf &&
        !EmptyString(source_p->localClient->att_conf->info.name) &&
        strcasecmp(source_p->localClient->att_conf->info.name,"NOMATCH") != 0)
    {
        /* Use auth block name as cloak domain */
        cloak_domain = source_p->localClient->att_conf->info.name;
    }
    else
    {
        /* fallback when auth missing or disable_auth = yes */
        cloak_domain = "gateway/irccloud";
    }

    /* Sanitize ident */
    if (!sanitise_ident(safe_ident,sizeof(safe_ident),ident))
    {
        rb_strlcpy(cloak, source_p->sockhost, sizeof(cloak));
    }
    else
    {
        size_t needed = strlen(safe_ident) + 1 + strlen(cloak_domain) + 1;
        if (needed >= sizeof(cloak))
        {
            rb_strlcpy(cloak, source_p->sockhost, sizeof(cloak));
            sendto_wallops_flags(UMODE_OPERWALL, &me,
                "IRCCloud cloak overflow for %s!%s",
                source_p->name, source_p->username);
        }
        else
        {
            rb_strlcpy(cloak, safe_ident, sizeof(cloak));
            rb_strlcat(cloak, "/", sizeof(cloak));
            rb_strlcat(cloak, cloak_domain, sizeof(cloak));
        }
    }

    /* Apply cloak */
    rb_strlcpy(source_p->host, cloak, sizeof(source_p->host));
}

/* Send user-visible NOTICE after cloak applied */
static void send_notice(void *data)
{
    hook_data_client *hdata = data;
    struct Client *source_p;

    if (!hdata || !(source_p = hdata->target))
        return;

    if (!MyClient(source_p) || !source_p->localClient)
        return;

    const char *ident = get_ident(source_p);
    if (!ident || !*ident)
        return;

    /* Only notify for UID/SID clients */
    if (strncasecmp(ident,"uid",3) != 0 && strncasecmp(ident,"sid",3) != 0)
        return;

    sendto_one(source_p,
               "NOTICE * :IRCCloud cloak set to %s",
               source_p->host);
}
