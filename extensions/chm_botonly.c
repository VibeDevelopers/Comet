/*
 * Comet: a slightly advanced ircd
 * chm_botonly: only allow users with umode +B to join (+X mode).
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "numeric.h"
#include "chmode.h"

static const char chm_botonly_desc[] =
	"Adds channel mode +X which only allows users with umode +B to join";

static void h_can_join(void *);

mapi_hfn_list_av1 botonly_hfnlist[] = {
	{ "can_join", h_can_join },
	{ NULL, NULL }
};

static unsigned int mymode;

static int
_modinit(void)
{
	mymode = cflag_add('X', chm_simple);
	if (mymode == 0)
		return -1;

	return 0;
}

static void
_moddeinit(void)
{
	cflag_orphan('X');
}

DECLARE_MODULE_AV2(chm_botonly, _modinit, _moddeinit, NULL, NULL, botonly_hfnlist, NULL, NULL, chm_botonly_desc);

static void
h_can_join(void *data_)
{
	hook_data_channel *data = data_;
	struct Client *source_p = data->client;
	struct Channel *chptr = data->chptr;

	if(data->approved != 0)
		return;

	if((chptr->mode.mode & mymode) && !IsBot(source_p))
	{
		sendto_one_numeric(source_p, 520, "%s :Cannot join channel (+X) - only bots are permitted", chptr->chname);
		data->approved = ERR_CUSTOM;
	}
}
