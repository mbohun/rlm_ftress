/*
 * rlm_ftress.c
 *
 * Version:	$Id: rlm_ftress.c,v 0.0 2007/10/10 14:43:00 mhoermann Exp $
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2007  Martin Hoermann <mhoermann@actividentity.com>
 */

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

#include "ftress.h"

static const char rcsid[] = "$Id: rlm_ftress.c,v 0.0 2007/10/10 14:43:00 mhoermann Exp $";

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_ftress_t {
	char* default_channel;
	char* security_domain;
	char* authentication_type;

	int proxy_mode;
	int use_device_sn;

	char* username;
	char* password;

} rlm_ftress_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static CONF_PARSER module_config[] = {
	{ "default_channel",PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, string), NULL,  NULL},
	{ "security_domain",  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, string), NULL,  NULL},
	{ "authentication_type",  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, string), NULL,  NULL},

	{ "proxy_mode", PW_TYPE_BOOLEAN,    offsetof(rlm_ftress_t,boolean), NULL, "no"},
	{ "use_device_sn", PW_TYPE_BOOLEAN,    offsetof(rlm_ftress_t,boolean), NULL, "no"},

	{ "username",  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, string), NULL,  NULL},
	{ "password",  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, string), NULL,  NULL},

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 *	Do any per-module initialization.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	Try to avoid putting too much stuff in here - it's better to
 *	do it in instantiate() where it is not global.
 */
static int ftress_init(void)
{
	/*
	 *	Everything's OK, return without an error.
	 */
	return 0;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int ftress_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_ftress_t *data;

	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));
	if (!data) {
		return -1;
	}
	memset(data, 0, sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}

	*instance = data;

	return 0;
}

static int example_authenticate(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;




	return RLM_MODULE_OK;
}

static int ftress_detach(void *instance)
{
	free(((struct rlm_ftress_t *)instance)->string);
	free(instance);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_ftress = {
	"ftress",
	RLM_TYPE_THREAD_SAFE,		/* type */
	ftress_init,			/* initialization */
	ftress_instantiate,		/* instantiation */
	{
		ftress_authenticate,	/* authentication */
		NULL,	/* authorization */
		NULL,	/* preaccounting */
		NULL,	/* accounting */
		NULL,	/* checksimul */
		NULL,	/* pre-proxy */
		NULL,	/* post-proxy */
		NULL	/* post-auth */
	},
	ftress_detach,	/* detach */
	NULL,		/* destroy */
};
