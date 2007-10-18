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
	{ "default_channel",     PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, default_channel),     NULL,  NULL},
	{ "security_domain",     PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, security_domain),     NULL,  NULL},
	{ "authentication_type", PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, authentication_type), NULL,  NULL},
	{ "proxy_mode",          PW_TYPE_BOOLEAN,    offsetof(rlm_ftress_t, proxy_mode),          NULL, "no"},
	{ "use_device_sn",       PW_TYPE_BOOLEAN,    offsetof(rlm_ftress_t, use_device_sn),       NULL, "no"},
	{ "username",            PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, username),            NULL,  NULL},
	{ "password",            PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, password),            NULL,  NULL},
	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	Do any per-module initialization.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	Try to avoid putting too much stuff in here - it's better to
 *	do it in instantiate() where it is not global.
 */
static int ftress_initiate(void) /* to avoid conflict with ftress API */
{
	/*
	 *	Everything's OK, return without an error.
	 */
	return 0;
}

/* TODO: We can hide these later in a function that is re-initiating this module's
 *       session.
 */
static ChannelCode channel_code;
static SecurityDomain security_domain;
static AuthenticationTypeCode authentication_type_code;

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

	ftress_init(); /* initialize the ftress client library */

	return 0;
}

static int authenticate_to_ftress() {

}

static int ftress_authenticate(void *instance, REQUEST *request)
{
	/* extract username and password */
	char* username;
	char* password;

	if (!request->username) {
		radlog(L_AUTH, 
		       "rlm_ftress: Attribute \"User-Name\" is required for authentication.");

		return RLM_MODULE_INVALID;
	}

	if (request->username->length > FTRESS_USERNAME_MAX_LENGTH) {
		radlog(L_AUTH, 
		       "rlm_ftress: username [%s] exceeds max length [%d]", 
		       username,
		       FTRESS_USERNAME_MAX_LENGTH);

		return RLM_MODULE_REJECT;
	}

	if (!request->password) {
		radlog(L_AUTH, 
		       "rlm_ftress: Attribute \"User-Password\" is required for authentication.");

		return RLM_MODULE_INVALID;
	}

	/* check if it is plain text */
	if (request->password->attribute != PW_PASSWORD) {
		radlog(L_AUTH, 
		       "rlm_ftress: Attribute \"User-Password\" is required for authentication. "
		       "Cannot use \"%s\".", request->password->name);

		return RLM_MODULE_INVALID;
	}

	/* do we have to check password length? */
	username = (char*)request->username->strvalue;
	password = (char*)request->password->strvalue;

	DeviceAuthenticationRequest req =
		ftress_create_dev_auth_req(username, password);

	PrimaryDeviceAuthenticationResponse resp =
		ftress_create_prim_dev_auth_resp();

	const int result = 
		ftress_primary_auth_dev(req, resp);

	if (FTRESS_SUCCESS == result) {
		ftress_free_dev_auth_req(req);
		ftress_free_prim_dev_auth_resp(resp);
		return RLM_MODULE_OK;
	} else {

		ftress_free_dev_auth_req(req);
		ftress_free_prim_dev_auth_resp(resp);
		return RLM_MODULE_REJECT;
	}

}

static int ftress_detach(void *instance)
{
	ftress_quit(); /* ftress client cleanup */

	/* free strings */
	free(((struct rlm_ftress_t *)instance)->default_channel);
	free(((struct rlm_ftress_t *)instance)->security_domain);
	free(((struct rlm_ftress_t *)instance)->authentication_type);
	free(((struct rlm_ftress_t *)instance)->username);
	free(((struct rlm_ftress_t *)instance)->password);

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
	ftress_initiate,		/* initialization */
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

/* test */

