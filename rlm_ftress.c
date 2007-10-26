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
	char* admin_authentication_type_code;

	char* server_authentication_type_code;
	char* server_channel;
	char* server_username;
	char* server_password;

	char* user_channel;
	char* user_authentication_type_code;

	char* security_domain;

	int use_device_sn;

	char* endpoint_authenticator;
	char* endpoint_authenticator_manager;
	char* endpoint_device_manager;
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
	{ "admin_authentication_type_code",  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, admin_authentication_type_code),  NULL,  NULL},

	{ "server_authentication_type_code", PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, server_authentication_type_code), NULL,  NULL},
	{ "server_channel",                  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, server_channel),                  NULL,  NULL},
	{ "server_username",                 PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, server_username),                 NULL,  NULL},
	{ "server_password",                 PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, server_password),                 NULL,  NULL},

	{ "user_channel",                    PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, user_channel),                    NULL,  NULL},
	{ "user_authentication_type_code",   PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, user_authentication_type_code),   NULL,  NULL},

	{ "security_domain",                 PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, security_domain),                 NULL,  NULL},

	{ "use_device_sn",                   PW_TYPE_BOOLEAN,    offsetof(rlm_ftress_t, use_device_sn),                   NULL, "no"},

	{ "endpoint_authenticator",          PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, endpoint_authenticator),          NULL,  NULL},
	{ "endpoint_authenticator_manager",  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, endpoint_authenticator_manager),  NULL,  NULL},
	{ "endpoint_device_manager",         PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, endpoint_device_manager),         NULL,  NULL},
	
	{ NULL, -1, 0, NULL, NULL}
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

static Alsi* module_alsi;

static ChannelCode server_channel_code;
static SecurityDomain security_domain;

static AuthenticationTypeCode admin_authentication_type_code;

static ChannelCode user_channel_code;
static AuthenticationTypeCode user_authentication_type_code; /* TODO: fix NULL pointer */

/* authenticates this module to 4TRESS server in order to do:
 * - ftress_indirect_primary_authenticate_device()
 * - ftress_reset_authenticator_failed_authentication_count()
 */
static Alsi* authenticate_module_to_ftress(void* instance) {

	const struct rlm_ftress_t* config = ((struct rlm_ftress_t*)instance);

	/** Create ChannelCode*/
	server_channel_code = ftress_create_channel_code(config->server_channel , 0);
	
	/** Create SecurityDomain */
	security_domain  = ftress_create_security_domain(config->security_domain);		
	ftress_set_security_domain(security_domain, config->security_domain); /* check this */

	/** Create AuthenticationTypeCode */
	AuthenticationTypeCode server_authentication_type_code = 
		ftress_create_authentication_type_code(config->server_authentication_type_code);

	/** Create UPAuthenticationRequest */
	UPAuthenticationRequest req = 
		ftress_create_up_authentication_request(NULL, 
							0, 
							server_authentication_type_code, 
							NULL ,
							config->server_password, 
							NULL, 
							NULL, 
							config->server_username);

	/** Create PrimaryAuthenticateUPResponse */
	PrimaryAuthenticateUPResponse resp = ftress_create_primary_authenticate_up_response();

	Alsi* alsi = NULL;

	if (FTRESS_SUCCESS == ftress_primary_authenticate_up(config->endpoint_authenticator, 
							     server_channel_code, 
							     req, 
							     security_domain, 
							     resp)) {
		/** Extract AuthenticationResponse from primaryAuthenticateUPResponse */
		AuthenticationResponse auth_res = 
			ftress_get_primary_authenticate_up_authentication_response(resp);
		
		/** Extract alsi from AuthenticationResponse */
		alsi = ftress_get_authentication_response_alsi(auth_res);
		
		/** TODO: free auth_res ? **/
	}
	
	ftress_free_primary_authenticate_up_response(resp);
	ftress_free_up_authentication_request(req);
	ftress_free_authentication_type_code(server_authentication_type_code);
	return alsi;
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

	/** Initialise ftress */
	ftress_init();

	*instance = data;

	module_alsi = authenticate_module_to_ftress(data);
	if (NULL != module_alsi) {
		const char* alsi_str = ftress_get_alsi(module_alsi);
		if (NULL != alsi_str) {
			radlog(L_AUTH, "rlm_ftress: module successfully authenticated to 4TRESS server.");
			/* success */
		}
	} else {
		radlog(L_AUTH, "rlm_ftress: module failed to authenticate to 4TRESS server.");
		return -1;
	}

	admin_authentication_type_code = 
		ftress_create_authentication_type_code(data->admin_authentication_type_code);

	user_channel_code = ftress_create_channel_code(data->user_channel , 0);
	
	user_authentication_type_code = 
		ftress_create_authentication_type_code(data->user_authentication_type_code);

	return 0; /* success */
}

static int ftress_authenticate(void *instance, REQUEST *request) {

	const struct rlm_ftress_t* config = instance;

	if (!request->username) {
		radlog(L_AUTH,
		       "rlm_ftress: Attribute \"User-Name\" is required for authentication.");

		return RLM_MODULE_INVALID;
	}

	if (!request->password) {
		radlog(L_AUTH,
		       "rlm_ftress: Attribute \"User-Password\" is required for authentication.");

		return RLM_MODULE_INVALID;
	}

	if (request->password->attribute != PW_PASSWORD) {
		radlog(L_AUTH,
		       "rlm_ftress: Attribute \"User-Password\" contains invalid characters."
		       "Cannot use \"%s\".", request->password->name);

		return RLM_MODULE_INVALID;
	}

	/* do we have to check password length? */
	const char* username = (char*)request->username->strvalue;
	const char* password = (char*)request->password->strvalue;

	AuthenticationTypeCode atc = NULL;

	DeviceSearchCriteria device_search_criteria = NULL;
	UserCode user_code = NULL;
		
	if (config->use_device_sn) {
		atc = admin_authentication_type_code;
		device_search_criteria = 
			ftress_device_search_criteria_create(1, /* TODO: search limit, request proper constant */
							     0, /* TODO: assigned to user, request proper constant */
							     NULL,
							     NULL, /* device id */
							     NULL, /* device type code */
							     NULL,
							     NULL,
							     0, /* issue number */
							     username, /* serial number */
							     NULL,
							     NULL);
	} else {
		atc = user_authentication_type_code;
		user_code = ftress_create_user_code(username);
	}

	DeviceAuthenticationRequest req =
		ftress_device_authentication_request_create(NULL,
							    0, /* TODO: authenticate no session - request proper constant */
							    atc,
							    NULL,
							    1, /* TODO: SYNCHRONOUS - request proper constant in ftress.h */
							    NULL,
							    device_search_criteria,
							    password,
							    user_code);
	
	IndirectPrimaryAuthenticateDeviceResponse resp =
		ftress_indirect_primary_authenticate_device_response_create();

	int authentication_result = RLM_MODULE_REJECT; /* default */

	int crap = ftress_indirect_primary_authenticate_device(config->endpoint_authenticator,
							       module_alsi,
							       user_channel_code,
							       req,
							       security_domain,
							       resp);
	if (FTRESS_SUCCESS == crap) {

		AuthenticationResponse auth_resp =
			ftress_primary_authenticate_device_get_authentication_response(resp);

		authentication_result =
			(NULL != ftress_get_authentication_response_alsi(auth_resp)) ? RLM_MODULE_OK : RLM_MODULE_REJECT;

		/* TODO: ? check on who is freeing AuthenticationResponse */
	} else {
		radlog(L_AUTH, "rlm_ftress: 4TRESS ERROR: %s", ftress_exception_handler(crap));	
	}

	ftress_indirect_primary_authenticate_device_response_free(resp);
	// TODO: BUG: mem management in ftress.a needs fixing
	// ftress_indirect_primary_authenticate_device_response_free(resp) is
	// freeing device_search_criteria as well - that 's wrong.
	// ftress_device_authentication_request_free(req);

	if (config->use_device_sn) {
		ftress_device_search_criteria_free(device_search_criteria);
	} else {
		ftress_free_user_code(user_code);
	}

	return authentication_result;
}

/* TODO:
 * if in proxy mode and the authentication to a 3rd party RADIUS
 * server was success decrease the authentication failure count
 * on the 4TRESS server.
 */
static int ftress_adjust_failure_count(void *instance, REQUEST *request) {

	const struct rlm_ftress_t* config = instance;

	radlog(L_AUTH, "rlm_ftress:ftress_adjust_failure_count(), proxy responded: %d",
	       request->proxy_reply->code);

	// user_code = ftress_create_user_code(username);

	if (PW_AUTHENTICATION_ACK == request->proxy_reply->code) {
		radlog(L_AUTH, "rlm_ftress:ftress_adjust_failure_count() ..."
		       "decreasing 4TRESS failed authentication count");

		if (config->use_device_sn) {
			/* TODO: not implemented yet DeviceManager.searchDevices() */
		} else {
	
		}
		/* TODO: not implemented yet
		ftress_reset_device_authenticator_failed_authentication_count(config->endpoint_authenticator_manager,
									      module_alsi,
									      server_channel_code,
									      admin_authentication_type_code,
									      security_domain,
									      user_code,
									      resp);
		*/
	} else { // PW_AUTHENTICATION_REJECT
		; //nothing to do!
	}
	
	return  RLM_MODULE_OK;
}

static int ftress_detach(void *instance)
{
	/** Free ChannelCode */	
	//ftress_free_channel_code(channelCode);

	/** Free securityDomain */
	ftress_free_security_domain(security_domain);

	/** Free authenticationTypeCode */
	ftress_free_authentication_type_code(admin_authentication_type_code);

	ftress_quit(); /* ftress client cleanup */

	/* free strings */
	free(((struct rlm_ftress_t *)instance)->admin_authentication_type_code);

	free(((struct rlm_ftress_t *)instance)->server_authentication_type_code);
	free(((struct rlm_ftress_t *)instance)->server_channel);
	free(((struct rlm_ftress_t *)instance)->server_username);
	free(((struct rlm_ftress_t *)instance)->server_password);

	free(((struct rlm_ftress_t *)instance)->user_channel);
	free(((struct rlm_ftress_t *)instance)->user_authentication_type_code);

	free(((struct rlm_ftress_t *)instance)->security_domain);

	free(((struct rlm_ftress_t *)instance)->endpoint_authenticator);
	free(((struct rlm_ftress_t *)instance)->endpoint_authenticator_manager);
	free(((struct rlm_ftress_t *)instance)->endpoint_device_manager);

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
		ftress_adjust_failure_count,	/* post-proxy */
		NULL  /* post-auth */
	},
	ftress_detach,	/* detach */
	NULL,		/* destroy */
};

/* test */

