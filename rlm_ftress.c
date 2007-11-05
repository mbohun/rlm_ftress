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

typedef struct rlm_ftress_t {
/* these are the variables we read from the configuration file, they are prefixed with conf_ */
	char* conf_admin_authentication_type_code;

	char* conf_server_authentication_type_code;
	char* conf_server_channel;
	char* conf_server_username;
	char* conf_server_password;

	char* conf_user_channel;
	char* conf_user_authentication_type_code;

	char* conf_security_domain;

	char* conf_endpoint_authenticator;
	char* conf_endpoint_authenticator_manager;
	char* conf_endpoint_device_manager;

	int conf_radius_username_mapping;

/* 'global' variables, we constructed programatically */
	Alsi* module_alsi;
	ChannelCode server_channel_code;
	SecurityDomain security_domain;
	AuthenticationTypeCode admin_authentication_type_code;
	ChannelCode user_channel_code;
	AuthenticationTypeCode user_authentication_type_code;

/* this is just a pointer set depending on the value of conf_radius_username_mapping 
 * conf_radius_username_mapping = USERNAME => 
 *            active_authentication_type_code = user_authentication_type_code
 *
 * conf_radius_username_mapping = DEVICE_SERIAL_NUMBER => 
 *            active_authentication_type_code = admin_authentication_type_code
 */
	AuthenticationTypeCode active_authentication_type_code;

} rlm_ftress_t;


static void create_search_criteria_username(const char* username, 
					    UserCode* uc,
					    DeviceSearchCriteria* dsc) {

	*uc = ftress_user_code_create(username);
}

static void free_search_criteria_username(UserCode* uc, 
					  DeviceSearchCriteria* dsc) {
	ftress_user_code_free(*uc);
}

static void set_active_authentication_type_code_username(struct rlm_ftress_t* data) {
	data->active_authentication_type_code = data->user_authentication_type_code;
}

static void create_search_criteria_device_sn(const char* username, 
					     UserCode* uc, 
					     DeviceSearchCriteria* dsc) {
	
	*dsc = ftress_device_search_criteria_create(1,		/* TODO: search limit, request proper constant */
						    0,		/* TODO: assigned to user, request proper constant */
						    NULL,
						    NULL,	/* device id */
						    NULL,	/* device type code */
						    NULL,
						    NULL,
						    0,		/* issue number */
						    username,	/* serial number */
						    NULL,
						    NULL);
}

static
void free_search_criteria_device_sn(UserCode* uc, 
				    DeviceSearchCriteria* dsc)
{
	ftress_device_search_criteria_free(*dsc);
}

static void set_active_authentication_type_code_device_sn(struct rlm_ftress_t* data) {
	data->active_authentication_type_code = data->admin_authentication_type_code;
	
}

static struct {
	int code;
	char* name;
	void (*create_search_criteria) (const char* username, UserCode* uc, DeviceSearchCriteria* dsc);
	void (*free_search_criteria) (UserCode* uc, DeviceSearchCriteria* dsc);
	void (*set_active_authentication_type_code)(struct rlm_ftress_t* instance);
} RADIUS_USERNAME_MAPPING_TABLE[] = {
	/* default */
	{  
		0, "USERNAME",
		create_search_criteria_username,
		free_search_criteria_username, 
		set_active_authentication_type_code_username
	},
	{  
		1, "DEVICE_SERIAL_NUMBER",
		create_search_criteria_device_sn, 
		free_search_criteria_device_sn,
		set_active_authentication_type_code_device_sn
	},
	/* the table has to be terminated with this */
	{ -1, NULL,                   
	  NULL,                             
	  NULL,
	  NULL
	}
};

static int is_valid_radius_username_mapping(const int mapping) {
	int i = 0;
	while (-1 != RADIUS_USERNAME_MAPPING_TABLE[i].code) {
		if (mapping == RADIUS_USERNAME_MAPPING_TABLE[i].code) {
			return 1; /* true */
		}
		++i;
	}
	radlog(L_AUTH, 
	       "rlm_ftress: ERROR: radius_username_mapping set to invalid value (%d)!, valid values are:",
	       mapping);
	return 0; /* false */
}

static void display_radius_username_mapping_info() {
	int i = 0;
	while (-1 != RADIUS_USERNAME_MAPPING_TABLE[i].code) {
		radlog(L_AUTH, "rlm_ftress: radius_username_mapping = %d (%s)", 
		       RADIUS_USERNAME_MAPPING_TABLE[i].code,
		       RADIUS_USERNAME_MAPPING_TABLE[i].name);
		++i;
	}
}

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
	{ "admin_authentication_type_code",  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_admin_authentication_type_code),  NULL,  NULL},

	{ "server_authentication_type_code", PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_server_authentication_type_code), NULL,  NULL},
	{ "server_channel",                  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_server_channel),                  NULL,  NULL},
	{ "server_username",                 PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_server_username),                 NULL,  NULL},
	{ "server_password",                 PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_server_password),                 NULL,  NULL},

	{ "user_channel",                    PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_user_channel),                    NULL,  NULL},
	{ "user_authentication_type_code",   PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_user_authentication_type_code),   NULL,  NULL},

	{ "security_domain",                 PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_security_domain),                 NULL,  NULL},

	{ "endpoint_authenticator",          PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_endpoint_authenticator),          NULL,  NULL},
	{ "endpoint_authenticator_manager",  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_endpoint_authenticator_manager),  NULL,  NULL},
	{ "endpoint_device_manager",         PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_endpoint_device_manager),         NULL,  NULL},

	{ "radius_username_mapping",         PW_TYPE_INTEGER,    offsetof(rlm_ftress_t, conf_radius_username_mapping),         NULL,  0}, /* 0=default */
	
	{ NULL, -1, 0, NULL, NULL}
};

/* authenticates this module to 4TRESS server in order to do:
 * - ftress_indirect_primary_authenticate_device()
 * - ftress_reset_authenticator_failed_authentication_count()
 */
static Alsi* authenticate_module_to_ftress(void* instance) {

	struct rlm_ftress_t* config = instance;

	/** Create ChannelCode*/
	config->server_channel_code = 
		ftress_channel_code_create(config->conf_server_channel, 0);
	
	/** Create SecurityDomain */
	config->security_domain = 
		ftress_security_domain_create(config->conf_security_domain);		

	ftress_security_domain_set_domain(config->security_domain, 
					  config->conf_security_domain); /* TODO: check if this is required */

	/** Create AuthenticationTypeCode */
	AuthenticationTypeCode server_authentication_type_code = 
		ftress_authentication_type_code_create(config->conf_server_authentication_type_code);

	/** Create UPAuthenticationRequest */
	UPAuthenticationRequest req = 
		ftress_up_authentication_request_create(NULL, 
							0, 
							server_authentication_type_code, 
							NULL ,
							config->conf_server_password, 
							NULL, 
							NULL, 
							config->conf_server_username);

	/** Create PrimaryAuthenticateUPResponse */
	PrimaryAuthenticateUPResponse resp = 
		ftress_primary_authenticate_up_response_create();

	Alsi* alsi = NULL;

	const int error_code =
		ftress_primary_authenticate_up(config->conf_endpoint_authenticator, 
					       config->server_channel_code, 
					       req, 
					       config->security_domain, 
					       resp);

	if (FTRESS_SUCCESS == error_code) {
		/** Extract AuthenticationResponse from primaryAuthenticateUPResponse */
		AuthenticationResponse auth_res =
			ftress_primary_authenticate_up_get_authentication_response(resp);
		
		/** Extract alsi from AuthenticationResponse */
		alsi = ftress_authentication_response_get_alsi(auth_res);
		/** TODO: free auth_res ? **/
	}
	
	ftress_primary_authenticate_up_response_free(resp);
	ftress_up_authentication_request_free(req);
	ftress_authentication_type_code_free(server_authentication_type_code);
	return alsi;
}

/* these function pointers are assigned depending on the value of conf_radius_username_mapping,
 * this is to avoid having if/else blocks all over the place.
 */
static void (*create_search_criteria) (const char* username, UserCode* uc, DeviceSearchCriteria* dsc);
static void (*free_search_criteria) (UserCode* uc, DeviceSearchCriteria* dsc);


static void set_radius_username_mapping_mode(struct rlm_ftress_t* data) {
	int i = 0;
	while (-1 != RADIUS_USERNAME_MAPPING_TABLE[i].code) {
		if (data->conf_radius_username_mapping == RADIUS_USERNAME_MAPPING_TABLE[i].code) {
			create_search_criteria = 
				RADIUS_USERNAME_MAPPING_TABLE[i].create_search_criteria;
			free_search_criteria =
				RADIUS_USERNAME_MAPPING_TABLE[i].free_search_criteria;

			RADIUS_USERNAME_MAPPING_TABLE[i].set_active_authentication_type_code(data);
			
		}
		++i;
	}

	radlog(L_AUTH, 
	       "rlm_ftress: ERROR: set_radius_username_mapping_mode() FAILED!");
	
}

/* module functions */

static int rlm_ftress_init(void) {
	return 0;
}

static int rlm_ftress_instantiate(CONF_SECTION *conf, void **instance)
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
	
	/* making our life easier, if the conf_radius_username_mapping is invalid, 
	 * we don't need to bother with the rest  
	 */
	if(!is_valid_radius_username_mapping(data->conf_radius_username_mapping)) {
		display_radius_username_mapping_info();
		free(data);
		return -1;
	}

	/** Initialise ftress */
	ftress_init();

	*instance = data;

	data->module_alsi = authenticate_module_to_ftress(data);
	if (NULL != data->module_alsi) {
		const char* alsi_str = ftress_alsi_get_alsi(data->module_alsi);
		if (NULL != alsi_str) {
			radlog(L_AUTH, "rlm_ftress: module successfully authenticated to 4TRESS server.");
			/* success */
		}
	} else {
		radlog(L_AUTH, "rlm_ftress: module failed to authenticate to 4TRESS server.");
		/* TODO: free alsi? */
		return -1;
	}

	/* check this later */
	data->user_channel_code = ftress_channel_code_create(data->conf_user_channel , 0);

	data->admin_authentication_type_code = 
		ftress_authentication_type_code_create(data->conf_admin_authentication_type_code);

	data->user_authentication_type_code = 
		ftress_authentication_type_code_create(data->conf_user_authentication_type_code);

	set_radius_username_mapping_mode(data);
	return 0; /* success */
}

/* TODO: clean this up, it is getting to long and messy */
static int rlm_ftress_authenticate(void *instance, REQUEST *request) {

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

	DeviceSearchCriteria device_search_criteria = NULL;
	UserCode user_code = NULL;

	radlog(L_AUTH,
	       "rlm_ftress: device_search_criteria = %u, user_code = %u",
	       device_search_criteria,
	       user_code);
		
	create_search_criteria(username, &user_code, &device_search_criteria);

	radlog(L_AUTH,
	       "rlm_ftress: device_search_criteria = %u, user_code = %u",
	       device_search_criteria,
	       user_code);

	DeviceAuthenticationRequest req =
		ftress_device_authentication_request_create(NULL,
							    0,				/* TODO: authenticate no session - request proper constant */
							    config->active_authentication_type_code,
							    NULL,
							    1, 				/* TODO: SYNCHRONOUS - request proper constant in ftress.h */
							    NULL,
							    device_search_criteria,
							    password,
							    user_code);
	
	IndirectPrimaryAuthenticateDeviceResponse resp =
		ftress_indirect_primary_authenticate_device_response_create();

	int authentication_result = RLM_MODULE_REJECT; /* default */

	const int error_code = 
		ftress_indirect_primary_authenticate_device(config->conf_endpoint_authenticator,
							    config->module_alsi,
							    config->user_channel_code,
							    req,
							    config->security_domain,
							    resp);

	if (FTRESS_SUCCESS == error_code) {
		AuthenticationResponse auth_resp =
			ftress_primary_authenticate_device_get_authentication_response(resp);

		authentication_result =
			(NULL != ftress_authentication_response_get_alsi(auth_resp))
			? RLM_MODULE_OK : RLM_MODULE_REJECT;

		/* TODO: ? check on who is freeing AuthenticationResponse */
	} else {
		/* TODO: ftress_exception_handler is not exposed in ftress.h */
		radlog(L_AUTH, "rlm_ftress: 4TRESS ERROR: %s", 
		       ftress_exception_handler(error_code));	
	}

	ftress_indirect_primary_authenticate_device_response_free(resp);
	ftress_device_authentication_request_free(req);
	free_search_criteria(&user_code, &device_search_criteria);

	radlog(L_AUTH, "rlm_ftress: ftress_authenticate(): %d", authentication_result);
	return authentication_result;
}

static int rlm_ftress_detach(void *instance)
{
	const struct rlm_ftress_t* data = instance;

	/* TODO: who is responsible for freeing module_alsi data->module_alsi ? */ 
	ftress_free_channel_code(data->server_channel_code);
	ftress_free_security_domain(data->security_domain);
	ftress_free_authentication_type_code(data->admin_authentication_type_code);
	ftress_free_channel_code(data->user_channel_code);
	ftress_free_authentication_type_code(data->user_authentication_type_code);

	/* ftress client cleanup */
	ftress_quit();

	/* free strings */
	free(data->conf_admin_authentication_type_code);

	free(data->conf_server_authentication_type_code);
	free(data->conf_server_channel);
	free(data->conf_server_username);
	free(data->conf_server_password);

	free(data->conf_user_channel);
	free(data->conf_user_authentication_type_code);

	free(data->conf_security_domain);

	free(data->conf_endpoint_authenticator);
	free(data->conf_endpoint_authenticator_manager);
	free(data->conf_endpoint_device_manager);

	free(data);
	return 0;
}

/*
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_ftress = {
	"ftress",
	RLM_TYPE_THREAD_SAFE,				/* type */
	rlm_ftress_init,				/* initialization */
	rlm_ftress_instantiate,				/* instantiation */
	{
		rlm_ftress_authenticate,		/* authentication */
		NULL,					/* authorization */
		NULL,					/* preaccounting */
		NULL,					/* accounting */
		NULL,					/* checksimul */
		NULL,					/* pre-proxy */
		NULL,					/* post-proxy */
		NULL					/* post-auth */
	},
	rlm_ftress_detach,				/* detach */
	NULL,						/* destroy */
};
