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
#include <sys/socket.h>
#include "ftress.h"

/* TODO (libftress.a): request proper error codes */
#define FTRESS_ERROR_AUTHENTICATE_BAD_OTP RLM_MODULE_REJECT


/* TODO (libftress.a): my Alsi copy ctor, move this to libftress.a */
Alsi ftress_alsi_dup(const Alsi other) {
	char* alsi_str = strdup(ftress_alsi_get_alsi(other));
	time_t* t = malloc(sizeof(time_t));
	memcpy(t, ftress_alsi_get_time_stamp(other), sizeof(time_t));

	Alsi this = ftress_alsi_create_default();
	ftress_alsi_set_alsi(this, alsi_str);
	ftress_alsi_set_time_stamp(this, t);
	return this;
}

void ftress_alsi_dup_free(const Alsi alsi) {
	free(ftress_alsi_get_alsi(alsi));
	free(ftress_alsi_get_time_stamp(alsi));
	free(alsi);
}

UserCode ftress_user_code_copy(const UserCode other) {
	UserCode uc = ftress_user_code_create_default();
	char* uc_str = strdup(ftress_user_code_get_code(other)); /* what if the string is empty? */
	ftress_user_code_set_code(uc, uc_str);
	return uc;
}

/* TODO (libftress.a): this is only tmp solution */
void ftress_user_code_copy_free(const UserCode uc) {
	free(ftress_user_code_get_code(uc));
	free(uc);
}

typedef struct rlm_ftress_t {
/* these are the variables we read from the configuration file, they are prefixed with conf_ */
	int conf_use_ssl;

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

	int conf_forward_authentication_mode;
	uint32_t conf_forward_authentication_server;
	int conf_forward_authentication_port;
	char* conf_forward_authentication_secret;

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

/* socket file descriptor for authentication forwarding
 * it is created and used only when  
 * 'conf_forward_authentication_mode = yes'
 */ 
	int client_sock_fd;
	struct sockaddr_in client_sock_addr;
} rlm_ftress_t;

static CONF_PARSER module_config[] = {
	{ "use_ssl",                         PW_TYPE_BOOLEAN,    offsetof(rlm_ftress_t, conf_use_ssl),                         NULL, "no"}, /* no=default */

	{ "admin_authentication_type_code",  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_admin_authentication_type_code),  NULL, NULL},

	{ "server_authentication_type_code", PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_server_authentication_type_code), NULL, NULL},
	{ "server_channel",                  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_server_channel),                  NULL, NULL},
	{ "server_username",                 PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_server_username),                 NULL, NULL},
	{ "server_password",                 PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_server_password),                 NULL, NULL},

	{ "user_channel",                    PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_user_channel),                    NULL, NULL},
	{ "user_authentication_type_code",   PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_user_authentication_type_code),   NULL, NULL},

	{ "security_domain",                 PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_security_domain),                 NULL, NULL},

	{ "endpoint_authenticator",          PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_endpoint_authenticator),          NULL, NULL},
	{ "endpoint_authenticator_manager",  PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_endpoint_authenticator_manager),  NULL, NULL},
	{ "endpoint_device_manager",         PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_endpoint_device_manager),         NULL, NULL},

	{ "radius_username_mapping",         PW_TYPE_INTEGER,    offsetof(rlm_ftress_t, conf_radius_username_mapping),         NULL, 0   }, /* 0=default */
	
	{ "forward_authentication_mode",     PW_TYPE_BOOLEAN,    offsetof(rlm_ftress_t, conf_forward_authentication_mode),     NULL, "no"}, /* no=default */
	{ "forward_authentication_server",   PW_TYPE_IPADDR,     offsetof(rlm_ftress_t, conf_forward_authentication_server),   NULL, "*"},
	{ "forward_authentication_port",     PW_TYPE_INTEGER,    offsetof(rlm_ftress_t, conf_forward_authentication_port),     NULL, 1812}, /* default RADIUS port */
	{ "forward_authentication_secret",   PW_TYPE_STRING_PTR, offsetof(rlm_ftress_t, conf_forward_authentication_secret),   NULL, NULL},

	{ NULL, -1, 0, NULL, NULL}
};

/* 'USERNAME' mode implementation */
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

static void get_user_code_username(struct rlm_ftress_t* data, const char* username, UserCode* uc) {
/* TODO: strdup() for now, till the mem management is not fixed in libftress.a */
	*uc = ftress_user_code_create(strdup(username));
}

/* 'DEVICE_SERIAL_NUMBER' mode implementation */
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

static void get_user_code_device_sn(const struct rlm_ftress_t* data, 
				    const char* device_serial_number, 
				    UserCode* uc) {

	DeviceSearchCriteria dsc =
		ftress_device_search_criteria_create(1, //searchLimit,
						     0, //assignedToUser, - logically must be assigned
						     NULL,
						     NULL,//deviceId, 
						     NULL,//deviceTypeCode,
						     NULL,
						     NULL,
						     0,//issueNumber,
						     device_serial_number,//serialNumber,
						     NULL,
						     NULL);

	SearchDevicesResponse resp =
		ftress_search_devices_response_create();

	const int ftress_result = 
		ftress_search_devices(data->conf_endpoint_device_manager,
				      data->module_alsi,
				      data->server_channel_code,
				      dsc,
				      data->security_domain,
				      resp);

	if (FTRESS_SUCCESS == ftress_result) {
		DeviceSearchResults dsr = 
			ftress_search_devices_response_get_device_search_results(resp);

		const int number_of_results =
			ftress_device_search_results_get_matched_criteria(dsr);
			
		radlog(L_AUTH, "rlm_ftress: ftress_device_search_results_get_matched_criteria():%d",
		       number_of_results);

		if (number_of_results < 1) {
			/* the lookup failed, not much we can do... */
			/* TODO: who is freeing DeviceSearchResults? */
			*uc = NULL;
			ftress_search_devices_response_free(resp);
			ftress_device_search_criteria_free(dsc);
			return;
		}

		ArrayOfDevices aod = ftress_device_search_results_get_devices(dsr);

		radlog(L_AUTH, "rlm_ftress: ftress_arrayof_devices_get_size():%d",
		       ftress_arrayof_devices_get_size(aod));

		Device* devices = ftress_arrayof_devices_get_devices(aod);
		Device d = devices[0];
	     
		/* TODO: make sure user_code we are getting here is a DEEP-COPY.
		 *       *uc = ftress_user_code_dup(test);
		 *
		 * For now we do it ourselves manually:
		 */
		UserCode test = ftress_device_get_user_code(d);
		const char* uc_str = ftress_user_code_get_code(test);
		const char* uc_str_dup = strdup(uc_str);
		*uc = ftress_user_code_create(uc_str_dup);

		radlog(L_AUTH, "rlm_ftress: device: %s is assigned to user: %s",
		       device_serial_number, ftress_user_code_get_code(*uc));

		/*TODO (libftress.a): who is freeing DeviceSearchResults? */
		
	} else {
		/* log this */
		radlog(L_AUTH, "rlm_ftress: 4TRESS ERROR:%s",
		       ftress_exception_handler(ftress_result));
	}

	ftress_search_devices_response_free(resp);
	ftress_device_search_criteria_free(dsc);
}

/* every mode needs to be registered in this RADIUS_USERNAME_MAPPING_TABLE */
/* TODO: suggestion we can add 'description' string to the mode struct as well */
static struct {
	int code;
	char* name;
	void (*create_search_criteria) (const char* username, UserCode* uc, DeviceSearchCriteria* dsc);
	void (*free_search_criteria) (UserCode* uc, DeviceSearchCriteria* dsc);
	void (*set_active_authentication_type_code)(struct rlm_ftress_t* instance);
	void (*get_user_code)(struct rlm_ftress_t* data, const char* username_or_dev_sn, UserCode* uc);
} RADIUS_USERNAME_MAPPING_TABLE[] = {
	/* default: USERNAME mode */
	{  
		0, "USERNAME",
		create_search_criteria_username,
		free_search_criteria_username, 
		set_active_authentication_type_code_username,
		get_user_code_username
	},
	/* DEVICE_SERIAL_NUMBER mode */
	{  
		1, "DEVICE_SERIAL_NUMBER",
		create_search_criteria_device_sn, 
		free_search_criteria_device_sn,
		set_active_authentication_type_code_device_sn,
		get_user_code_device_sn
	},
	/* terminator - the table has to be terminated like this */
	{ -1, NULL,
	  NULL,
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

/* these function pointers are assigned depending on the value of conf_radius_username_mapping,
 * this is to avoid having if/else blocks all over the place.
 */
static void (*create_search_criteria) (const char* username, UserCode* uc, DeviceSearchCriteria* dsc);
static void (*free_search_criteria) (UserCode* uc, DeviceSearchCriteria* dsc);
static void (*get_user_code)(struct rlm_ftress_t* data, const char* username, UserCode* uc);

static void set_radius_username_mapping_mode(struct rlm_ftress_t* data) {
	int i = 0;
	while (-1 != RADIUS_USERNAME_MAPPING_TABLE[i].code) {
		if (data->conf_radius_username_mapping == RADIUS_USERNAME_MAPPING_TABLE[i].code) {
			create_search_criteria = 
				RADIUS_USERNAME_MAPPING_TABLE[i].create_search_criteria;
			free_search_criteria =
				RADIUS_USERNAME_MAPPING_TABLE[i].free_search_criteria;

			RADIUS_USERNAME_MAPPING_TABLE[i].set_active_authentication_type_code(data);

			get_user_code =
				RADIUS_USERNAME_MAPPING_TABLE[i].get_user_code;
				
			
			return; /* success */
			
		}
		++i;
	}

	/* we should never come here */
	radlog(L_AUTH, 
	       "rlm_ftress: ERROR: set_radius_username_mapping_mode() FAILED!");
	
}

/* authenticates this module to 4TRESS server in order to do:
 * - ftress_indirect_primary_authenticate_device()
 * - ftress_reset_authenticator_failed_authentication_count()
 */
static int authenticate_module_to_ftress(void* instance) {

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
		const Alsi alsi = ftress_authentication_response_get_alsi(auth_res);
		config->module_alsi = ftress_alsi_dup(alsi);

		/** TODO: free auth_res ? **/
	}
	
	ftress_primary_authenticate_up_response_free(resp);
	ftress_up_authentication_request_free(req);
	ftress_authentication_type_code_free(server_authentication_type_code);

	return 0;
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
	if (data->conf_use_ssl) {
		ftress_init_ssl();
	} else {
		ftress_init();
	}

	/* this is supposed to populate data->module_alsi with a valid ALSI */
	authenticate_module_to_ftress(data);

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

	/* create client socket for receiving packets */
	if (data->conf_forward_authentication_mode) {

		data->client_sock_fd = -1;

		if ((data->client_sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			//failed to create a socket
			radlog(L_AUTH, "rlm_ftress: ERROR: failed to create a socket!");
			return -1;
		}

		/* bind any port */
		data->client_sock_addr.sin_family = AF_INET;
		data->client_sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		data->client_sock_addr.sin_port = htons(0);
  
		if (bind(data->client_sock_fd,
			 (struct sockaddr *)&(data->client_sock_addr),
			 sizeof(data->client_sock_addr)) < 0) {
			//failed to create a socket
			radlog(L_AUTH, "rlm_ftress: ERROR: failed to bind a port!");
			return -1;	
		}

	}

	*instance = data;
	return 0; /* success */
}

/* TODO: clean this up, it is getting to long and messy */
static int authenticate_ftress_indirect_primary_device(void *instance, REQUEST *request) {

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
		
	create_search_criteria(username, &user_code, &device_search_criteria);

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

	radlog(L_AUTH, "rlm_ftress: ftress_indirect_primary_authenticate_device(): %d, (FTRESS_SUCCESS:%d)",
	       error_code,
	       FTRESS_SUCCESS);

	if (FTRESS_SUCCESS == error_code) { /* this means just succesfull communication with 4tress server */
		AuthenticationResponse auth_resp =
			ftress_primary_authenticate_device_get_authentication_response(resp);

		authentication_result =
			(NULL != ftress_authentication_response_get_alsi(auth_resp))
			? RLM_MODULE_OK : RLM_MODULE_REJECT;

		if (RLM_MODULE_OK != authentication_result) {
			radlog(L_AUTH, "rlm_ftress: 4TRESS authentication FAILED!!!"); 
		}

		/* TODO: ? check on who is freeing AuthenticationResponse */

	} else {
		/* TODO: ftress_exception_handler is not exposed in ftress.h */
		radlog(L_AUTH, "rlm_ftress: 4TRESS ERROR: %s", 
		       ftress_exception_handler(error_code));	
	}

	ftress_indirect_primary_authenticate_device_response_free(resp);
	ftress_device_authentication_request_free(req);
	free_search_criteria(&user_code, &device_search_criteria);

	radlog(L_AUTH, "rlm_ftress: ftress_authenticate(): %s",
	       (authentication_result==RLM_MODULE_OK)?"RLM_MODULE_OK":"RLM_MODULE_REJECT" );

	return authentication_result;
}

static int forward_authentication_request(void *instance, REQUEST *request) {
	const struct rlm_ftress_t* data = instance;

	//time_t now = time(NULL);

	fd_set set;
	FD_ZERO(&set);
	FD_SET(data->client_sock_fd, &set);

	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	request->packet->sockfd = data->client_sock_fd;
	request->packet->dst_ipaddr = data->conf_forward_authentication_server;
	request->packet->dst_port = data->conf_forward_authentication_port;

	/* should we set new client IP and port as well ? */
	request->packet->src_ipaddr = data->client_sock_addr.sin_addr.s_addr;
	request->packet->src_port = data->client_sock_addr.sin_port;

	/* if they have provided a shared secret for forwarding */
	const char* secret =
		(NULL != data->conf_forward_authentication_secret) 
		? data->conf_forward_authentication_secret : request->secret;
	
	radlog(L_AUTH, "rlm_ftress: forwarding secret: %s", secret);

	if (rad_send(request->packet, NULL, secret) < 0) {
		radlog(L_AUTH, "rlm_ftress: ERROR: rad_send() failed!");
		return 0;
	}
/* TODO: fix the timeout
	if (select(data->client_sock_fd + 1, &set, NULL, NULL, &tv) != 1) {
		radlog(L_AUTH, "rlm_ftress: ERROR: received no packets!");
		return 0;
	}
*/
	RADIUS_PACKET* reply = rad_recv(data->client_sock_fd);

	const int forward_reply = reply->code;

	radlog(L_AUTH, "rlm_ftress: request->reply->code(after): %d",
	       forward_reply);
	
	if (PW_AUTHENTICATION_ACK == forward_reply) {
		return 1; /* success */
	} else {
		return 0; /* error */
	}

}

static int ftress_reset_failed_authentication_count(void *instance, REQUEST *request) {
	const struct rlm_ftress_t* data = instance;

	/* TODO: add support for device serial numbers here */
	/* can be both username OR device serial number*/
	const char* username = (char*)request->username->strvalue;
	UserCode user_code = NULL;
	get_user_code(data, username, &user_code);

	if (NULL == user_code) {
		/* failed to create user code, most likely because 
		   the device serial number to username lookup failed */
		radlog(L_AUTH, "rlm_ftress: ERROR: user (for device serial number:%s) not found! - can not reset 4TRESS failed authentication counter!",
		       username);
		return 0; /* failure */
	}

	ResetDeviceAuthenticatorFailedAuthenticationCountResponse resp =
		ftress_reset_device_authenticator_failed_authentication_count_response_create();

	const int error_code =
		ftress_reset_device_authenticator_failed_authentication_count(data->conf_endpoint_authenticator_manager,
									      data->module_alsi,
									      data->server_channel_code,
									      user_code,
									      data->admin_authentication_type_code,
									      data->security_domain,
									      resp);
	int return_code = 0; /* failure */

	if (FTRESS_SUCCESS == error_code) {
		radlog(L_AUTH, "rlm_ftress: ");
		return_code = 1; /* success */	
	} else {
		/* log error */
	}
	
	/* TODO (libftress.a): ftress_reset_device_authenticator_failed_authentication_count_response_free(resp); */
	
	/* TODO (libftress.a): add UserCode copy constructor */
	free(ftress_user_code_get_code(user_code)); //free the string first ...
	ftress_user_code_free(user_code); //then free the struct

	return return_code;
}

static int rlm_ftress_authenticate(void *instance, REQUEST *request) {

	const struct rlm_ftress_t* data = instance;

	/* at this stage we *NEED* ftress errors, as the different error codes are used to decide
	 * if the request needs to be forwarded or not.
	 */
	const int authenticate_to_ftress = 
		authenticate_ftress_indirect_primary_device(instance, request);

	if (RLM_MODULE_OK == authenticate_to_ftress) {
		/* successful athentication to 4tress server, we are done */
		return RLM_MODULE_OK;
	}

/* 8>< --- we get pass this point *ONLY* if the authentication to 4tress server failed --- ><8 */

	/* first check if authentication forwarding mode is on */
	if (!data->conf_forward_authentication_mode) {
		/* authentication forwarding is off, not much to do */
		return RLM_MODULE_REJECT;
	}

	/* now, be explicit about in what situation we want to forward authentication request to a 3rd party server */
	if (FTRESS_ERROR_AUTHENTICATE_BAD_OTP == authenticate_to_ftress) {
		
		const int forwarding_response =
			forward_authentication_request(data, request);

		radlog(L_AUTH, "rlm_ftress: forwarding_response: %d",
		       forwarding_response);

		if (forwarding_response) {
			/* the 3rd party RADIUS server responded OK */
			ftress_reset_failed_authentication_count(instance, request);
			return RLM_MODULE_OK;
		}

	}

	return RLM_MODULE_REJECT;
}

static int rlm_ftress_detach(void *instance)
{
	const struct rlm_ftress_t* data = instance;

	/* close the client socket */
	if (data->conf_forward_authentication_mode) {
		close(data->client_sock_fd);
	}

	/* TODO: who is responsible for freeing module_alsi data->module_alsi ? */
	ftress_alsi_dup_free(data->module_alsi);

	ftress_channel_code_free(data->server_channel_code);
	ftress_security_domain_free(data->security_domain);
	ftress_authentication_type_code_free(data->admin_authentication_type_code);
	ftress_channel_code_free(data->user_channel_code);
	ftress_authentication_type_code_free(data->user_authentication_type_code);

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

	free(data->conf_forward_authentication_secret);

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
