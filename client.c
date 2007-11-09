#include <string.h>
#include <freeradius-client.h>

int forward_authentication_request(int ip, int port, char* usr, char* pwd, char* secret) {

	rc_handle* rh = NULL;
        VALUE_PAIR* send = NULL;
        VALUE_PAIR* received = NULL;
	char msg[4096];

	char username[128];
	char password[AUTH_PASS_LEN + 1];

	strncpy(username, usr, sizeof(username));
	strncpy(password, pwd, sizeof(password));

	/* Initialize the 'rh' structure */
	rh = rc_new();
	if (rh == NULL) {
		printf("ERROR: Failed to allocate initial structure\n");
		exit(1);
	}

/* missing symbol?
	rh = rc_config_init(rh);
	if (rh == NULL) {
		printf("ERROR: Failed to initialze configuration\n");
		exit(1);
	}
*/

/* TODO: what is this?
	if (rc_add_config(rh, "auth_order", "radius", "config", 0) != 0) {
		printf("ERROR: Unable to set auth_order.\n");
		rc_destroy(rh);
		exit(1);
	}
*/

/* TODO: add this later - if required
	if (rc_add_config(rh, "login_tries", "4", "config", 0) != 0) 
	{
		printf("ERROR: Unable to set login_tries.\n");
		rc_destroy(rh);
		exit(1);
	}

	
	if (rc_add_config(rh, "seqfile", "/var/run/radius.seq", "config", 0) != 0)
	{
		printf("ERROR: Unable to set seq file.\n");
		rc_destroy(rh);
		exit(1);
	}
	
	if (rc_add_config(rh, "radius_retries", "3", "config", 0) != 0) {
		printf("ERROR: Unable to set radius_retries.\n");
		rc_destroy(rh);
		exit(1);
	}

	if (rc_add_config(rh, "radius_timeout", "5", "config", 0) != 0) {
		printf("ERROR: Unable to set radius_timeout.\n");
		rc_destroy(rh);
		exit(1);
	}
*/

	/* TODO: fix this */
	if (rc_add_config(rh, "dictionary", "/usr/local/radius/dictionary", "config", 0) != 0) {
		printf("ERROR: Unable to set dictionary.\n");
		rc_destroy(rh);
		exit(1);
	}


	/* TODO: fix this hardcoded crap */
	if (rc_add_config(rh, "authserver", "192.168.1.109:1812:testing123", "config", 0) != 0) {
		printf("ERROR: Unable to set authserver.\n");
		rc_destroy(rh);
		exit(1);
	}

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) {
		printf("ERROR: Failed to initialize radius dictionary\n");
		exit(1);
	}

	//Fill in User-name
	if (rc_avpair_add(rh, &send, PW_USER_NAME, username, -1, 0) == NULL)
		return ERROR_RC;

	//Fill in User-Password
	if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, password, -1, 0) == NULL)
		return ERROR_RC;

	//Fill in Service-Type
	UINT4 service = PW_AUTHENTICATE_ONLY;
	if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL)
		return ERROR_RC;

	const int result = rc_auth(rh, 0, send, &received, msg);

	rc_destroy(rh);
	rc_avpair_free(send);

	return (OK_RC==result) ? 1 : 0; 

}
