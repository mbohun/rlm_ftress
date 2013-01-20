rlm_ftress
==========

[4TRESS](http://www.hidglobal.com/products/software/indentity-assurance/4tress-authentication-appliance) plugin for [FreeRADIUS](http://freeradius.org) I wrote back in 2007-2008 while working for [ActivIdentity](http://www.hidglobal.com/identity-assurance)

![Alt text](https://raw.github.com/mbohun/rlm_ftress/master/doc/rlm_ftress-overview.png "rlm_ftress overview")

## plugin architecture
![Alt text](https://raw.github.com/mbohun/rlm_ftress/master/doc/rlm_ftress-plugin-architecture.png "rlm_ftress plugin architecture")

## implementation notes

### OVERVIEW
This document describes the implementation of rlm_ftress - a plugin for FreeRADIUS server that connects 4TRESS server and FreeRADIUS. The actual communication is not done by rlm_ftress directly, but through libftress that uses SOAP to comunicate with 4TRESS server.

### PREREQUIREMENTS
In order to understand this document some basic knowledge of FreeRADIUS is required, mainly:
FreeRADIUS module interface documentation
FreeRADIUS configuration files documentation

### NAMING CONVENTIONS
libftress functions are prefixed with ftress_, please refer to libftress documentation and to ftress.h

### SOURCE CODE WALKTHROUGH
At the startup FreeRADIUS server parses its configuration files and it attempts to load every module present in 'modules' section of the $FREERADIUS/etc/raddb/radius.conf file. Every module has 0..n configuration properties. For illustration here is an example of rlm_ftress configuration properties (lines starting with # are comments):
```
  modules {

        # ...
  
        ftress {

                # use http or https (ssl)
                use_ssl = no

                # required for reseting the failed login counter only
                admin_authentication_type_code = "AT_AIOTP"

                # required/used by rlm_ftress to authenticate itself to 4TRESS server
                server_authentication_type_code = "OP_ATCODE"
                server_channel = "OPERATOR"
                server_username = "ftadmin"
                server_password = "Password01"

                # used by endusers to authenticate
                user_channel = "CH_WEB" # for end users
                user_authentication_type_code = "DYNMC_AUTH" # for endusers

                security_domain = "DOMAIN1"

                # endpoints for different SOAP services
                endpoint_authenticator = "http://192.168.1.119:9090/4TRESSSoap/services/Authenticator-12"
                endpoint_authenticator_manager = "http://192.168.1.119:9090/4TRESSSoap/services/AuthenticatorManager-12"
                endpoint_device_manager = "http://192.168.1.119:9090/4TRESSSoap/services/DeviceManager-12"

                # how to interpret the username value in incoming RADIUS requests
                # 0 = username
                # 1 = device serial number
                #
                radius_username_mapping = 0

                # authentication forwarding
                forward_authentication_mode = yes
                forward_authentication_server = 192.168.1.109
                forward_authentication_port = 1812
                forward_authentication_timeout = 10
                forward_authentication_retries = 3
                forward_authentication_secret = "crapcrap123"

        }

  }
```

### CONSTRUCTOR (instantiation)
The first function called for each module is the module 'constructor', see `module_t rlm_ftress` for details, the constructor is `rlm_ftress_instantiate`. The constructor (`rlm_ftress_instantiate`) invokes the built in configuration properties parser. FreeRADIUS is going to use its built in parser that parses the configuration properties and stores them in variables (usually packed in a struct) in the module.
To do this the module has to:

1. define the variables, see struct `rlm_ftress_t`

2. setup the array of config options for the FreeRADIUS internal parser, see `CONF_PARSER module_config[]`
 
Every config property has 5 attributes:

1. name

2. type, FreeRADIUS supports 4 types:
   ```
   PW_TYPE_BOOLEAN
   PW_TYPE_STRING_PTR
   PW_TYPE_INTEGER
   PW_TYPE_IPADDR
   ```

3. mem location (variable) where to store the parsed result

4. not used

5. default value

example:
```C
static CONF_PARSER module_config[] = {
        /* name,     type,            mem location (variable),              NULL,  default value */
        { "use_ssl", PW_TYPE_BOOLEAN, offsetof(rlm_ftress_t, conf_use_ssl), NULL, "yes"},

        /* more configuration properties ... */

        { NULL, -1, 0, NULL, NULL} /* terminate the array of configuration properties */
};
```

After this 'generic' bit the module is to do its own custom initialization - rlm_ftress does:

1. call `is_valid_radius_username_mapping`

2. initializes libftress, depending on configuration property `use_ssl` sets HTTPS or HTTP mode for the rlm_ftress to 4TRESS server SOAP communication

3. call `authenticate_module_to_ftress` function to authenticate the module to 4TRESS server

4. checks if the authentication was successful

5. creates `user_channel_code`, `admin_authentication_type_code` and `user_authentication_type_code`

6. call `set_radius_username_mapping_mode` to setup so called username mapping mode (basically the usernames are interpreted as usernames, or device serial numbers, see bellow the dscription of the `set_radius_username_mapping_mode` function for details)

7. based on the value of `forward_authentication_mode` configuration property creates a client socket for so called authentication forwarding, see `rlm_ftress_authenticate` and `forward_authentication_request` function description bellow for more details

At this stage the rlm_ftress is ready for accepting and processing the incoming authentications.

### AUTHENTICATION
Every FreeRADIUS module can register at least one of the 8 available function pointers:

1. authentication

2. authorization

3. preaccounting

4. accounting

5. checksimul

6. pre-proxy

7. post-proxy

8. post-auth

Because rlm_ftress at this stage does only support authentication the only registered function pointer is authentication, and it points to `rlm_ftress_authenticate`
`rlm_ftress_authenticate` function invokes `authenticate_ftress_indirect_primary_device` function (described in detail bellow).

1. authenticate_ftress_indirect_primary_device calls to 4TRESS server and fetches back the return code:
   `RLM_MODULE_OK` - if the authentication on 4TRESS server succeded
   `FTRESS_ERROR_AUTHENTICATE_BAD_OTP` - if the authentication on 4TRESS server failed

2. if authenticate_ftress_indirect_primary_device returns `FTRESS_ERROR_AUTHENTICATE_BAD_OTP` and rlm_ftress is set to forward authentications to a 3rd party RADIUS server, rlm_ftress is going to call `forward_authentication_request` function and if the authentication to the 3rd party RADIUS server returns success `reset_failed_authentication_count` function is called to reset the failed authentication counter on 4TRESS. This step is repeated `conf_forward_authentication_retries` times.

### DESTRUCTOR
At the rlm_ftress module shutdown FreeRADIUS invokes its destructor - that is used to free any resources. The destructor function is `rlm_ftress_detach`. `rlm_ftress_detach`:

1. closes the client socket for authentication forwarding (if we opened one)

2. frees all resources required by libftress

3. shuts down libftress

4. frees all the parsed string configuration properties (only configuration properties of type `PW_TYPE_STRING_PTR` were allocated dynamically and therefore need to be freed) 

### CONSTANTS

`FTRESS_ERROR_AUTHENTICATE_BAD_OTP` - returned by libftress if an authentication on 4TRESS server failed because of bad OTP
`RLM_FTRESS_FORWARD_AUTHENTICATION_PROBLEM` - returned if there was a problem to communicate with 4TRESS server
`RLM_FTRESS_FORWARD_AUTHENTICATION_ACCEPT` - returned if forwarded authentication succeeded
`RLM_FTRESS_FORWARD_AUTHENTICATION_REJECT` - returned if forwarded authentication failed

### DATA STRUCTURES
`module_t rlm_ftress`
Every FreeRADIUS module has to setup this structure, i.e. register function pointers for construction, destruction, and at least one of the following: authentication, authorization, preaccounting, accounting, checksimul, pre-proxy, post-proxy, post-auth

`CONF_PARSER module_config[]`
Static array of configuration properties required by FreeRADIUS config properties parser

`struct rlm_ftress_t`
All required variables for rlm_ftress operation are stored in this structure. The following variables are 1:1 representation of the configuration properties required by rlm_ftress. FreeRADIUS config property parser populates them with values read from the $FREERADIUS/etc/raddb/radius.conf file as configured in the modules section, subsection ftress. These variables are 'read only', rlm_ftress is not changing them.
```    
int conf_use_ssl
char* conf_admin_authentication_type_code
char* conf_server_authentication_type_code
char* conf_server_channel
char* conf_server_username
char* conf_server_password
char* conf_user_channel
char* conf_user_authentication_type_code
char* conf_security_domain
char* conf_endpoint_authenticator
char* conf_endpoint_authenticator_manager
char* conf_endpoint_device_manager
int conf_radius_username_mapping
int conf_forward_authentication_mode
uint32_t conf_forward_authentication_server
int conf_forward_authentication_port
int conf_forward_authentication_timeout
int conf_forward_authentication_retries
char* conf_forward_authentication_secret
```

The following variables are constructed by rlm_ftress at instantiation time from the above configuration properties using libftress function calls. These variables are required to init and setup libftress for communication with 4TRESS server. Refer to libftress documentation for their description.

```
Alsi* module_alsi
ChannelCode server_channel_code
SecurityDomain security_domain
AuthenticationTypeCode admin_authentication_type_code
ChannelCode user_channel_code
AuthenticationTypeCode user_authentication_type_code
```
`AuthenticationTypeCode active_authentication_type_code` This is just a pointer set depending on the value of conf_radius_username_mapping configuration property. If the value of conf_radius_username_mapping is set to USERNAME the pointer points to user_authentication_type_code. If the value of conf_radius_username_mapping is set to DEVICE_SERIAL_NUMBER the pointer is set to admin_authentication_type_code. This is to avoid cluttering all functions that are using authentication_type_code with if-else blocks.

`int client_sock_fd` Client socket file descriptor used for authentication forwarding

`struct sockaddr_in client_sock_addr` Client socket address struct used for authentication forwarding
      
`RADIUS_USERNAME_MAPPING_TABLE[]` Static array of supported username mapping modes. Currently two modes are supported:

1. USERNAME (`radius_username_mapping` set to 0, this is the default)

2. DEVICE_SERIAL_NUMBER (`radius_username_mapping` set to 1)

### FUNCTION REFERENCE

`static int rlm_ftress_instantiate(CONF_SECTION *conf, void **instance)`
Constructor.

`static int rlm_ftress_detach(void *instance)`
Destructor.

`static int rlm_ftress_authenticate(void *instance, REQUEST *request)`
This is the main function of rlm_ftress for authentication. It contains all of the 'high level' logic used for authentication of users, and optional authentication forwarding to a 3rd party server and failed authentication counter reseting on 4TRESS server. 
Return codes:
`RLM_MODULE_OK` on success
`RLM_MODULE_REJECT` on failure

`static void set_radius_username_mapping_mode(struct rlm_ftress_t* data)`
Helper function for setting username mapping mode. Depending on the value of radius_username_mapping property in the `$FREERADIUS/etc/raddb/radius.conf` file it assigns the following pointers:

```
static void (*create_search_criteria) (const char* username, UserCode* uc, DeviceSearchCriteria* dsc)
static void (*free_search_criteria) (UserCode* uc, DeviceSearchCriteria* dsc)
static void (*get_user_code)(struct rlm_ftress_t* data, const char* username, UserCode* uc)
rlm_ftress_t.active_authentication_type_code
```
The available username mapping modes are defined in the `RADIUS_USERNAME_MAPPING_TABLE[]`. Currently supported modes are:
USERNAME (0) - in this mode the pointers are assigned as follows:
```
create_search_criteria : create_search_criteria_username
free_search_criteria   : free_search_criteria_username
get_user_code          : get_user_code_username
rlm_ftress_t.active_authentication_type_code : rlm_ftress_t.user_authentication_type_code
```
DEVICE_SERIAL_NUMBER (1) - in this mode the pointers are assigned as follows:
```
create_search_criteria : create_search_criteria_device_sn
free_search_criteria   : free_search_criteria_device_sn
get_user_code          : get_user_code_device_sn
rlm_ftress_t.active_authentication_type_code : rlm_ftress_t.admin_authentication_type_code
```
This approach was chosen to avoid cluttering every function that uses any of these 4 pointers with if-else blocks.

`static void display_radius_username_mapping_info()`
Helper function that displays a table of supported username mapping modes. This function is called when `is_valid_radius_username_mapping` returns an error, i.e. the `radius_username_mapping` property in the `$FREERADIUS/etc/raddb/radius.conf file is set to invalid value. This way the user gets a list of supported values (and their human readable names).

`static int is_valid_radius_username_mapping(const int mapping)`
Helper function that validates if `radius_username_mapping` property in the `$FREERADIUS/etc/raddb/radius.conf` file is set to a valid value. 
Return codes:
`1` on success
`0` on failure

`static int authenticate_module_to_ftress(void* instance)`
This function calls libftress `ftress_primary_authenticate_up` function to authenticate rlm_ftress to 4TRESS server with username and password that are set in `$FREERADIUS/etc/raddb/radius.conf` (`server_username`/`server_password` configuration properties). The success or failure of authentication are determined by the value of `rlm_ftress_t.module_alsi` this function populates on success, on authentication failure, or communication failure `rlm_ftress_t.module_alsi` is set to `NULL`.
Return codes:
Allways 0

`static int authenticate_ftress_indirect_primary_device(void *instance, REQUEST *request)`
This function calls libftress `ftress_indirect_primary_authenticate_device` function to authenticate users with username/OTP. 
Return codes:
`RLM_MODULE_OK` on success
`RLM_MODULE_REJECT` on failure

`static int forward_authentication_request(void *instance, REQUEST *request)`
This function uses the client socket to forward authentication requests to a 3rd party RADIUS server.
Return codes:
`RLM_FTRESS_FORWARD_AUTHENTICATION_ACCEPT `
`RLM_FTRESS_FORWARD_AUTHENTICATION_REJECT`
`RLM_FTRESS_FORWARD_AUTHENTICATION_PROBLEM`

`static int reset_failed_authentication_count(void *instance, REQUEST *request)`
This function calls libftress `ftress_reset_device_authenticator_failed_authentication_count` to reset the failed authentication counter on 4TRESS server.
Return codes:
`1` on success
`0` on failure

## building & installing
Get the FreeRadius server source (the 1.1.x series is supported):
```
$ cd ~/src
$ wget ftp://ftp.freeradius.org/pub/radius/freeradius-1.1.8.tar.bz2
$ tar -jxvf freeradius-1.1.8.tar.bz2
```

Go to the `modules` subdir and clone/checkout/copy in the `rlm_ftress` source: 
```
$ cd freeradius-1.1.8/src/modules
$ git clone git://github.com/mbohun/rlm_ftress.git
```

The `freeradius-1.1.8/src/modules/stable` file is used to specify which FreeRADIUS modules/plugins will be build:
```
$ echo "rlm_ftress" >> stable
```

Go into the `rlm_ftress` module dir and run the `autogen.sh` script to generate the `configure` file (this needs to be done only once):
```
$ cd rlm_ftress
$ ./autogen.sh
```

Go back to the FreeRADIUS top level dir and run a standard `./configure; make; sudo make install` build. Note: The QuickStartAPI library (either the shared libftress.so or the static libftress.a) needs to be available to the linker.
```
$ cd ~/src/freeradius-1.1.8
$ ./configure --prefix=/opt/freeradius-1.1.8
$ make
$ sudo make install
```
