/**************************************************************************************************
File Name: ftress.h
Description: This file represents the 'public' interface to the 4TRESS C Client.

***************************************************************************************************/
#include <time.h>

#ifdef __cplusplus
 extern "C" {
 #endif

/* error codes */

#define FTRESS_SUCCESS                    0 // No error
#define FTRESS_SVR_FAULT                  2 // The service returned a server fault (SOAP 1.2 Receiver fault)
#define FTRESS_FATAL_ERROR                11 // Internal error
#define FTRESS_FAULT                      12 // An exception raised by the service
#define FTRESS_NO_METHOD                  13 // The dispatcher did not find a matching operation for the request
#define FTRESS_NO_DATA                    14 // No data in HTTP message
#define FTRESS_GET_METHOD                 15 // HTTP GET operation not handled
#define FTRESS_NULL                       19 // An element was null, while it is not supposed to be null
#define FTRESS_TCP_ERROR                  24 // A connection error occured
#define FTRESS_HTTP_ERROR                 25 // An HTTP error occured
#define FTRESS_SSL_ERROR                  26 // An SSL error occured

/* data types */
typedef void *Alsi;
typedef void *ChannelCode;
typedef void *SecurityDomain;
typedef void *UPAuthenticationRequest;
typedef void *AuthenticationRequestParameter;
typedef void *AuthenticationTypeCode;
typedef void *UserCode;
typedef void *AuthenticationResponse;
typedef void *MDPromptCode;
typedef void *PrimaryAuthenticateUPResponse;
typedef void *AuthenticationStatistics;
typedef void *AuthenticationResponseParameter;
typedef void *ArrayOfAuthenticationRequestParameter;
typedef void *ArrayOfMDPromptCode;
typedef void *ArrayOfInt;
typedef void *LogoutResponse;
typedef void *PrimaryAuthenticateDeviceResponse;
typedef void *DeviceAuthenticationRequest;
typedef void *DeviceSearchCriteria;
typedef void *DeviceGroupCode;
typedef void *ArrayOfDeviceGroupCode;
typedef void *DeviceId;
typedef void *DeviceTypeCode;
typedef void *DateRangeSearchCriteria;
typedef void *IndirectPrimaryAuthenticateUPResponse;
typedef void *IndirectPrimaryAuthenticateDeviceResponse;
typedef void *GetAuthenticationChallengeResponse;
typedef void *AuthenticationChallenge;
typedef void *SeedPositions;
typedef void *MDAuthenticationRequest;
typedef void *MDAuthenticationAnswer;
typedef void *MDAuthenticationPrompts;
typedef void *MDAuthenticationPrompt;
typedef void *ArrayOfMDAuthenticationAnswer;
typedef void *ArrayOfMDAuthenticationPrompt;
typedef void *GetMDAuthenticationPromptsResponse;
typedef void *IndirectPrimaryAuthenticateMDResponse;
typedef void *IndirectGetPasswordSeedPositionsResponse;
typedef void *ResetDeviceAuthenticatorFailedAuthenticationCountResponse;
typedef void *SearchDevicesResponse;
typedef void *DeviceSearchResults;
typedef void *ArrayOfDevices;
typedef void *Device;
typedef void *SDB;
typedef void *ArrayOfDeviceCredentialInfo;
typedef void *DeviceStatus;
typedef void *DeviceCredentialInfo;
typedef void *CredentialId;
typedef void *CredentialTypeCode;

/** ftress init */
const int ftress_init();

/** ftress quit */
const int ftress_quit();

/** ftress init ssl */
const int ftress_init_ssl();

/** 
* Returns the error or exception string
*/
char * ftress_exception_handler(int result);

/*************************************************************************************
*			 ftress DTOs                                                 *
*************************************************************************************/

/*************************************************************************************
*			 ChannelCode                                                 *
*************************************************************************************/

/** Default constructor for Channel code */
ChannelCode ftress_channel_code_create_default();

/** Parameterised constructor for Channel code */
ChannelCode ftress_channel_code_create(char *code, int allChannels);

/** Setter for channel code */
const int ftress_channel_code_set_code(ChannelCode channelCode, char *code);

/**  Getter for channel code*/
char * ftress_channel_code_get_code(ChannelCode channelCode);

/** Setter for all channels */
const int ftress_channel_code_set_all_channels(ChannelCode channelCode, int allChannels);

/** Getter for all channels */
int ftress_channel_code_get_all_channels(ChannelCode channelCode);

/** Free the Channel code */
const int ftress_channel_code_free(ChannelCode channelCode);

/*************************************************************************************
*			 SecurityDomain                                              *
*************************************************************************************/

/** Default constructor for security domain */
SecurityDomain ftress_security_domain_create_default();

/** Parameterised constructor for security domain */

SecurityDomain ftress_security_domain_create(char *domainCode);

/** Getter for security domain */
char * ftress_security_domain_get_domain(SecurityDomain securityDomain);

/** Setter for security domain code */
const int ftress_security_domain_set_domain(SecurityDomain securityDomain, char *domain);

/** Getter for security domain code */
char * ftress_security_domain_get_code(SecurityDomain securityDomain);

/** Setter for security domain code */
const int ftress_security_domain_set_code(SecurityDomain securityDomain, char *domainCode);

/**Free the security domain */
const int ftress_security_domain_free(SecurityDomain securityDomain);

/*************************************************************************************
*			 AuthenticationRequestParameter                              *
*************************************************************************************/

/**Default constructor for Authentication Request Parameter */
AuthenticationRequestParameter ftress_up_authentication_request_parameter_create_default();

/** Parameterised constructor for Authentication Request Parameter*/
AuthenticationRequestParameter ftress_up_authentication_request_parameter_create(char *name, char *value);

/** Setter for up authentication request parameter name*/
const int ftress_up_authentication_request_parameter_set_name(AuthenticationRequestParameter authenticationRequestParameter, char *name);

/** Getter for up authentication request parameter name */
char * ftress_up_authentication_request_parameter_get_name(AuthenticationRequestParameter authenticationRequestParameter);

/** Setter for up authentication request parameter value */
const int ftress_up_authentication_request_parameter_set_value(AuthenticationRequestParameter authenticationRequestParameter, char *value);

/** Getter for up authentication request parameter value */
char * ftress_up_authentication_request_parameter_get_value(AuthenticationRequestParameter authenticationRequestParameter);

/**Free the authentication request parameter */
const int ftress_authentication_request_parameter_free(AuthenticationRequestParameter authenticationRequestParameter);

/*************************************************************************************
*			 AuthenticationTypeCode                                      *
*************************************************************************************/

/** Default constructor for Authentication Type Code*/
AuthenticationTypeCode ftress_authentication_type_code_create_default();

/** Parameterised constructor for Authentication Type Code */
AuthenticationTypeCode ftress_authentication_type_code_create(char *code);

/** Setter for Authentication Type Code */
const int ftress_authentication_type_code_set_code(AuthenticationTypeCode authenticationTypeCode, char *code);

/** Getter for Authentication Type Code */
char* ftress_authentication_type_code_get_code(AuthenticationTypeCode authenticationTypeCode);

/**Free the Authentication Type Code */
const int ftress_authentication_type_code_free(AuthenticationTypeCode authenticationTypeCode);

/*************************************************************************************
*			 UserCode                                                    *
*************************************************************************************/

/** Default constructor for User Code */
UserCode ftress_user_code_create_default();

/** Copy constructor for User Code */
UserCode ftress_user_code_copy(UserCode userCode);

/** Parameterised constructor for User Code */
UserCode ftress_user_code_create(char *code);

/** Setter for User Code */
const int ftress_user_code_set_code(UserCode userCode, char *code);

/** Getter for User Code */
char * ftress_user_code_get_code(UserCode userCode);

/**Free the User Code */
const int ftress_user_code_free(UserCode userCode);

/*************************************************************************************
*			 ArrayOfAuthenticationRequestParameter                       *
*************************************************************************************/
/** Create array of authentication request parameter */
ArrayOfAuthenticationRequestParameter ftress_arrayof_authentication_request_parameter_create(int size, AuthenticationRequestParameter *authenticationRequestParameter);

/** Getter for array size of ArrayOfAuthenticationRequestParameter */
int ftress_arrayof_authentication_request_parameter_get_size(ArrayOfAuthenticationRequestParameter arrayOfAuthenticationRequestParameter);

/** Getter for array of authenticationRequestParameter */
AuthenticationRequestParameter * ftress_arrayof_authentication_request_parameter_get_parameters(ArrayOfAuthenticationRequestParameter arrayOfAuthenticationRequestParameter);

/** Setter for array size of ArrayOfAuthenticationRequestParameter */
const int ftress_arrayof_authentication_request_parameter_set_size(ArrayOfAuthenticationRequestParameter arrayOfAuthenticationRequestParameter, int size);

/** Setter for array of authenticationRequestParameter */
const int ftress_arrayof_authentication_request_parameter_set_parameters(ArrayOfAuthenticationRequestParameter arrayOfAuthenticationRequestParameter, AuthenticationRequestParameter *authenticationRequestParameter);

/** Free the ArrayOfAuthenticationRequestParameter */
const int ftress_arrayof_authentication_request_parameter_free(ArrayOfAuthenticationRequestParameter arrayOfAuthenticationRequestParameter);

/*************************************************************************************
*			 ArrayOfInt                                                  *
*************************************************************************************/
/** Create array of int */
ArrayOfInt ftress_arrayof_int_create(int size, int *values);

/** Getter for array size of ArrayOfInt */
int ftress_arrayof_int_get_size(ArrayOfInt arrayOfInt);

/** Getter for array of int */
int * ftress_arrayof_int_get_positions(ArrayOfInt arrayOfInt);

/** Setter for array size of ArrayOfInt */
const int ftress_arrayof_int_set_size(ArrayOfInt arrayOfInt, int size);

/** Setter for array of int */
const int ftress_arrayof_int_set_positions(ArrayOfInt arrayOfInt, int *values);

/** Free the ArrayOfInt */
const int ftress_arrayof_int_free(ArrayOfInt arrayOfInt);

/*************************************************************************************
*			 UPAuthenticationRequest                                     *
*************************************************************************************/

/** Default constructor for up authentication request */
UPAuthenticationRequest ftress_up_authentication_request_create_default();

/** Parameterised constructor for UP Authentication Request */
UPAuthenticationRequest ftress_up_authentication_request_create(ArrayOfAuthenticationRequestParameter auditedParameters, 
								int authenticateNoSession, 
								AuthenticationTypeCode authenticationTypeCode, 
								ArrayOfAuthenticationRequestParameter parameters, 
								char *password, 
								ArrayOfInt seedPositions, 
								UserCode userCode, 
								char *username );

/** Returns the password. */
char * ftress_up_authentication_request_get_password(UPAuthenticationRequest upAuthenticationRequest);

/** Returns the seed positions. */
int * ftress_up_authentication_request_get_seed_positions(UPAuthenticationRequest upAuthenticationRequest);

/** Returns the user code (external reference) of a specific user. */
UserCode ftress_up_authentication_request_get_user_code(UPAuthenticationRequest upAuthenticationRequest);

/** Returns the user name. */
char * ftress_up_authentication_request_get_user_name(UPAuthenticationRequest upAuthenticationRequest);

/** Returns the authentication type (code) of the authentication. */
AuthenticationTypeCode ftress_up_authentication_request_get_authentication_type_code(UPAuthenticationRequest upAuthenticationRequest);

/**Returns the audited parameters. */
ArrayOfAuthenticationRequestParameter ftress_up_authentication_request_get_audited_parameters(UPAuthenticationRequest upAuthenticationRequest); 

/**Returns the parameters. */
ArrayOfAuthenticationRequestParameter ftress_up_authentication_request_get_parameters(UPAuthenticationRequest upAuthenticationRequest);

/** Returns true/false ie 1/0 based on authenticate session */
int ftress_up_authentication_request_get_authenticate_no_session(UPAuthenticationRequest upAuthenticationRequest);


/** Sets the password (see note about seeded authentication above). */
const int ftress_up_authentication_request_set_password(UPAuthenticationRequest upAuthenticationRequest, char *password);

/** Sets the seed positions (of the seeded password). */
const int ftress_up_authentication_request_set_seed_positions(UPAuthenticationRequest upAuthenticationRequest, int *seedPositions);

/**Sets the user code (external reference) of a specific user. */
const int ftress_up_authentication_request_set_user_code(UPAuthenticationRequest upAuthenticationRequest, UserCode userCode);

/** Sets the user name (which in combination with the authentication type, identifies the user). */
const int ftress_up_authentication_request_set_user_name(UPAuthenticationRequest upAuthenticationRequest, char *userName);

/** Sets the authentication type (code) of the authentication. */
const int ftress_up_authentication_request_set_authentication_type_code(UPAuthenticationRequest upAuthenticationRequest, AuthenticationTypeCode authenticationTypeCode);

/**Sets the audited parameters. */
const int ftress_up_authentication_request_set_audited_parameters(UPAuthenticationRequest upAuthenticationRequest, ArrayOfAuthenticationRequestParameter arrayOfAuthenticationRequestParameter); 

/**Sets the parameters. */
const int ftress_up_authentication_request_set_parameters(UPAuthenticationRequest upAuthenticationRequest, ArrayOfAuthenticationRequestParameter arrayOfAuthenticationRequestParameter);

/** Sets true/false ie 1/0 based on authenticate session */
const int ftress_up_authentication_request_set_authenticate_no_session(UPAuthenticationRequest upAuthenticationRequest, int authenticateNoSession);

/**Free the UP Authentication Request */
const int ftress_up_authentication_request_free(UPAuthenticationRequest upAuthenticationRequest);

/*************************************************************************************
*			 Alsi                                                        *
*************************************************************************************/

/**Default constructor for Alsi */
Alsi ftress_alsi_create_default();

/** Copy constructor for Alsi */
Alsi ftress_alsi_copy(Alsi alsi);

/** Parameterised constructor for Alsi */
Alsi ftress_alsi_create(char *alsi);

/** Getter for Alsi */
char * ftress_alsi_get_alsi(Alsi alsi);

/** Getter for Alsi time stamp */
time_t * ftress_alsi_get_time_stamp(Alsi alsi);

/** Setter for Alsi */
const int ftress_alsi_set_alsi(Alsi alsi, char *ALSI);

/** Setter for Alsi time stamp*/
const int ftress_alsi_set_time_stamp(Alsi alsi, time_t *time);

/**Free the Alsi */
const int ftress_alsi_free(Alsi alsi);

/*************************************************************************************
*			 AuthenticationStatistics                                    *
*************************************************************************************/

/** Constructor for AuthenticationStatistics */
AuthenticationStatistics ftress_authentication_statistics_create();

/**Getter for authentication statistics challenge count. Return the challenge counter */
int * ftress_authentication_statistics_get_challenge_count(AuthenticationStatistics authenticationStatistics);

/** Getter for authentication statistics consecutive failed. Returns the count of consecutive, failed authentication attempts. */
int ftress_authentication_statistics_get_consecutive_failed(AuthenticationStatistics authenticationStatistics);

/** Getter for authentication statistics consecutive success. Returns the count of successful authentication attempts since the password was first set, reset or modified. */
int ftress_authentication_statistics_get_consecutive_success(AuthenticationStatistics authenticationStatistics);

/** Getter for authentication statistics last successful channel. Returns the channel (code) of the last successful authentication attempt. */
ChannelCode ftress_authentication_statistics_get_last_successful_channel(AuthenticationStatistics authenticationStatistics);

/** Getter for authentication statistics last successful date time. Returns the datetime of the last successful authentication attempt. */
time_t * ftress_authentication_statistics_get_last_successful_date_time(AuthenticationStatistics authenticationStatistics);

/** Getter for authentication statistics last unsuccessful channel. Returns the channel (code) of the last unsuccessful authentication attempt. */
ChannelCode ftress_authentication_statistics_get_last_unsuccessful_channel(AuthenticationStatistics authenticationStatistics);

/** Getter for authentication statistics last unsuccessful date time. Returns the datetime of the last unsuccessful authentication attempt. */
time_t * ftress_authentication_statistics_get_last_unsuccessful_date_time(AuthenticationStatistics authenticationStatistics);

/** Getter for authentication statistics total count of authentication attempts. Returns the total count of authentication attempts. */
int ftress_authentication_statistics_get_total(AuthenticationStatistics authenticationStatistics);

/** Getter for authentication statistics total count of failed authentications. */
int ftress_authentication_statistics_get_total_failed(AuthenticationStatistics authenticationStatistics);

/** Getter for authentication statistics total count of successful authentications. */
int ftress_authentication_statistics_get_total_successful(AuthenticationStatistics authenticationStatistics);


/** Setters for authentication statistics */

/** Setter for authentication statistics challenge count. Sets the challenge counter */
const int ftress_authentication_statistics_set_challenge_count(AuthenticationStatistics authenticationStatistics, int *challengeCount);

/** Setter for authentication statistics consecutive failed. Sets the count of consecutive, failed authentication attempts. */
const int ftress_authentication_statistics_set_consecutive_failed(AuthenticationStatistics authenticationStatistics, int consecutiveFailed);

/** Setter for authentication statistics consecutive success. Sets the count of successful authentication attempts since the password was first set, reset or modified. */
const int ftress_authentication_statistics_set_consecutive_success(AuthenticationStatistics authenticationStatistics, int consecutiveSuccess);

/** Setter for authentication statistics last successful channel. Sets the channel (code) of the last successful authentication attempt. */
const int ftress_authentication_statistics_set_last_successful_channel(AuthenticationStatistics authenticationStatistics, ChannelCode channelCode);

/** Setter for authentication statistics last successful date time. Sets the datetime of the last successful authentication attempt. */
const int ftress_authentication_statistics_set_last_successful_date_time(AuthenticationStatistics authenticationStatistics, time_t *lastSuccessfulDateTime);

/** Setter for authentication statistics last unsuccessful channel. Sets the channel (code) of the last unsuccessful authentication attempt. */
const int ftress_authentication_statistics_set_last_unsuccessful_channel(AuthenticationStatistics authenticationStatistics, ChannelCode channelCode);

/** Setter for authentication statistics last unsuccessful date time. Sets the datetime of the last unsuccessful authentication attempt. */
const int ftress_authentication_statistics_set_last_unsuccessful_date_time(AuthenticationStatistics authenticationStatistics, time_t *lastUnsuccessfulDateTime);

/** Setter for authentication statistics total count of authentication attempts. Sets the total count of authentication attempts. 
*/
const int ftress_authentication_statistics_set_total(AuthenticationStatistics authenticationStatistics, int total);

/** Setter for authentication statistics total count of failed authentications. Sets the total count of failed authentication attempts. */
const int ftress_authentication_statistics_set_total_failed(AuthenticationStatistics authenticationStatistics, int totalFailed);

/** Setter for authentication statistics total count of successful authentications. Sets the total count of successful authentications. */
const int ftress_authentication_statistics_set_total_successful(AuthenticationStatistics authenticationStatistics, int totalSuccessful);

/**Free the authentication statistics */
const int ftress_authentication_statistics_free(AuthenticationStatistics authenticationStatistics);

/*************************************************************************************
*			 ArrayOfMDPromptCode                                         *
*************************************************************************************/
/** Create array of MDPromptCode */
ArrayOfMDPromptCode ftress_arrayof_md_prompt_code_create(int size, MDPromptCode *mdPromptCode);

/** Getter for array size of MDPromptCode */
int ftress_arrayof_md_prompt_code_get_size(ArrayOfMDPromptCode arrayOfMDPromptCode);

/** Getter for array of MDPromptCode */
MDPromptCode * ftress_arrayof_md_prompt_code_get_prompts(ArrayOfMDPromptCode arrayOfMDPromptCode);

/** Setter for array size of MDPromptCode */
const int ftress_arrayof_md_prompt_code_set_size(ArrayOfMDPromptCode arrayOfMDPromptCode, int size);

/** Setter for array of MDPromptCode */
const int ftress_arrayof_md_prompt_code_set_prompts(ArrayOfMDPromptCode arrayOfMDPromptCode, MDPromptCode *mdPromptCode);

// Free
/** 
* Free the ArrayOfMDPromptCode
*/
const int ftress_arrayof_md_prompt_code_free(ArrayOfMDPromptCode arrayOfMDPromptCode);

/*************************************************************************************
*			 MDPromptCode                                                *
*************************************************************************************/
/** Constructor for MDPromptCode */
MDPromptCode ftress_md_prompt_code_create_default();

/** Parameterised constructor for MDPromptCode */
MDPromptCode ftress_md_prompt_code_create(char *code);

/** Getter for MDPromptCode. Returns the string representing the code.*/
char * ftress_md_prompt_code_get_code(MDPromptCode mdPromptCode);

/** Setter for MDPromptCode. Sets the string representing the code. */
const int ftress_md_prompt_code_set_code(MDPromptCode mdPromptCode, char *code);

/**Free the MDPromptCode */
const int ftress_md_prompt_code_free(MDPromptCode mdPromptCode);

/*************************************************************************************
*			 AuthenticationResponseParameter                             *
*************************************************************************************/
/** Constructor for AuthenticationResponseParameter */
AuthenticationResponseParameter ftress_authentication_response_parameter_create_default();

/** Parameterised constructor for AuthenticationResponseParameter */
AuthenticationResponseParameter ftress_authentication_response_parameter_create(char *name, char *value);

/** Getter for Authentication Response Parameter name */
char * ftress_authentication_response_parameter_get_name(AuthenticationResponseParameter authenticationResponseParameter);

/** Getter for Authentication Response Parameter value */
char * ftress_authentication_response_parameter_get_value(AuthenticationResponseParameter authenticationResponseParameter);

/** Setter for Authentication Response Parameter name */
const int ftress_authentication_response_parameter_set_name(AuthenticationResponseParameter authenticationResponseParameter, char *name);

/** Setter for Authentication Response Parameter value */
const int ftress_authentication_response_parameter_set_value(AuthenticationResponseParameter authenticationResponseParameter, char *value);
 
/**Free the Authentication Response Parameter */
const int ftress_authentication_response_parameter_free(AuthenticationResponseParameter authenticationResponseParameter);

/*************************************************************************************
*			 AuthenticationResponse                                      *
*************************************************************************************/

/** Constructor for Authentication Response */
AuthenticationResponse ftress_authentication_response_create();

/** Getter for authentication response ALSI */
Alsi ftress_authentication_response_get_alsi(AuthenticationResponse authenticationResponse);

/** Getter for authentication response expiryThreshold */
int ftress_authentication_response_get_expiry_threshold(AuthenticationResponse authenticationResponse);

/** Getter for authentication response message */
char * ftress_authentication_response_get_message(AuthenticationResponse authenticationResponse);

/** Getter for authentication response reason */
int ftress_authentication_response_get_reason(AuthenticationResponse authenticationResponse);

/** Getter for authentication response response */
int ftress_authentication_response_get_response(AuthenticationResponse authenticationResponse);

/** Getter for authentication response */
char * ftress_authentication_response_get_status(AuthenticationResponse authenticationResponse);

/** Getter for authentication response user code*/
UserCode ftress_authentication_response_get_user_code(AuthenticationResponse authenticationResponse);

/** Getter for authentication response authentication statistics */
AuthenticationStatistics ftress_authentication_response_get_authentication_statistics(AuthenticationResponse authenticationResponse);

/** Getter for authentication response array of MDPromptCode. Returns the failed MD prompts (MD authentication only). */
MDPromptCode * ftress_authentication_response_get_arrayof_md_prompt_code(AuthenticationResponse authenticationResponse);

/** Getter for authentication response array of AuthenticationResponseParameter. Returns the parameters */
AuthenticationResponseParameter * ftress_authentication_response_get_parameters(AuthenticationResponse authenticationResponse);

/** Setter for authentication response ALSI */
const int ftress_authentication_response_set_alsi(AuthenticationResponse authenticationResponse, Alsi alsi);

/** Setter for authentication response expiryThreshold */
const int ftress_authentication_response_set_expiry_threshold(AuthenticationResponse authenticationResponse, int expiryThreshold);

/** Setter for authentication response message */
const int ftress_authentication_response_set_message(AuthenticationResponse authenticationResponse, char *message);

/** Setter for authentication response reason */
const int ftress_authentication_response_set_reason(AuthenticationResponse authenticationResponse, int reason);

/** Setter for authentication response response */
const int ftress_authentication_response_set_response(AuthenticationResponse authenticationResponse, int response);

/** Setter for authentication response */
const int ftress_authentication_response_set_status(AuthenticationResponse authenticationResponse, char *status);

/** Setter for authentication response user code*/
const int ftress_authentication_response_set_user_code(AuthenticationResponse authenticationResponse, UserCode userCode);

/** Setter for authentication response authentication statistics */
const int ftress_authentication_response_set_authentication_statistics(AuthenticationResponse authenticationResponse, AuthenticationStatistics authenticationStatistics);

/** Setter for authentication response array of MDPromptCode. Returns the failed MD prompts (MD authentication only). */
const int ftress_authentication_response_set_array_of_md_prompt_code(AuthenticationResponse authenticationResponse, MDPromptCode *mdPromptCode);

/** Setter for authentication response array of AuthenticationResponseParameter. Returns the parameters */
const int ftress_authentication_response_set_parameters(AuthenticationResponse authenticationResponse, AuthenticationResponseParameter *authenticationResponseParameter);

/**Free the Authentication Response */
const int ftress_authentication_response_free(AuthenticationResponse authenticationResponse);

/************************************************************************************
*                       DateRangeSearchCriteria                                     *
************************************************************************************/

/** Constructs a new DateRangeSearchCriteria */
DateRangeSearchCriteria ftress_date_range_search_criteria_create();

// Getters

/**  gets the exact date in case there are no range of dates */
time_t * ftress_date_range_search_criteria_get_date_equals(DateRangeSearchCriteria dateRangeSearchCriteria);

/** gets the from date. */
time_t * ftress_date_range_search_criteria_get_date_from(DateRangeSearchCriteria dateRangeSearchCriteria);

/** gets the to date */
time_t * ftress_date_range_search_criteria_get_date_to(DateRangeSearchCriteria dateRangeSearchCriteria);

// Setters

/**  sets the exact date in case there are no range of dates */
const int ftress_date_range_search_criteria_set_date_equals(DateRangeSearchCriteria dateRangeSearchCriteria,
							    time_t *dateEquals);

/** sets the from date. */
const int ftress_date_range_search_criteria_set_date_from(DateRangeSearchCriteria dateRangeSearchCriteria,
							 time_t *dateFrom);

/** sets the to date */
const int ftress_date_range_search_criteria_set_date_to(DateRangeSearchCriteria dateRangeSearchCriteria,
						       time_t * dateTo);

// Free

/** Free the DateRangeSearchCriteria */
const int ftress_date_range_search_criteria_free(DateRangeSearchCriteria dateRangeSearchCriteria);

/************************************************************************************
*                       DeviceAuthenticationRequest                                 *
************************************************************************************/
/** Default Constructor for DeviceAuthenticationRequest */
DeviceAuthenticationRequest ftress_device_authentication_request_create_default();

/** Parameterised Constructor for DeviceAuthenticationRequest */

DeviceAuthenticationRequest ftress_device_authentication_request_create(ArrayOfAuthenticationRequestParameter auditedParameters,
									int authenticateNoSession,
									AuthenticationTypeCode authenticationTypeCode,
									ArrayOfAuthenticationRequestParameter parameters,
									int authenticationMode,
									char *challenge,
									DeviceSearchCriteria deviceCriteria,
									char *oneTimePassword,
									UserCode userCode);
/** Getters */

/** Returns the audited parameters. */
ArrayOfAuthenticationRequestParameter ftress_device_authentication_request_get_audited_parameters(DeviceAuthenticationRequest deviceAuthenticationRequest);

/** Returns the non-audited parameters. */
ArrayOfAuthenticationRequestParameter ftress_device_authentication_request_get_parameters(DeviceAuthenticationRequest deviceAuthenticationRequest);

/** Returns true/false based on authenticate session */
int ftress_device_authentication_request_get_authenticate_no_session(DeviceAuthenticationRequest deviceAuthenticationRequest);

/** Returns the authentication type (code) of the authentication. */
AuthenticationTypeCode ftress_device_authentication_request_get_authentication_type_code(DeviceAuthenticationRequest deviceAuthenticationRequest);

/** Returns the authentication mode of this request either SYNC/ASYNC */
int ftress_device_authentication_request_get_authentication_mode(DeviceAuthenticationRequest deviceAuthenticationRequest);

/** Returns the user defined challenge for this request */
char * ftress_device_authentication_request_get_challenge(DeviceAuthenticationRequest deviceAuthenticationRequest);

/** Returns the device search criteria for this request */
DeviceSearchCriteria ftress_device_authentication_request_get_device_criteria(DeviceAuthenticationRequest deviceAuthenticationRequest);

/** Returns the one time oneTimePassword for this authentication request */
char * ftress_device_authentication_request_get_one_time_password(DeviceAuthenticationRequest deviceAuthenticationRequest);

/** Returns the user code. */
UserCode ftress_device_authentication_request_get_user_code(DeviceAuthenticationRequest deviceAuthenticationRequest);

/** Setters */

/** Sets the audited parameters. */
const int ftress_device_authentication_request_set_audited_parameters(DeviceAuthenticationRequest deviceAuthenticationRequest, ArrayOfAuthenticationRequestParameter auditedParameters);

/** Sets the non-audited parameters. */
const int  ftress_device_authentication_request_set_parameters(DeviceAuthenticationRequest deviceAuthenticationRequest, ArrayOfAuthenticationRequestParameter parameter);

/** Sets true/false based on authenticate session */
const int ftress_device_authentication_request_set_authenticate_no_session(DeviceAuthenticationRequest deviceAuthenticationRequest, int authenticateNoSession);

/** Sets the authentication type (code) of the authentication. */
const int ftress_device_authentication_request_set_authentication_type_code(DeviceAuthenticationRequest deviceAuthenticationRequest, AuthenticationTypeCode authenticationTypeCode);

/** Sets the authentication mode of this request either SYNC/ASYNC */
const int ftress_device_authentication_request_set_authentication_mode(DeviceAuthenticationRequest deviceAuthenticationRequest, int authenticationMode);

/** Sets the user defined challenge for this request */
const int ftress_device_authentication_request_set_challenge(DeviceAuthenticationRequest deviceAuthenticationRequest, char *challenge);

/** Sets the device search criteria for this request */
const int ftress_device_authentication_request_set_device_criteria(DeviceAuthenticationRequest deviceAuthenticationRequest, DeviceSearchCriteria deviceSearchCriteria);

/** Sets the one time oneTimePassword for this authentication request */
const int ftress_device_authentication_request_set_one_time_password(DeviceAuthenticationRequest deviceAuthenticationRequest, char *oneTimePassword);

/** Sets the user code. */
const int ftress_device_authentication_request_set_user_code(DeviceAuthenticationRequest deviceAuthenticationRequest, UserCode userCode);

// Free

/** Ftree the DeviceAuthenticationRequest */
const int ftress_device_authentication_request_free(DeviceAuthenticationRequest deviceAuthenticationRequest);

/************************************************************************************
*                      SeedPositions                                                *
************************************************************************************/
/** Constructs a new SeedPositions. */
SeedPositions ftress_seed_positions_create_default();

/** Constructs a new SeedPositions with the specified positions. */
SeedPositions ftress_seed_positions_create(ArrayOfInt arrayOfInt);

// Getters

/** Returns the positions of character(s) in a password. */
ArrayOfInt ftress_seed_positions_get_positions(SeedPositions seedPositions);

// Setters

/** Sets the positions of character(s) in a password. */
const int ftress_seed_positions_set_positions(SeedPositions seedPositions, ArrayOfInt arrayOfInt);

// Free

/** Free the seed positions */
const int ftress_seed_positions_free(SeedPositions seedPositions);

/************************************************************************************
*                      MDAuthenticationRequest                                      *
************************************************************************************/
/** 
* Constructs a new MDAuthenticationRequest.
*/
MDAuthenticationRequest ftress_md_authentication_request_create_default();

/** 
* Constructs a new MDAuthenticationRequest.  
*/
MDAuthenticationRequest ftress_md_authentication_request_create(ArrayOfAuthenticationRequestParameter auditedParameters,
								int authenticateNoSession,
								AuthenticationTypeCode authenticationTypeCode,
								ArrayOfAuthenticationRequestParameter parameters,
								ArrayOfMDAuthenticationAnswer answers,
								UserCode userCode);

// Getters

/** 
* Returns the audited parameters.
*/
ArrayOfAuthenticationRequestParameter ftress_md_authentication_request_get_audited_parameters(MDAuthenticationRequest mdAuthenticationRequest);

/** 
* Returns true/false based on authenticate session
*/
int ftress_md_authentication_request_get_authenticate_no_session(MDAuthenticationRequest mdAuthenticationRequest); 

/** 
* Returns the authentication type (code) of the authentication.
*/
AuthenticationTypeCode ftress_md_authentication_request_get_authentication_type_code(MDAuthenticationRequest mdAuthenticationRequest);

/** 
* Returns the non-audited parameters.
*/
ArrayOfAuthenticationRequestParameter ftress_md_authentication_request_get_parameters(MDAuthenticationRequest mdAuthenticationRequest);

/** 
* Returns the answers provided to authenticate the user.
*/
ArrayOfMDAuthenticationAnswer ftress_md_authentication_request_get_answers(MDAuthenticationRequest mdAuthenticationRequest);

/** 
* Returns the unique user code (external reference).
*/
UserCode ftress_md_authentication_request_get_user_code(MDAuthenticationRequest mdAuthenticationRequest);

// Setters

/** 
* Sets the audited parameters.
*/
const int ftress_md_authentication_request_set_audited_parameters(MDAuthenticationRequest mdAuthenticationRequest,
					                	  ArrayOfAuthenticationRequestParameter auditedParameters);

/** 
* Sets true/false based on authenticate session
*/
const int ftress_md_authentication_request_set_authenticate_no_session(MDAuthenticationRequest mdAuthenticationRequest,
								       int authenticateNoSession); 

/** 
* Sets the authentication type (code) of the authentication.
*/
const int ftress_md_authentication_request_set_authentication_type_code(MDAuthenticationRequest mdAuthenticationRequest,
									AuthenticationTypeCode authenticationTypeCode);

/** 
* Sets the non-audited parameters.
*/
const int ftress_md_authentication_request_set_parameters(MDAuthenticationRequest mdAuthenticationRequest,
							  ArrayOfAuthenticationRequestParameter parameters);

/** 
* Sets the answers provided to authenticate the user.
*/
const int ftress_md_authentication_request_set_answers(MDAuthenticationRequest mdAuthenticationRequest,									          ArrayOfMDAuthenticationAnswer arrayOfMDAuthenticationAnswer);

/** 
* Sets the unique user code (external reference).
*/
const int ftress_md_authentication_request_set_user_code(MDAuthenticationRequest mdAuthenticationRequest,
							 UserCode userCode);

// Free

/** 
* Free the MDAuthenticationRequest
*/
const int ftress_md_authentication_request_free(MDAuthenticationRequest mdAuthenticationRequest);


/************************************************************************************
*                      ArrayOfMDAuthenticationAnswer                                *
************************************************************************************/
/** 
* Constructs a new ArrayOfMDAuthenticationAnswer
*/
ArrayOfMDAuthenticationAnswer ftress_arrayof_md_authentication_answer_create(int size, MDAuthenticationAnswer *mdAuthenticationAnswer);

// Getters

/** 
* Returns size of ArrayOfMDAuthenticationAnswer
*/
int ftress_arrayof_md_authentication_answer_get_size(ArrayOfMDAuthenticationAnswer arrayOfMDAuthenticationAnswer);

/** 
* Returns array of MDAuthenticationAnswer.
*/
MDAuthenticationAnswer * ftress_arrayof_md_authentication_answer_get_md_authentication_answer(ArrayOfMDAuthenticationAnswer arrayOfMDAuthenticationAnswer);

// Setters

/** 
* Sets size of ArrayOfMDAuthenticationAnswer
*/
const int ftress_arrayof_md_authentication_answer_set_size(ArrayOfMDAuthenticationAnswer arrayOfMDAuthenticationAnswer,
						     int size);

/** 
* Sets array of MDAuthenticationAnswer.
*/
const int ftress_arrayof_md_authentication_answer_set_md_authentication_answer(ArrayOfMDAuthenticationAnswer arrayOfMDAuthenticationAnswer, 
									       MDAuthenticationAnswer *mdAuthenticationAnswer);

// Free

/** 
* Free the ArrayOfMDAuthenticationAnswer
*/
const int ftress_arrayof_md_authentication_answer_free(ArrayOfMDAuthenticationAnswer arrayOfMDAuthenticationAnswer);

/************************************************************************************
*                      MDAuthenticationAnswer                                       *
************************************************************************************/
/** 
* Constructs a new MDAuthenticationAnswer.
*/
MDAuthenticationAnswer ftress_md_authentication_answer_create_default();

/** 
* Constructs a new MDAuthenticationAnswer with specified answer and prompt code.
*/
MDAuthenticationAnswer ftress_md_authentication_answer_create(char *answer,
							      MDPromptCode mdPromptCode);

/** 
* Constructs a new MDAuthenticationAnswer with specified answer, prompt code and seed positions.
*/
MDAuthenticationAnswer ftress_md_authentication_answer_create_for_seeded_auth(char *answer,
                                                               		      MDPromptCode mdPromptCode,
							      		      ArrayOfInt arrayOfInt);

// Getters

/** 
* Returns the answer.
*/
char * ftress_md_authentication_answer_get_answer(MDAuthenticationAnswer mdAuthenticationAnswer);

/** 
* Returns the memorable data prompt (code). 
*/
MDPromptCode ftress_md_authentication_answer_get_md_prompt_code(MDAuthenticationAnswer mdAuthenticationAnswer);

/** 
* Returns the seed positions (positions i.e. indexes, of characters in the answer) (optional).
*/
ArrayOfInt ftress_md_authentication_answer_get_seed_positions(MDAuthenticationAnswer mdAuthenticationAnswer);

/** 
* Sets the answer.
*/
const int ftress_md_authentication_answer_set_answer(MDAuthenticationAnswer mdAuthenticationAnswer,	
						     char *answer);

/** 
* Sets the memorable data prompt (code). 
*/
const int ftress_md_authentication_answer_set_md_prompt_code(MDAuthenticationAnswer mdAuthenticationAnswer,
								MDPromptCode mdPromptCode);

/** 
* Sets the seed positions (positions i.e. indexes, of characters in the answer) (optional).
*/
const int ftress_md_authentication_answer_set_seed_positions(MDAuthenticationAnswer mdAuthenticationAnswer,
	  					             ArrayOfInt arrayOfInt);

// Free

/** 
* Free the MDAuthenticationAnswer
*/
const int ftress_md_authentication_answer_free(MDAuthenticationAnswer mdAuthenticationAnswer);

/************************************************************************************
*                      MDPromptCode                                                 *
************************************************************************************/
/** 
* Constructs a new MDPromptCode.
*/
MDPromptCode ftress_md_prompt_code_create_default();

/** 
* Constructs a new MDPromptCode with the specified code.
*/
MDPromptCode ftress_md_prompt_code_create(char *code);

//Getters

/** 
* Returns the string representing the code.
*/
char * ftress_md_prompt_code_get_code(MDPromptCode mdPromptCode);

// Setters

/** 
* Sets the string representing the code.
*/
const int ftress_md_prompt_code_set_code(MDPromptCode mdPromptCode, char *code);

// Free

/** 
* Free the MDPromptCode.
*/
const int ftress_md_prompt_code_free(MDPromptCode mdPromptCode);

/************************************************************************************
*                      MDAuthenticationPrompts                                      *
************************************************************************************/
/** 
* Constructs a new MDAuthenticationPrompts.
*/
MDAuthenticationPrompts ftress_md_authentication_prompts_create();

// Getters

/** 
* Returns the number of MD answers that are required to authenticate.
*/
int ftress_md_authentication_prompts_get_answers_required(MDAuthenticationPrompts mdAuthenticationPrompts);

/** 
* Returns the available MD prompts to which answers can be provided.
*/
ArrayOfMDAuthenticationPrompt ftress_md_authentication_prompts_get_prompts(MDAuthenticationPrompts mdAuthenticationPrompts);

// Setters

/** 
* Sets the number of MD answers that are required to authenticate.
*/
const int ftress_md_authentication_prompts_set_answers_required(MDAuthenticationPrompts mdAuthenticationPrompts, 
								int answersRequired);

/** 
* Sets the available MD prompts to which answers can be provided.
*/
const int ftress_md_authentication_prompts_set_prompts(MDAuthenticationPrompts mdAuthenticationPrompts,
						       ArrayOfMDAuthenticationPrompt prompts);

// Free

/** 
* Free the MDAuthenticationPrompts
*/
const int ftress_md_authentication_prompts_free(MDAuthenticationPrompts mdAuthenticationPrompts);

/************************************************************************************
*                      ArrayOfMDAuthenticationPrompt                                *
************************************************************************************/
/** 
* Constructs a new ArrayOfMDAuthenticationPrompt
*/
ArrayOfMDAuthenticationPrompt ftress_arrayof_md_authentication_prompt_create(int size, 
									     MDAuthenticationPrompt *mdAuthenticationPrompt);

// Getters

/** 
* Returns the size of ArrayOfMDAuthenticationPrompt
*/
int ftress_arrayof_md_authentication_prompt_get_size(ArrayOfMDAuthenticationPrompt prompts);

/** 
* Returns the array of MDAuthenticationPrompt 
*/
MDAuthenticationPrompt * ftress_arrayof_md_authentication_prompt_get_prompts(ArrayOfMDAuthenticationPrompt prompts);

// Setters

/** 
* Sets the size of ArrayOfMDAuthenticationPrompt
*/
const int ftress_arrayof_md_authentication_prompt_set_size(ArrayOfMDAuthenticationPrompt prompts,
							   int size);

/** 
* Sets the array of MDAuthenticationPrompt
*/
const int ftress_arrayof_md_authentication_prompt_set_prompts(ArrayOfMDAuthenticationPrompt prompts,
							      MDAuthenticationPrompt *mdAuthenticationPrompt);

// Fress

/** 
* Free the ArrayOfMDAuthenticationPrompt
*/
const int ftress_arrayof_md_authentication_prompt_free(ArrayOfMDAuthenticationPrompt prompts);

/************************************************************************************
*                      MDAuthenticationPrompt                                       *
************************************************************************************/

/** 
* Constructs a new MDAuthenticationPrompt.
*/
MDAuthenticationPrompt ftress_md_authentication_prompt_create_default();

/** 
* Constructs a new MDAuthenticationPrompt.
*/
MDAuthenticationPrompt ftress_md_authentication_prompt_create(char *name,
							      char *prompt,
							      MDPromptCode promptCode,
							      ArrayOfInt seedPositions);

// Getters

/** 
* Returns the descriptive name.
*/
char * ftress_md_authentication_prompt_get_name(MDAuthenticationPrompt mdAuthenticationPrompt);

/** 
*    Returns the prompt (question) to be presented to a user.
*/
char * ftress_md_authentication_prompt_get_prompt(MDAuthenticationPrompt mdAuthenticationPrompt);

/** 
* Returns the md prompt code.
*/
MDPromptCode ftress_md_authentication_prompt_get_md_prompt_code(MDAuthenticationPrompt mdAuthenticationPrompt);

/** 
* Returns suitable seed positions for the MD answer.
*/
ArrayOfInt ftress_md_authentication_prompt_get_seed_positions(MDAuthenticationPrompt mdAuthenticationPrompt);

// Setters

/** 
* Sets the descriptive name.
*/
const int ftress_md_authentication_prompt_set_name(MDAuthenticationPrompt mdAuthenticationPrompt, 
						   char *name);

/** 
*    Sets the prompt (question) to be presented to a user.
*/
const int ftress_md_authentication_prompt_set_prompt(MDAuthenticationPrompt mdAuthenticationPrompt, 
						     char *prompt);

/** 
* Sets the md prompt code.
*/
const int ftress_md_authentication_prompt_set_md_prompt_code(MDAuthenticationPrompt mdAuthenticationPrompt, 
								MDPromptCode mdPromptCode);

/** 
* Sets suitable seed positions for the MD answer.
*/
const int ftress_md_authentication_prompt_set_seed_positions(MDAuthenticationPrompt mdAuthenticationPrompt,
							      ArrayOfInt seedPositions);

//Free 

/** 
* Free the MDAuthenticationPrompt
*/
const int ftress_md_authentication_prompt_free(MDAuthenticationPrompt mdAuthenticationPrompt);

/************************************************************************************
*                       End of ftres DTOs                                           *
************************************************************************************/

/************************************************************************************
*                       Ftress Devices                                              *
************************************************************************************/

/************************************************************************************
*                       DeviceGroupCode                                             *
************************************************************************************/
/** Constructs a new DeviceGroupCode. */
DeviceGroupCode ftress_device_group_code_create_default();

/** Constructs a new DeviceGroupCode. */
DeviceGroupCode ftress_device_group_code_create(char *code);

// Getters 

/** Returns the string representing the code.*/
char * ftress_device_group_code_get_code(DeviceGroupCode deviceGroupCode);

// Setters

/** Sets the string representing the code. */
const int ftress_device_group_code_set_code(DeviceGroupCode deviceGroupCode, 
					    char *code);

// Free

/** Free the DeviceGroupCode */
const int ftress_device_group_code_free(DeviceGroupCode deviceGroupCode);

/************************************************************************************
*                       ArrayOfDeviceGroupCode                                      *
************************************************************************************/
/** Constructs a new ArrayOfDeviceGroupCode */
ArrayOfDeviceGroupCode ftress_arrayof_device_group_code_create(int size, 
							DeviceGroupCode *deviceGroupCode);

// Getters

/** Returns the size of ArrayOfDeviceGroupCode */
int ftress_arrayof_device_group_code_get_size(ArrayOfDeviceGroupCode deviceGroupCodes);

/** Returns the array of deviceGroupCode */
DeviceGroupCode * ftress_arrayof_device_group_code_get_device_group_code(ArrayOfDeviceGroupCode deviceGroupCodes);

// Setters

/** Sets the size of ArrayOfDeviceGroupCode */
const int ftress_arrayof_device_group_code_set_size(ArrayOfDeviceGroupCode deviceGroupCodes, 
						    int size);

/** Sets the array of deviceGroupCode */
const int ftress_arrayof_device_group_code_set_device_group_code(ArrayOfDeviceGroupCode deviceGroupCodes,
								 DeviceGroupCode *deviceGroupCode);

// Free

/** Free the ArrayOfDeviceGroupCode */
const int ftress_arrayof_device_group_code_free(ArrayOfDeviceGroupCode deviceGroupCodes);


/************************************************************************************
*                       DeviceId                                                    *
************************************************************************************/

/**  Allocates a new DeviceId. */
DeviceId ftress_device_id_create_default();

/** Allocates a new DeviceId passing a long. */
DeviceId ftress_device_id_create(long id);

//Getters

/** Returns the device id. */
int ftress_device_id_get_id(DeviceId deviceId);

// Setters

/** Sets the device id. */
const int ftress_device_id_set_id(DeviceId deviceId, 
				  long id);

// Free

/** Free the DeviceId */
const int ftress_device_id_free(DeviceId deviceId);


/************************************************************************************
*                       DeviceTypeCode                                              *
************************************************************************************/
/** Constructs a new DeviceTypeCode. */
DeviceTypeCode ftress_device_type_code_create_default();

/** Constructs a new DeviceTypeCode from the specified code. */
DeviceTypeCode ftress_device_type_code_create(char *code);

// Getters

/** Returns the string representing the code. */
char * ftress_device_type_code_get_code(DeviceTypeCode deviceTypeCode);

// Setters

/** Sets the string representing the code. */
const int ftress_device_type_code_set_code(DeviceTypeCode deviceTypeCode, char *code);

// Free

/** Free the DeviceTypeCode */
const int ftress_device_type_code_free(DeviceTypeCode deviceTypeCode);




/************************************************************************************
*                       DeviceSearchCriteria                                        *
************************************************************************************/

/** Default Constructor for DeviceSearchCriteria. Allocates a new DeviceSearchCriteria. */
DeviceSearchCriteria ftress_device_search_criteria_create_default();

/** Parameterised Constructor for DeviceSearchCriteria. Allocates a new DeviceSearchCriteria. */
DeviceSearchCriteria ftress_device_search_criteria_create(int searchLimit,
							  int assignedToUser,
							  ArrayOfDeviceGroupCode deviceGroupCodes,
							  DeviceId deviceId,
							  DeviceTypeCode deviceTypeCode,
							  time_t *expiryDate, 
							  DateRangeSearchCriteria expiryDateCriteria,
							  int issueNumber,
							  char *serialNumber,
							  time_t *startDate,
							  UserCode userCode);
/** Getters */

/** Returns the maximum number of records to return */
int ftress_device_search_criteria_get_search_limit(DeviceSearchCriteria deviceSearchCriteria);

/** Getter for DeviceSearchCriteria's assignedToUser */
int ftress_device_search_criteria_get_assigned_to_user(DeviceSearchCriteria deviceSearchCriteria);

/** Returns the array of deviceGroupCodes */
ArrayOfDeviceGroupCode ftress_device_search_criteria_get_device_group_codes(DeviceSearchCriteria deviceSearchCriteria);

/** Returns the device id criteria. */
DeviceId ftress_device_search_criteria_get_device_id(DeviceSearchCriteria deviceSearchCriteria);

/** Returns the device type code criteria. */
DeviceTypeCode ftress_device_search_criteria_get_device_type_code(DeviceSearchCriteria deviceSearchCriteria);

/** Returns the device expiry date criteria. */
time_t * ftress_device_search_criteria_get_expiry_date(DeviceSearchCriteria deviceSearchCriteria);

/** Returns the expiry date criteria */
DateRangeSearchCriteria ftress_device_search_criteria_get_expiry_date_criteria(DeviceSearchCriteria deviceSearchCriteria);

/** Returns the issue number criteria. */
int ftress_device_search_criteria_get_issue_number(DeviceSearchCriteria deviceSearchCriteria);

/** Returns the serial number criteria. */
char * ftress_device_search_criteria_get_serial_number(DeviceSearchCriteria deviceSearchCriteria);

/** Returns the start date. */
time_t * ftress_device_search_criteria_get_start_date(DeviceSearchCriteria deviceSearchCriteria);

/** Returns the User Code */
UserCode ftress_device_search_criteria_get_user_code(DeviceSearchCriteria deviceSearchCriteria);


/** Setters */

/** Sets the maximum number of records to return */
const int ftress_device_search_criteria_set_search_limit(DeviceSearchCriteria deviceSearchCriteria, 
							 int searchLimit);

/** Getter for DeviceSearchCriteria's assignedToUser */
const int ftress_device_search_criteria_set_assigned_to_user(DeviceSearchCriteria deviceSearchCriteria, 
							     int assignedToUser);

/** Sets the array of deviceGroupCodes */
const int ftress_device_search_criteria_set_device_group_codes(DeviceSearchCriteria deviceSearchCriteria, 
									     ArrayOfDeviceGroupCode deviceGroupCodes);

/** Sets the device id criteria. */
const int ftress_device_search_criteria_set_device_id(DeviceSearchCriteria deviceSearchCriteria, 
						     DeviceId deviceId);

/** Sets the device type code criteria. */
const int ftress_device_search_criteria_set_device_type_code(DeviceSearchCriteria deviceSearchCriteria, 
                    		            		     DeviceTypeCode deviceTypeCode);

/** Sets the device expiry date criteria. */
const int ftress_device_search_criteria_set_expiry_date(DeviceSearchCriteria deviceSearchCriteria,
						       time_t *expiryDate);
/** Sets the expiry date criteria */
const int ftress_device_search_criteria_set_expiry_date_criteria(DeviceSearchCriteria deviceSearchCriteria, 
								 DateRangeSearchCriteria dateRangeSearchCriteria);

/** Sets the issue number criteria. */
const int ftress_device_search_criteria_set_issue_number(DeviceSearchCriteria deviceSearchCriteria,
							 int issueNumber);

/** Sets the serial number criteria. */
const int ftress_device_search_criteria_set_serial_number(DeviceSearchCriteria deviceSearchCriteria,
							     char *serialNumber);

/** Sets the start date. */
const int ftress_device_search_criteria_set_start_date(DeviceSearchCriteria deviceSearchCriteria, time_t *startDate);

/** Sets the User Code */
const int ftress_device_search_criteria_set_user_code(DeviceSearchCriteria deviceSearchCriteria, 
						      UserCode userCode);
// Free

/** Free the DeviceSearchCriteria */
const int ftress_device_search_criteria_free(DeviceSearchCriteria deviceSearchCriteria);

/************************************************************************************
*                      AuthenticationChallenge                                      *
************************************************************************************/

/** Constructs a new AuthenticationChallenge */
AuthenticationChallenge ftress_authentication_challenge_create();

// Getters

/** Returns the challenge. */
char * ftress_authentication_challenge_get_challenge(AuthenticationChallenge authenticationChallenge);

/** gets challenge request error message */
char * ftress_authentication_challenge_get_challenge_request_error_message(AuthenticationChallenge authenticationChallenge);

/**  Returns the reason for this authentication challenge response (outcome). */
int ftress_authentication_challenge_get_challenge_request_reason(AuthenticationChallenge authenticationChallenge);

/**  gets challenge request status */
int ftress_authentication_challenge_get_challenge_request_status(AuthenticationChallenge authenticationChallenge);

// Setters

/** Sets the challenge. */
const int ftress_authentication_challenge_set_challenge(AuthenticationChallenge authenticationChallengei, char *challenge);

/** sets challenge request error message */
const int ftress_authentication_challenge_set_challenge_request_error_message(AuthenticationChallenge authenticationChallenge, char *challengeRequestErrorMessage);

/**  Sets the reason for this authentication challenge response (outcome). */
const int ftress_authentication_challenge_set_challenge_request_reason(AuthenticationChallenge authenticationChallenge, int challengeRequestReason);

/**  sets challenge request status */
const int ftress_authentication_challenge_set_challenge_request_status(AuthenticationChallenge authenticationChallenge, int challengeRequestStatus);

// Free

/** 
* Free the AuthenticationChallenge
*/
const int ftress_authentication_challenge_free(AuthenticationChallenge authenticationChallenge);

/************************************************************************************
*                      DeviceSearchResults                                          *
************************************************************************************/
/** 
* Constructs a new DeviceSearchResults.
*/
DeviceSearchResults ftress_device_search_results_create();

// Getters

/** 
* Returns the number of items found by a search.
*/
int ftress_device_search_results_get_matched_criteria(DeviceSearchResults deviceSearchResults);

/** 
* Returns the devices that were found.
*/
ArrayOfDevices ftress_device_search_results_get_devices(DeviceSearchResults deviceSearchResults);

// Setters

/** 
* Sets the number of items found by a search.
*/
const int ftress_device_search_results_set_matched_criteria(DeviceSearchResults deviceSearchResults, int numberItems);

/** 
* Sets the devices that were found.
*/
const int ftress_device_search_results_set_devices(DeviceSearchResults deviceSearchResults, ArrayOfDevices arrayOfDevices);

// Free

/** 
* Free the DeviceSearchResults
*/
const int ftress_device_search_results_free(DeviceSearchResults deviceSearchResults);


/************************************************************************************
*                      ArrayOfDevices                                               *
************************************************************************************/
/** 
* Constructs new ArrayOfDevices
*/
ArrayOfDevices ftress_arrayof_devices_create(int size, Device *device);

// Getters

/** 
* Returns the size of ArrayOfDevices 
*/
int ftress_arrayof_devices_get_size(ArrayOfDevices arrayOfDevices);

/** 
* Returns the array of devices
*/
Device * ftress_arrayof_devices_get_devices(ArrayOfDevices arrayOfDevices);

// Setters

/** 
* Sets the size of ArrayOfDevices
*/
const int ftress_arrayof_devices_set_size(ArrayOfDevices arrayOfDevices, int size);

/** 
* Sets the array of devices
*/
const int ftress_arrayof_devices_set_devices(ArrayOfDevices arrayOfDevices, Device *device);

// Free

/** 
* Free the ArrayOfDevices
*/
const int ftress_arrayof_devices_free(ArrayOfDevices arrayOfDevices);

/************************************************************************************
*                      Device                                                       *
************************************************************************************/

/** 
* Allocates a new device 
*/
Device ftress_device_create_default();

/** 
* Allocates a new device
*/
Device ftress_device_create(SDB sdb, 
			    char *SDBKey, 
			    time_t *addedDate, 
			    ArrayOfDeviceCredentialInfo arrayOfDeviceCredentialInfo,
			    DeviceGroupCode deviceGroupCode,
			    DeviceId deviceId,
			    DeviceTypeCode deviceTypeCode,
			    time_t *expiryDate,
			    int issueNumber,
			    int neverExpires,
			    char *serialNumber,
			    time_t *startDate,
			    DeviceStatus status,
			    UserCode userCode);

// Getters

/** 
* Returns the Secure Data Block (SDB) or token secret. 
*/
SDB ftress_device_get_sdb(Device device);

/** 
* Returns the key (hex encoded) with which the SDB was encrypted.
*/
char * ftress_device_get_sdb_key(Device device);

/** 
* Returns a list of data items describing credentials associated with this device.
*/
ArrayOfDeviceCredentialInfo ftress_device_get_arrayof_device_credential_info(Device device);

/** 
* Returns a device group code
*/
DeviceGroupCode ftress_device_get_device_group_code(Device device);

/** 
* Returns the unique system generated identifier.
*/
DeviceId ftress_device_get_device_id(Device device);

/** 
* Returns the device type (code).
*/
DeviceTypeCode ftress_device_get_device_type_code(Device device);

/** 
* Returns the expiry date. 
*/
time_t * ftress_device_get_expiry_date(Device device);

/** 
* Returns the issue number.
*/
int ftress_device_get_issue_number(Device device);

/** 
* Returns the never expires flag.
*/
int ftress_device_get_never_expires(Device device);

/** 
*  Returns the serial number.
*/
char * ftress_device_get_serial_number(Device device);

/** 
* Returns the start date 
*/
time_t * ftress_device_get_start_date(Device device);

/** 
* Returns the Device status
*/
DeviceStatus ftress_device_get_device_status(Device device);

/** 
* Returns the code identifying the user who has been issued with the device.
*/
UserCode ftress_device_get_user_code(Device device);

// Setters

/** 
* Sets the Secure Data Block (SDB) or token secret. 
*/
const int ftress_device_set_sdb(Device device, SDB sdb);

/** 
* Sets the key (hex encoded) with which the SDB was encrypted.
*/
const int ftress_device_set_sdb_key(Device device, char *SDBKey);

/** 
* Sets a list of data items describing credentials associated with this device.
*/
const int ftress_device_set_arrayof_device_credential_info(Device device, ArrayOfDeviceCredentialInfo arrayOfDeviceCredentialInfo);

/** 
* Sets a device group code
*/
const int ftress_device_set_device_group_code(Device device, DeviceGroupCode deviceGroupCode);

/** 
* Sets the unique system generated identifier.
*/
const int ftress_device_set_device_id(Device device, DeviceId deviceId);

/** 
* Sets the device type (code).
*/
const int ftress_device_set_device_type_code(Device device, DeviceTypeCode deviceTypeCode);

/** 
* Sets the expiry date. 
*/
const int ftress_device_set_expiry_date(Device device, time_t *expiryDate);

/** 
* Sets the issue number.
*/
const int ftress_device_set_issue_number(Device device, int issueNumber);

/** 
* Sets the never expires flag.
*/
const int ftress_device_set_never_expires(Device device, int neverExpires);

/** 
*  Sets the serial number.
*/
const int ftress_device_set_serial_number(Device device, char *serialNumber);

/** 
* Sets the start date 
*/
const int ftress_device_set_start_date(Device device, time_t *startDate);

/** 
* Sets the Device status
*/
const int ftress_device_set_device_status(Device device, DeviceStatus deviceStatus);

/** 
* Sets the code identifying the user who has been issued with the device.
*/
const int ftress_device_set_user_code(Device device, UserCode userCode);

// Free

/** 
* Free the Device
*/
const int ftress_device_free(Device device);

/************************************************************************************
*                      SDB                                                          *
************************************************************************************/
/** 
* Constructs new SDB
*/
SDB ftress_sdb_create_default();

/** 
* Constructs new SDB 
*/
SDB ftress_sdb_create(unsigned char *__ptr, int __size);

// Getters

/** 
*  Returns the Secure Data Block (SDB) or token secret. 
*/
unsigned char * ftress_sdb_get_data_block(SDB sdb);

/** 
* Returns the size of data block array
*/
int ftress_sdb_get_size(SDB sdb);

// Setters

/** 
* Sets the Secure Data Block (SDB) or token secret.
*/
const int ftress_sdb_set_data_block(SDB sdb, unsigned char *dataBlock);

/** 
* Sets the size of data block array 
*/
const int ftress_sdb_set_size(SDB sdb, int size);

// Free

/** 
* Free the SDB
*/
const int ftress_sdb_free(SDB sdb);

/************************************************************************************
*                                 DeviceStatus                                      *
************************************************************************************/
/** 
* Constructs a new DeviceStatus. 
*/
DeviceStatus ftress_device_status_create_default();

/** 
* Constructs a new DeviceStatus with the specified status
*/
DeviceStatus ftress_device_status_create(char *status);

// Getters

/** 
* Returns the status.
*/
char * ftress_device_status_get_status(DeviceStatus deviceStatus);

// Setters

/** 
* Sets the status
*/
const int ftress_device_status_set_status(DeviceStatus deviceStatus, char *status);

// Free

/** 
* Free the DeviceStatus
*/
const int ftress_device_status_free(DeviceStatus deviceStatus);

/************************************************************************************
*                      ArrayOfDeviceCredentialInfo                                  *
************************************************************************************/
/** 
* Constructs the new ArrayOfDeviceCredentialInfo 
*/
ArrayOfDeviceCredentialInfo ftress_arrayof_device_credential_info_create(int size, DeviceCredentialInfo *deviceCredentialInfo);

// Getters

/** 
* Returns the size of ArrayOfDeviceCredentialInfo 
*/
int ftress_arrayof_device_credential_info_get_size(ArrayOfDeviceCredentialInfo arrayOfDeviceCredentialInfo);

/** 
* Returns the array of DeviceCredentialInfo
*/
DeviceCredentialInfo * ftress_arrayof_device_credential_info_get_device_credential_info(ArrayOfDeviceCredentialInfo arrayOfDeviceCredentialInfo);

// Setters

/** 
* Sets the size of ArrayOfDeviceCredentialInfo  
*/
const int ftress_arrayof_device_credential_info_set_size(ArrayOfDeviceCredentialInfo arrayOfDeviceCredentialInfo, int size);

/** 
* Sets the array of DeviceCredentialInfo 
*/
const int ftress_arrayof_device_credential_info_set_device_credential_info(ArrayOfDeviceCredentialInfo arrayOfDeviceCredentialInfo, DeviceCredentialInfo *deviceCredentialInfo);

// Free

/** 
* Free the ArrayOfDeviceCredentialInfo
*/
const int ftress_arrayof_device_credential_info_free(ArrayOfDeviceCredentialInfo arrayOfDeviceCredentialInfo);

/************************************************************************************
*                      DeviceCredentialInfo                                         *
************************************************************************************/
/** 
* Constructs the new DeviceCredentialInfo 
*/
DeviceCredentialInfo ftress_device_credential_info_create_default();

/** 
* Constructs the new DeviceCredentialInfo
*/
DeviceCredentialInfo ftress_device_credential_info_create(CredentialId credentialId,
							  char *credentialKey,
							  CredentialTypeCode credentialTypeCode,
							  int slotId);

// Getters

/** 
* Returns the Credential Id
*/
CredentialId ftress_device_credential_info_get_credential_id(DeviceCredentialInfo deviceCredentialInfo);

/** 
* Returns the credentialKey
*/
char * ftress_device_credential_info_get_credential_key(DeviceCredentialInfo deviceCredentialInfo);

/** 
* Returns the CredentialTypeCode
*/
CredentialTypeCode ftress_device_credential_info_get_credential_type_code(DeviceCredentialInfo deviceCredentialInfo);

/** 
* Returns the slot id
*/
int ftress_device_credential_info_get_slot_id(DeviceCredentialInfo deviceCredentialInfo);

// Setters

/** 
* Sets the Credential Id
*/
const int ftress_device_credential_info_set_credential_id(DeviceCredentialInfo deviceCredentialInfo, CredentialId credentialId);

/** 
* Sets the credentialKey
*/
const int ftress_device_credential_info_set_credential_key(DeviceCredentialInfo deviceCredentialInfo, char *credentialKey);

/** 
* Sets the CredentialTypeCode
*/
const int ftress_device_credential_info_set_credential_type_code(DeviceCredentialInfo deviceCredentialInfo, CredentialTypeCode credentialTypeCode);

/** 
* Sets the slot id
*/
const int ftress_device_credential_info_set_slot_id(DeviceCredentialInfo deviceCredentialInfo, int slotId);

// Free

/** 
* Free the DeviceCredentialInfo
*/
const int ftress_device_credential_info_free(DeviceCredentialInfo deviceCredentialInfo);

/************************************************************************************
*                      End Ftress Devices                                           *
************************************************************************************/
/************************************************************************************
*                      Ftress Credentials                                           *
************************************************************************************/

/************************************************************************************
*                      CredentialId                                                 *
************************************************************************************/
/** 
* Allocates a new CredentialId. 
*/
CredentialId ftress_credential_id_create_default();

/** 
* Allocates a new CredentialId passing a long.
*/
CredentialId ftress_credential_id_create(long id);

// Getters

/** 
* Returns the credential id.
*/
long ftress_credential_id_get_id(CredentialId credentialId);

// Setters

/** 
* Sets the credential id.
*/
const int ftress_credential_id_set_id(CredentialId credentialId, long id);

// Free

/** 
* Free the CredentialId
*/
const int ftress_credential_id_free(CredentialId credentialId);

/************************************************************************************
*                      CredentialTypeCode                                           *
************************************************************************************/

/** 
*  Constructs a new CredentialTypeCode.
*/
CredentialTypeCode ftress_credential_type_code_create_default();

/** 
* Constructs a new CredentialTypeCode from the specified code.
*/
CredentialTypeCode ftress_credential_type_code_create(char *code);

// Getters

/** 
* Returns the string representing the code.
*/
char * ftress_credential_type_code_get_code(CredentialTypeCode credentialTypeCode);

// Setters

/** 
* Sets the string representing the code.
*/
const int ftress_credential_type_code_set_code(CredentialTypeCode credentialTypeCode, char *code);

// Free

/** 
* Free the CredentialTypeCode
*/
const int ftress_credential_type_code_free(CredentialTypeCode credentialTypeCode);


/************************************************************************************
*                     End Ftress Credentials                                        *
************************************************************************************/
/*************************************************************************************
*			 Responses                                                   *
*************************************************************************************/
/*************************************************************************************
*			 IndirectPrimaryAuthenticateUPResponse                       *
*************************************************************************************/

/** Constructs a new IndirectPrimaryAuthenticateUPResponse */
IndirectPrimaryAuthenticateUPResponse ftress_indirect_primary_authenticate_up_response_create();

// Getters

/** Getter for PrimaryAuthenticateUP authentication response */
AuthenticationResponse ftress_indirect_primary_authenticate_up_get_authentication_response(IndirectPrimaryAuthenticateUPResponse indirectPrimaryAuthenticateUPResponse);

// Setters

/** Setter for PrimaryAuthenticateUP authentication response */
const int ftress_indirect_primary_authenticate_up_set_authentication_response(IndirectPrimaryAuthenticateUPResponse indirectPrimaryAuthenticateUPResponse, AuthenticationResponse authenticationResponse);

// Free

/**Free the IndirectPrimaryAuthenticateUPResponse */
const int ftress_indirect_indirect_primary_authenticate_up_response_free(IndirectPrimaryAuthenticateUPResponse indirectPrimaryAuthenticateUPResponse);

/*************************************************************************************
*			 PrimaryAuthenticateDeviceResponse                           *
*************************************************************************************/
/** Constructs a new PrimaryAuthenticateDeviceResponse */
PrimaryAuthenticateDeviceResponse ftress_primary_authenticate_device_response_create();

// Getters

/** Returns PrimaryAuthenticateDeviceResponse authentication response */
AuthenticationResponse ftress_primary_authenticate_device_get_authentication_response(PrimaryAuthenticateDeviceResponse primaryAuthenticateDeviceResponse);

// Setters

/** Setter for PrimaryAuthenticateDevice authentication response */
const int ftress_primary_authenticate_device_set_authentication_response(PrimaryAuthenticateDeviceResponse primaryAuthenticateDeviceResponse, AuthenticationResponse authenticationResponse);

// Free

/**Free the PrimaryAuthenticateDeviceResponse */
const int ftress_primary_authenticate_device_response_free(PrimaryAuthenticateDeviceResponse primaryAuthenticateDeviceResponse);

/*************************************************************************************
*			 IndirectPrimaryAuthenticateDeviceResponse                   *
*************************************************************************************/
/** Constructs a new IndirectPrimaryAuthenticateDeviceResponse */
IndirectPrimaryAuthenticateDeviceResponse ftress_indirect_primary_authenticate_device_response_create();

// Getters

/** Returns IndirectPrimaryAuthenticateDeviceResponse authentication response */
AuthenticationResponse ftress_indirect_primary_authenticate_device_get_authentication_response(IndirectPrimaryAuthenticateDeviceResponse indirectPrimaryAuthenticateDeviceResponse);

// Setters

/** Setter for IndirectPrimaryAuthenticateDeviceResponse authentication response */
const int ftress_indirect_primary_authenticate_device_set_authentication_response(IndirectPrimaryAuthenticateDeviceResponse indirectPrimaryAuthenticateDeviceResponse, AuthenticationResponse authenticationResponse);

// Free

/**Free the IndirectPrimaryAuthenticateDeviceResponse */
const int ftress_indirect_primary_authenticate_device_response_free(IndirectPrimaryAuthenticateDeviceResponse indirectPrimaryAuthenticateDeviceResponse);

/*************************************************************************************
*			 LogoutResponse                                              *
*************************************************************************************/

/** Constructs a new LogoutResponse */
LogoutResponse ftress_logout_response_create();

// Free

/**Free the LogoutResponse */
const int ftress_logout_response_free(LogoutResponse logoutResponse);

/*************************************************************************************
*			 GetAuthenticationChallengeResponse                          *
*************************************************************************************/
/** Constructs a new GetAuthenticationChallengeResponse */
GetAuthenticationChallengeResponse ftress_get_authentication_challenge_response_create();

// Getters

/** Returns GetAuthenticationChallengeResponse authentication chanllenge */
AuthenticationChallenge ftress_get_authentication_challenge_get_authentication_challenge(GetAuthenticationChallengeResponse getAuthenticationChallengeResponse);

// Setters

/** Setter for GetAuthenticationChallengeResponse authentication response */
const int ftress_get_authentication_challenge_set_authentication_challenge(GetAuthenticationChallengeResponse getAuthenticationChallengeResponse, AuthenticationChallenge authenticationChallenge);

// Free

/**Free the GetAuthenticationChallengeResponse */
const int ftress_get_authentication_challenge_response_free(GetAuthenticationChallengeResponse getAuthenticationChallengeResponse);

/************************************************************************************
*                     IndirectGetPasswordSeedPositionsResponse                      *
************************************************************************************/
/** Constructs a new IndirectGetPasswordSeedPositionsResponse */
IndirectGetPasswordSeedPositionsResponse ftress_indirect_get_password_seed_positions_response_create();

// Getters

/** Returns the SeedPositions */
SeedPositions ftress_indirect_get_password_seed_positions_get_seed_positions(IndirectGetPasswordSeedPositionsResponse indirectGetPasswordSeedPositionsResponse);

// Setters

/** Sets the SeedPositions */
const int ftress_indirect_get_password_seed_positions_set_seed_positions(IndirectGetPasswordSeedPositionsResponse indirectGetPasswordSeedPositionsResponse, SeedPositions seedPositions);

// Free

/** Free the IndirectGetPasswordSeedPositionsResponse */
const int ftress_indirect_get_password_seed_positions_response_free(IndirectGetPasswordSeedPositionsResponse indirectGetPasswordSeedPositionsResponse);

/************************************************************************************
*                     GetMDAuthenticationPromptsResponse                            *
************************************************************************************/
/** 
* Constructs a new GetMDAuthenticationPromptsResponse
*/
GetMDAuthenticationPromptsResponse ftress_get_md_authentication_prompts_response_create();

// Getters

/** 
* Returns the MDAuthenticationPrompts
*/
MDAuthenticationPrompts ftress_get_md_authentication_prompts_get_md_authentication_prompts(GetMDAuthenticationPromptsResponse getMDAuthenticationPromptsResponse);

// Setters

/** 
* Sets the MDAuthenticationPrompts 
*/
const int ftress_get_md_authentication_prompts_set_md_authentication_prompts(GetMDAuthenticationPromptsResponse getMDAuthenticationPromptsResponse, MDAuthenticationPrompts mdAuthenticationPrompts);

// Free

/** 
* Free the GetMDAuthenticationPromptsResponse 
*/
const int ftress_get_md_authentication_prompts_response_free(GetMDAuthenticationPromptsResponse getMDAuthenticationPromptsResponse);

/************************************************************************************
*                    IndirectPrimaryAuthenticateMDResponse                          *
************************************************************************************/
/** 
* Constructs a new IndirectPrimaryAuthenticateMDResponse
*/
IndirectPrimaryAuthenticateMDResponse ftress_indirect_primary_authenticate_md_response_create();

// Getters

/**
* Returns IndirectPrimaryAuthenticateMDResponse authentication response 
*/
AuthenticationResponse ftress_indirect_primary_authenticate_md_get_authentication_response(IndirectPrimaryAuthenticateMDResponse indirectPrimaryAuthenticateMDResponse);

// Setters

/** 
* Setter for IndirectPrimaryAuthenticateMDResponse authentication response 
*/
const int ftress_indirect_primary_authenticate_md_set_authentication_response(IndirectPrimaryAuthenticateMDResponse indirectPrimaryAuthenticateMDResponse, AuthenticationResponse authenticationResponse);

// Free

/**
* Free the IndirectPrimaryAuthenticateMDResponse 
*/
const int ftress_indirect_primary_authenticate_md_response_free(IndirectPrimaryAuthenticateMDResponse indirectPrimaryAuthenticateMDResponse);

/*************************************************************************************
*			 PrimaryAuthenticateUPResponse                               *
*************************************************************************************/

/**
* Constructor for PrimaryAuthenticateUPResponse 
*/
PrimaryAuthenticateUPResponse ftress_primary_authenticate_up_response_create();

/** Getter for PrimaryAuthenticateUP authentication response */
AuthenticationResponse ftress_primary_authenticate_up_get_authentication_response(PrimaryAuthenticateUPResponse primaryAuthenticateUPResponse);

/** 
* Setter for PrimaryAuthenticateUP authentication response 
*/
const int ftress_primary_authenticate_up_set_authentication_response(PrimaryAuthenticateUPResponse primaryAuthenticateUPResponse, 
								     AuthenticationResponse authenticationResponse);

/**Free the PrimaryAuthenticateUPResponse */
const int ftress_primary_authenticate_up_response_free(PrimaryAuthenticateUPResponse primaryAuthenticateUPResponse);


/*************************************************************************************
*			 SearchDevicesResponse                                       *
*************************************************************************************/
/**
* Constructor for SearchDevicesResponse
*/
SearchDevicesResponse ftress_search_devices_response_create();

// Getters

/** 
* Returns the devices matching specified search criteria.
*/
DeviceSearchResults ftress_search_devices_response_get_device_search_results(SearchDevicesResponse searchDevicesResponse);

// Setters

/**
* Sets the DeviceSearchResults
*/
const int ftress_search_devices_response_set_device_search_results(SearchDevicesResponse searchDevicesResponse, DeviceSearchResults deviceSearchResults);

// Free

/** 
* Free the SearchDevicesResponse
*/
const int ftress_search_devices_response_free(SearchDevicesResponse searchDevicesResponse);

/************************************************************************************
*   ResetDeviceAuthenticatorFailedAuthenticationCountResponse                       *
************************************************************************************/
/** 
* Constructs the new ResetDeviceAuthenticatorFailedAuthenticationCountResponse
*/
ResetDeviceAuthenticatorFailedAuthenticationCountResponse ftress_reset_device_authenticator_failed_authentication_count_response_create();

/** 
* Free the ResetDeviceAuthenticatorFailedAuthenticationCountResponse
*/
const int ftress_reset_device_authenticator_failed_authentication_count_response_free(ResetDeviceAuthenticatorFailedAuthenticationCountResponse resetDeviceAuthenticatorFailedAuthenticationCountResponse);

/*************************************************************************************
*			End Responses                                                *
*************************************************************************************/


/************************************************************************************
*                       ftress Services                                             *
************************************************************************************/

/**
* Requests a primary UP authentication, to create a new direct session. 
*/
const int ftress_primary_authenticate_up(const char *endpoint, 
					 ChannelCode channelCode, 
					 UPAuthenticationRequest upAuthenticationRequest, 
					 SecurityDomain securityDomain, 
					 PrimaryAuthenticateUPResponse primaryAuthenticateUPResponse);

/**
* Requests a primary UP authentication for a specified authentication type for a specified user, 
* to create an indirect session. 
*/
const int ftress_indirect_primary_authenticate_up(const char *endpoint, 
						  Alsi alsi, 
						  ChannelCode channelCode, 
						  UPAuthenticationRequest upAuthenticationRequest, 
						  SecurityDomain securityDomain, 
						  IndirectPrimaryAuthenticateUPResponse indirectPrimaryAuthenticateUPResponse);


/** 
* Requests a primary Device authentication for a specified authentication type for a specified user or device, 
* to create a new direct session. 
*/
const int ftress_primary_authenticate_device(const char *endpoint, 
					     ChannelCode channelCode, 
					     DeviceAuthenticationRequest deviceAuthenticationRequest, 
					     SecurityDomain securityDomain, 
					     PrimaryAuthenticateDeviceResponse primaryAuthenticateDeviceResponse);

/** 
* Requests a primary Device authentication for a specified authentication type for an indirect user or device,
* to create an indirect session. 
*/
const int ftress_indirect_primary_authenticate_device(const char *endpoint,
						      Alsi alsi, 
						      ChannelCode channelCode, 
						      DeviceAuthenticationRequest deviceAuthenticationRequest, 
						      SecurityDomain securityDomain, 
						      IndirectPrimaryAuthenticateDeviceResponse indirectPrimaryAuthenticateDeviceResponse);

/** 
* Returns the authentication challenge that needs to be entered into the device for 
* asynchronous (challenge/response) authentication.
*/
const int ftress_get_authentication_challenge(const char *endpoint, 
					      ChannelCode channelCode, 
					      UserCode userCode, 
					      AuthenticationTypeCode authenticationTypeCode, 
					      SecurityDomain securityDomain, 
					      GetAuthenticationChallengeResponse getAuthenticationChallengeResponse);

/** 
* Returns a random set of seed positions, as the challenge for a seeded UP authentication of 
* a specified authentication type, for a specified user. The required number of seeds can also be specified.
* The method is intended to be used to obtain the seed positions for an indirect authentication, 
* although this restriction is not enforced.  
*/
const int ftress_indirect_get_password_seed_positions(const char *endpoint, 
						      Alsi alsi, 
						      ChannelCode channelCode, 
						      UserCode userCode, 
						      AuthenticationTypeCode authenticationTypeCode,
						      int numberOfSeeds,
						      SecurityDomain securityDomain,
						      IndirectGetPasswordSeedPositionsResponse indirectGetPasswordSeedPositionsResponse);

/** 
* Logs out a direct user. 
*/
const int ftress_logout(const char *endpoint,
			Alsi alsi, 
			ChannelCode channelCode, 
			SecurityDomain securityDomain, 
			LogoutResponse logoutResponse);

/** 
* Requests a primary MD authentication for a specified authentication type for a specified user,
* to create an indirect session.
*/
const int ftress_indirect_primary_authenticate_md(const char *endpoint,
						  Alsi alsi, 
						  ChannelCode channelCode, 
						  MDAuthenticationRequest mdAuthenticationRequest, 
						  SecurityDomain securityDomain, 
						  IndirectPrimaryAuthenticateMDResponse indirectPrimaryAuthenticateMDResponse);

/** 
* Returns a random set of unseeded prompts, as the challenge for an unseeded MD authentication 
* of a specified authentication type, for a specified user.
* The prompts returned depend on the configuration of the specified authentication type, 
* and the prompts available for the specified user's authenticator. This method is designed 
* to be called before making an unseeded primary MD authenticate call using 
*/
const int ftress_get_md_authentication_prompts(const char *endpoint,
					       UserCode userCode,
					       ChannelCode channelCode, 
					       AuthenticationTypeCode authenticationTypeCode, 
					       SecurityDomain securityDomain, 
					       GetMDAuthenticationPromptsResponse getMDAuthenticationPromptsResponse);

/** 
* Returns the devices matching specified search criteria.
* The maximum number of matching devices which can be returned is defined in the 4TRESS system configuration 
*/
const int ftress_search_devices(const char *endpoint,
				Alsi alsi,
				ChannelCode channelCode,
				DeviceSearchCriteria deviceSearchCriteria,
				SecurityDomain securityDomain,
				SearchDevicesResponse searchDevicesResponse);

/** 
* Resets the failed authentication count of the device authenticator of a specified authentication type, 
* of a specified user.
* This is a count of successive failed authentications (since the last successful authentication). 
*/
const int ftress_reset_device_authenticator_failed_authentication_count(const char *endpoint,
									Alsi alsi,
									ChannelCode channelCode,
									UserCode userCode,
									AuthenticationTypeCode authenticationTypeCode,
									SecurityDomain securityDomain,
									ResetDeviceAuthenticatorFailedAuthenticationCountResponse resetDeviceAuthenticatorFailedAuthenticationCountResponse);

/************************************************************************************
*                      End ftress Services                                          *
************************************************************************************/

#ifdef __cplusplus
 }
 #endif
