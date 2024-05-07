#include<string.h>

#include<stdlib.h>


#include<stdbool.h>

#include<stdint.h>
#include<errno.h>





#define COCKPIT_TYPE_FLOW             (cockpit_flow_get_type ())
#define COCKPIT_ERROR (cockpit_error_quark ())


#define COCKPIT_CONF_SSH_SECTION "Ssh-Login"
#define COCKPIT_TYPE_WEB_FILTER            (cockpit_web_filter_get_type ())

#define COCKPIT_CHECKSUM_HEADER "X-Cockpit-Pkg-Checksum"
#define COCKPIT_RESOURCE_PACKAGE_VALID "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
#define COCKPIT_TYPE_WEB_RESPONSE         (cockpit_web_response_get_type ())

