allow clearance:classified government users to access classified
services.


# ZPL author must define any auth services and ensure that
# the service name is present in the configuration.

define AuthService as a service

// define AuthService as a service with endpoint.zpr.adapter.cn:'bas.zpr.org'
// consider "define AuthService as a service on endpoints with cn:'bas.zpr.org'

// ZPL author must explicitly grant access to any authentication
// services for adapters.
// Access for the visa service is added by the compiler.

allow zpr.adapter.cn: endpoints to access AuthService

# In policy you can define "administrators" in any way you want.
define NetAdmins as users with endpoint.zpr.adapter.cn:'admin.zpr.org'

# VisaService is a reserved name.
allow NetAdmins to access VisaService






