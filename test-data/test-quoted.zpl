
define 'my great service' as a service.

define mygreatservice as a service.

define 'most excellent user' aka 'great ones' as a user with color:red.
allow  'most excellent user' to access "my great service".
allow 'great ones' to access user.color:red services.

define mostexcellentuser as a user with color:green.
allow  mostexcellentuser to access mygreatservice.


define AuthService as a service
allow zpr.adapter.cn: endpoints to access AuthService

# define NetAdmins as users with endpoint.zpr.adapter.cn:'admin.zpr.org'

# VisaService is a reserved name.
# allow NetAdmins to access VisaService






