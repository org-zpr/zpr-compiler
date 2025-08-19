allow clearance:classified government users to access classified
services.


note: ZPL author must define any auth services and ensure that
note: the service name is present in the configuration.

define AuthService as a service

note: define AuthService as a service with endpoint.zpr.adapter.cn:'bas.zpr.org'
note: consider "define AuthService as a service on endpoints with cn:'bas.zpr.org'

note: ZPL author must explicitly grant access to any authentication
note: services for adapters.
note: Access for the visa service is added by the compiler.


allow zpr.adapter.cn: endpoints to access AuthService



note: In policy you can define "administrators" in any way you want.
define NetAdmins as users with endpoint.zpr.adapter.cn:'admin.zpr.org'

note: VisaService is a reserved name.
allow NetAdmins to access VisaService






