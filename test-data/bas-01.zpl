allow clearance:classified government users to access classified
services.


note: ZPL author must define any auth services and ensure that
note: the service name is present in the configuration.

define AuthService as a service with cn:'bas.zpr.org'

note: ZPL author must explicitly grant access to any authentication
note: services for adapters.
note: Access for the visa service is added by the compiler.

allow zpr.adapter.cn: users to access AuthService


