



define WebService as a service with user.bas_id:1234.

allow color:green users to access content:green services.
allow color:brown users to access content:brown services.
allow color:red users to access WebService.

define FooService as a service with user.bas_id:4567.
allow color:green users to access content:green FooServices.
allow color:purple users to access FooServices.


# What we expect:
#
# CONNECT:
#   user.bas_id:1234 then advertise WebService
#   user.bas_id:4567 then advertise FooService
#   user.bas_id:4567 && service.content:green then advertise FooService#1
#   user.color:green OK
#   user.color:brown OK
#   user.color:red OK
#   user.color:purple OK
#
# POLICIES:
#   WebService
#     svc_cond: content:green
#     cli_cond: color:green
#   WebService
#     svc_cond: content:brown
#     cli_cond: color:brown
#   WebService
#     cli_cond: color:red
#   FooService
#     svc_cond: content:green
#     cli_cond: color:green
#  FooService:
#     svc_cond: content:brown
#     cli_conf: color:brown
#   FooService
#     cli:cond: color:purple
#
