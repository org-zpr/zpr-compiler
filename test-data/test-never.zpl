



define WebService as a service with user.bas_id:1234.

never allow color:green users to access content:green services.
allow color:brown users to access content:brown services.

define FooService as a service with user.bas_id:4567.
allow color:green users to access content:green FooServices.
never allow color:purple users to access FooServices.


