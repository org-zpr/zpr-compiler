

define Image-database as a service.

# ON - used for a client endpoint clause
# In this case the client user is on a secure endpoint.
allow clearance:classified government users on hardened endpoints to access level:classified services.

# ON - used for a service clause
# In this case the service is on a secure endpoint.

# First, here is old way that should still work.
allow clearance:classified government users to access level:classified, endpoint.hardened services.

# And here is new way using ON
allow clearance:classified government users to access level:classified services on encrypted endpoints.



# allow clearance:classified government users to access classified services.


define AuthService as a service

# Here is an endpoint clause without ON since there is no user clause.
allow zpr.adapter.cn: endpoints to access AuthService

# This should work too. Once "on" appears in a define it starts an endpoint clause
# until EOL or a WITH.
# TODO define NetAdmins as users on zpr.adapter.cn:'admin.zpr.org' endpoints.

# VisaService is a reserved name.
# allow NetAdmins to access VisaService






