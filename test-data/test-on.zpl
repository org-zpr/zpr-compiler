

define Image-database as a service.

# ON - used for a client endpoint clause
# In this case the client user is on a secure endpoint.
allow clearance:classified government users on hardened endpoints to access level:classified services.
#___________________________________________↑

# ON - used for a service clause
# In this case the service is on a secure endpoint.

# First, here is old way that should still work.
allow clearance:classified government users to access level:classified, endpoint.hardened services.

# And here is new way using ON
allow clearance:classified government users to access level:classified services on encrypted endpoints.
#_______________________________________________________________________________↑


# Now define an endpoint that requires an attribute. And then use that in a
# trailing ON clause.
define LockedEndpoint as an endpoint with tag encrypted.
allow clearance:classified government users to access level:secret services on LockedEndpoints.
#___________________________________________________________________________↑



# Defines as usual must use the WITH format.
define ServiceRequiresEncrypted as an Image-database with tag endpoint.encrypted.
allow clearance:public users to access ServiceRequiresEncrypted.


define AuthService as a service.

# Here is an endpoint clause without ON since there is no user clause.
allow zpr.adapter.cn: endpoints to access AuthService
define NetAdmins as users with endpoint.zpr.adapter.cn:'admin.zpr.org'.
allow NetAdmins to access VisaService






