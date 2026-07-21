

define Image-database as a service.

# ON - used for a client device clause
# In this case the client user is on a secure device.
allow clearance:classified government users on hardened devices to access level:classified services.
#___________________________________________↑

# ON - used for a service clause
# In this case the service is on a secure device.

# First, here is old way that should still work.
allow clearance:classified government users to access level:classified, device.hardened services.

# And here is new way using ON
allow clearance:classified government users to access level:classified services on encrypted devices.
#_______________________________________________________________________________↑


# Now define an device that requires an attribute. And then use that in a
# trailing ON clause.
define LockedDevice as an device with tag encrypted.
allow clearance:classified government users to access level:secret services on LockedDevices.
#___________________________________________________________________________↑



# Defines as usual must use the WITH format.
define ServiceRequiresEncrypted as an Image-database with tag device.encrypted.
allow clearance:public users to access ServiceRequiresEncrypted.


define AuthService as a service.

# Here is an device clause without ON since there is no user clause.
allow zpr.adapter.cn: devices to access AuthService.
define NetAdmins as users with device.zpr.adapter.cn:'admin.zpr.org'.
allow NetAdmins to access VisaService.
