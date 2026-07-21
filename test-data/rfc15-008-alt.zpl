define Image-database as a device with mach-type:idb.

define server as service with machine-id.

# Rewritten using the 'on' keyword.
allow users on Image-database to access service:image-database servers.

