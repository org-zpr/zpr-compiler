define Image-database as an device with mach-type:idb.
define server as service with service.
allow Image-database to access service:image-database servers.
