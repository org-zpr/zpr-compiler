define Image-database as a endpoint with mach-type:idb.

define server as service with machine-id.

allow Image-database with users to access service:image-database servers.

