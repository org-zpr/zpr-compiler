
Allow red services                                    to access blue services.
Allow green users                on yellow endpoints  to access blue services on orange endpoints.
Allow red services               on yellow endpoints  to access blue services on orange endpoints.
Allow user.green, brown services on yellow endpoints  to access blue services.
Allow service.brown, green users on yellow endpoints  to access blue services.
Allow red services                                    to access user.green, blue services on yellow endpoints.


define MyDb as a service with tag blue.
define MyWeb as a service with tag red.

Allow MyWeb to access MyDb.



# If you put a service class on the LHS, implies actor must provide a service.
# AND match the attribute. 
