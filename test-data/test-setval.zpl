define WebService as a service with user.markers:{web, service}

allow role:{manager, marketing} users to access content:{green, marketing} services

allow role:intern users to access content:{edu, govt} services

# Ok to use set notation here too though not required.
allow role:{foo} users to access content:{red} services

