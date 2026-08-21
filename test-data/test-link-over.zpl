
# Link constraints: the "over" clause (RFC 15).
# Both the allow and the never forms must record their link conditions.

define database as a service.


allow redhead users to access database over secure, location:usa links.
never allow baldy users to access database over foreign links.

# A statement with no over clause must record no link conditions.
allow nerd users to access database.
