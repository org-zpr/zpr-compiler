define database as a service.
define employee as a user with user.bas_id.
define signalService as a service.

# No ON
allow color:red employees
to access databases and
signal "red employee" to signalService.

allow employees to access databases and signal "employee"
     to signalService.

# With ON
allow color:red employees to access databases on tint:sales devices and signal "red tint access" to signalService.

allow employees on hardened devices to access databases and signal "accessed" to signalService.
