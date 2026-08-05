# Fixture for the bin2 determinism test (see tests/zpl-test.rs).
# `database` is defined with provider attributes here AND accessed generically below,
# so the fabric ends up with two instances of the same config id: database and database#1.
# The `never` statements must stay ahead of the `allow` statements for each service.

define employee as a user with user.bas_id.
define database as a service with user.bas_id:1234.

never allow color:red employees to access classified databases.
allow lazy, color:green employees to access classified databases on tint:sales devices.
allow clearance:classified government users to access classified services.

define AuthService as a service.
allow zpr.adapter.cn: devices to access AuthService.

define NetAdmins as users with device.zpr.adapter.cn:'admin.zpr.org'.
allow hair_color:red NetAdmins to access VisaService.
