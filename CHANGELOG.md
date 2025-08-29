# The ZPR ZPL Compiler Changelog

## [0.6.1] - 2025-08-29

- Quoting and escaping now in line with ZRFC-15. That is you can quote
  with either single quotes (any sort and they do not have to match) or
  with double quotes.  While quoting, you can insert a literal quote or
  backslash by using a backslash.

## [0.6.0] - 2025-08-26

- Uses zpr-policy version 0.6.0.

## [0.5.0] - 2025-08-25

- `device` is now `endpoint`.
- New comment syntax: '#' or '//' which consumes to EOL. The old 'note:'
  and 'comment:' syntax is removed.

## [0.4.0] - 2025-06-16

- Stores the return and identity attributes in the policy binary.
- The `admin_attrs` for `visa_service` block is no longer supported.
  Instead you must write `allow` statements in your ZPL targeting the
  special reserved service named `VisaService`.


## [0.3.0] - 2025-06-02

- `trusted_service` block requires provider (not for default).
- Additions to `trusted_service` to support new authentication services.
- In the `protocol` block, the `protocol` key has been renamed to `l4protocol`.
- A `service` block can override protocol details like `port` or ICMP.
- Non default trusted services must have cooresponding services blocks for 
  their client and visa service components.
- All attributes must be in one of our domains: user, device or service.
- All attributes must come from a declared service.
- Removed the `prefix` setting for a `trusted_service`.


## [0.2.0] - 2025-05-01

- Support for adding bootstrap keys to policy.
- New binary name: 'zplc'.


## [0.1.0] - 2025-03-27

_Initial Release._  In which the compiler source code was ported over
from the main [zpr-core](https://github.com/org-zpr/zpr-core)
repository.



[0.6.0]: https://github.com/org-zpr/zpr-compiler/releases/tag/v0.6.0
[0.5.0]: https://github.com/org-zpr/zpr-compiler/releases/tag/v0.5.0
[0.4.0]: https://github.com/org-zpr/zpr-compiler/releases/tag/v0.4.0
[0.3.0]: https://github.com/org-zpr/zpr-compiler/releases/tag/v0.3.0
[0.2.0]: https://github.com/org-zpr/zpr-compiler/releases/tag/v0.2.0
[0.1.0]: https://github.com/org-zpr/zpr-compiler/releases/tag/v0.1.0

