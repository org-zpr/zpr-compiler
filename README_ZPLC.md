# ZPLC - ZPL Configuration

ZPLC uses TOML syntax.  Work in progress.


## Trusted Services

The trustred block contains details about the API to use to talk to it, as
well as things like attributes returned.

Syntax:

```toml
  [trusted_service.<TSNAME>]
  api = ""
  service = ""
  client = ""
  cert_path = ""
  returns_attributes = []
  identity_attributes = []
  provider = []
```

The **TSNAME** of `default` is special and is used to check the adapter CN values.
It is responsible for the property: `device.zpr.adapter.cn`.  The default
service requires a `cert_path` which should be set to the certificate of the
authority which has signed the NOISE certs given to the adapters.

For non default trusted services, the field meanings are:

* `api` - Configures how the visa service uses the trusted service. Valid values are:
  * `validation/2` - An validation service.  Meaning that the service can provide
     validation of authentication to a visa service, and actor authentication services
     to an adapter.
  * *addition values TBD*
* `service` - Sets the service ID used in the **services** block for the visa-service
  facing service provided by this trusted service.  This is *optional* and by default
  the compiler expects to find a service block named `<TSNAME>-vs`.
* `client` - Sets the service ID used in the **services** block for the actor/adapter
  facing service provided by this trusted service.  This is *optional* and by default
  the compiler expects to find a service block named `<TSNAME>-client`.
* `cert_path` - Used to pass a TLS certificate to the visa service which is used to
  verify the service connection.
* `returns_attributes` - List of attribute keys returned by the service.
* `identity_attributes` - Subset of the `returns_attributes` that denote identity.
* `provider` - Attribute key/value tuples of the actor (or actors) that provide this service.


### Services

A trusted service for validation is really two services: the service that the visa service
talks to to confirm authentication and retrieve attributes, and the service that an actor
talks to to perform authentication.  These services use varying protocols and ports like
any service on the ZPRnet.  To configure these services, the compiler requires that there
are `services` blocks defined in the usual way.  The IDs attached to these blocks are either
defaults or are set using the `service` and `client` properties of the trusted service
(see above).

Communication with the trusted service uses a set of pre-defined protocols which must be
supported by the ZPR implementation.  The protocols defined in the ZPR Referernce
Implementation are:

* `zpr-authrsa` - An actor OAuth-derived HTTPS protocol used by an adapter to authenicate its
  actor using an RSA key.
* `zpr-validation/2`- A visa service HTTPS OAuth protocol which allows the visa service to
  request an authentication token based on an identifier.

Example:

```toml
[services.foo-vs]
protocol = "zpr-validation/2"
port = 4444

[services.foo-client]
protocol = "zpr-oauthrsa"
port = 1234
```



### Attributes

An attribute is of the form: `<NAMESPACE>.<ATTR_KEY>`.  There may be additional periods
in the `<ATTR_KEY>` value.

Every attribute must be in one of the ZPR namespaces: "device", "user", or "service".

Valid attribute examples:
* `user.id`
* `device.tmp.key_hash`
* `service.type`

Attributes from services may be single value, multi value, or tags.  An attribute list
(eg, `returns_attributes` or `identity_attributes`) is a list of strings.  The type of
the attribute is set as:

* **Single Value** - Just a plain string, eg `"user.clearance"`.
* **Multi Value** - *TODO*
* **Tag** - Prefixed with a hash mark (`#`), eg `"#device.secure`.



## Protocols

Each service defined in the coniguration uses a protocol for communication. The protocols
are defined seperately in a `protocols` block.  Syntax:

```toml
[protocol.<NAME>]
l4protocol = ""
l7protocol = ""
port = N
icmp_type = ""
icmp_codes = []
```

The `<NAME>` field must be unique and is referenced by configuraiton `service` blocks.

Meanings:
* `l4protocol` - Supports values like, `iana.ICMP6` or `iana.TCP`.
* `l7protocol` - Optional and may be used as a hint to the visa service when setting up rules.
  Example, `http`.
* `port` - Required if the `l4protocol` requires a port number (as it does for TCP and UDP).
* `icmp_type` - Required for the ICMP familty of protocols, possible values are:
  `request-response` or `oneshot`.
* `icmp_codes` - Is a list of integers.  For `request-response` this is a tuple of
  (request-code, response-code).  For `oneshot` this is one or more allowed ICMP codes.


## Services

A service must be defined in the configuration for every service that is
declared in the policy file.  The basic format is:

```toml
[service.<NAME>]
protocol = "" # required
```

The `<NAME>` must match a name in the ZPL policy file.  The `protocol` must match a
protocol block defined elsewhere in the configuration.

Since it is typical to have a protocol like `HTTPS` but then have instances that
use many different ports, it is possible to override some aspects of a protocol in
the service definition, for example:

```toml
[protocol.webtls]
l4protocl = "iana.TCP"
l7protocol = "https"
port = 443

[service.WebService]
protocol = webtls
port = 3030
```

