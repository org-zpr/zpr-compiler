# ZPLC - ZPL Configuration

ZPLC uses TOML syntax.  Work in progress.



## Layout

Suggest layout within the TOML file:

* nodes
* trusted_services
* bootstrap
* protocols
* services


## Nodes

Only one node is supported currently in a ZPRnet.  Syntax:

```toml
[nodes.<NODEID>]
provider = [["<KEY>", "<VALUE>"]]
zpr_address = "fd5a..."
```
* `provider` - The set of attributes required in order to provide the node "service". These
attributes cannot come from an external service they must be "built in".  Typically the
only attribute you can use here is `endpoint.zpr.adapter.cn` which is the `CN` value from
the nodes Noise certificate.
* `zpr_address` - IPv6 ZPRnet address for the node. Node must be preconfigured with this
same address.


## Trusted Services

The trusted services block contains details about the API to use to talk to it, as
well as things like attributes returned.

Syntax:

```toml
  [trusted_service.<TSNAME>]
  api = "validation/2"
  service = ""
  client = ""
  cert_path = ""
  returns_attributes = []
  identity_attributes = []
  provider = []
```

The **TSNAME** of `default` is special and is used to check the adapter CN values.
It is responsible for the property: `endpoint.zpr.adapter.cn`.  The default
service requires a `cert_path` which should be set to the certificate of the
authority which has signed the NOISE certs given to the adapters.

```toml
[trusted_services.default]
cert_path = "path/to/ca/cert.pem"
```


If you omit `trusted_services.default` then certificates will not be checked.

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

* `zpr-oauthrsa` - An actor OAuth-derived HTTPS protocol used by an adapter to authenicate its
  actor using an RSA key.
* `zpr-validation2`- A visa service HTTPS OAuth protocol which allows the visa service to
  request an authentication token based on an identifier.

Example:

```toml
[services.foo-vs]
protocol = "zpr-validation2"
port = 4444

[services.foo-client]
protocol = "zpr-oauthrsa"
port = 1234
```

### Attributes

An attribute is of the form: `<NAMESPACE>.<ATTR_KEY>`.  There may be additional periods
in the `<ATTR_KEY>` value.

Every attribute must be in one of the ZPR namespaces: "endpoint", "user", or "service".

Valid attribute examples:
* `user.id`
* `endpoint.tmp.key_hash`
* `service.type`

Attributes from services may be single value, multi value, or tags.  An attribute list
(eg, `returns_attributes` or `identity_attributes`) is a list of strings.  The type of
the attribute is set as:

* **Single Value** - Just a plain string, eg `"user.clearance"`.
* **Multi Value** - *TODO*
* **Tag** - Prefixed with a hash mark (`#`), eg `"#endpoint.secure`.






## Bootstrap

The boostrap section maps a `CN` value (from noise keys) to a cooresponding public
RSA key file.  When adapters connect with these `CN` values, they can perform "self authentication"
which ends up having the visa service check that the adapter is using the correct private
key.

Bootstrap is required for services that need to connect before there are trusted services
connected.

Syntax:

```toml
[boostrap]
"some.cn.value.here" = "path-to-rsa-pub-key.pem"
```


## Protocols

Use protocols blocks to define protocols that are needed to access your services.

Syntax:
```toml
[protocols.<NAME>]
l4protocol = "TCP"
port = 80

# or if using ICMP
[protocols.ping]
l4protocol = "ICMP4"
icmp_type = "request-response"
icmp_codes = [0, 8]
```

* `protocols.<NAME>` - The NAME here is used later in `services` blocks to reference
the protocol.
* `l4protocol` - Layer 4 protocol name. One of 'TCP', 'UDP', 'ICMPV6', or 'ICMP' (or 'ICMP4').
* `port` - Port number. Currently only supports a single port number.
* `icmp_type` - Required for the ICMP familty of protocols, possible values are: `request-response` or `oneshot`.
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
l4protocl = "TCP"
port = 443

[service.WebService]
protocol = webtls
port = 3030
```




