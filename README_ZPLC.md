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
only attribute you can use here is `device.zpr.adapter.cn` which is the `CN` value from
the nodes Noise certificate.
* `zpr_address` - IPv6 ZPRnet address for the node. Node must be preconfigured with this
same address.

### Topology

If there are multiple nodes you need to define their substrate addresses. We support multiple
substrate addresses per node. Each address is specified in `HOST:PORT` format and is tied
to an identifier.  In the example below the identifier is `i0`.


```toml
[nodes.<NODEID>]
provider = [[]]
#...

[nodes.<NODEID>.substrate_addrs]
i0 = "10.0.0.1:5000"
```

To connect nodes you must specific `links` in the zplc file.

```toml
[links.<LINKID>]
attributes = [["zpr.cost", "1"]] # this is the default
peers = [ { node = "<NODEID>" },
          { node = "<NODEID>" } ]
```

If a node has multiple substrate addresses then reference the substrate address name
in the peers list, eg:

```toml
[links.<LINKID>]
attributes = [["zpr.cost", "1"]] # this is the default
peers = [ { node = "<NODEID>" },
          { node = "<NODEID>", interface = "i3" } ]
```


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
It is responsible for the property: `device.zpr.adapter.cn`.  The default
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
  * `file` - A file-backed attribute source offered by the visa service itself, with no
     network presence. The visa service loads the attributes from a local `<TSNAME>.json`
     file at runtime. See *File Trusted Services* below.
  * *addition values TBD*
* `service` - Sets the service ID used in the **services** block for the visa-service
  facing service provided by this trusted service.  This is *optional* and by default
  the compiler expects to find a service block named `<TSNAME>-vs`.
* `client` - Sets the service ID used in the **services** block for the actor/adapter
  facing service provided by this trusted service.  This is *optional* and by default
  the compiler expects to find a service block named `<TSNAME>-client`.
* `cert_path` - Used to pass a TLS certificate to the visa service which is used to
  verify the service connection.
* `returns_attributes` - List of attribute keys returned by the service mapped to
  ZPL attribute names.
* `identity_attributes` - Subset of the `returns_attributes` that denote identity.
* `provider` - Attribute key/value tuples of the actor (or actors) that provide this service.
* `expiration_seconds` - Optional lifetime (in seconds) of the attributes this service vouches
  for. Accepted on `validation/2` and `file` services; rejected on `default`. Must be a
  non-negative integer that fits in a 32-bit unsigned value. Omitted or `0` means the visa
  service selects the lifetime at runtime (from the service or its own default).

Every trusted-service ID (the `<TSNAME>`) must match `[A-Za-z0-9_-]+`. For a `file` service this
ID is also the filename stem — the visa service loads attributes from `<TSNAME>.json`.


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

### File Trusted Services

A `file` trusted service supplies actor attributes from a local JSON file loaded by the visa
service rather than over the network. Declare only `returns_attributes` (at least one mapping)
and, optionally, `expiration_seconds`:

```toml
[trusted_services.attrfile]
api = "file"
returns_attributes = ["hair_color -> user.hair_color", "lazy -> #user.lazy"]
expiration_seconds = 3600
```

Because a file service has no network presence, the `service`, `client`, `cert_path`, `provider`,
and `identity_attributes` properties are **not** allowed. The compiler weaves it as a service
offered by the visa service CN (`vs.zpr`) with no endpoints and no communication policy. The
attribute mappings use the same `->` syntax (and single / `{}` multi / `#` tag forms) as any other
trusted service (see *Attributes* below).

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
* **Multi Value** - Add a '{}' to the end, eg `"user.role{}"`.
* **Tag** - Prefixed with a hash mark (`#`), eg `"#device.secure`.

When specifying the `returns_attributes` use a map format with an arrow '->':


```toml
returns_attributes = [
  "tint -> device.tint",
  "color -> user.color",
  "govt -> #user.government",
  "bas_id -> user.id",
  "roles -> user.role{}"
]
```

And then for `identity_attributes` make sure to use the service name (not the
ZPL name).  For example, given the above returns attributes:

```toml
identity_attributes = [ "bas_id" ]
```


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
protocol = "webtls"
port = 3030
```

To associate a service with an actor you need provider attributes. These can
come from the ZPL, but you can also put them in the configuration.  Eg,

```toml
[service.WebService]
protocol = "http"
port = 80
provider = [[ "device.zpr.adapter.cn", "foo.blah"]]
```

If you need a static address for a service, the service adapter needs to specify
a `zpr_addr` in its config file AND the service configuration needs to match
with a `zpr.addr` attribute.  For example,

```toml
[service.WebService]
protocol = "http"
port = 80
provider = [[ "device.zpr.adapter.cn", "foo.blah"], ["zpr.addr", "fd5a:5052:2020::19"]]
```




