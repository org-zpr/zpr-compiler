# ZPL Compiler

Can translate simple ZPL into binary policies that the prototype visa
service can process.  This comes bundled with a tool to examine the
contents of a "compiled" binary policy, `zpdump`.

## Example usage

```bash
./zplc -k path/to/rsa-key.pem path/to/policy.zpl
```

- That RSA key in the invocation is used to sign the binary policy so
  must match the one that the visa service is configured with.
- By default the _configuration_ for the ZPL policy will be found in a
  file with the same name as the ZPL file but with the `zplc` extension.
  If you want to load configuration from somewhre else, use
  `-c path/to/config.zplc` argument.
- Help is available via `zplc -h`


## How to build

The compiler makes use of our binary policy encodings which are currently
in a private repository. We have bundled the rust repo along with the
current compiler [release](https://github.com/org-zpr/zpr-compiler/releases).

First download and unpack `zpr-policy-rs.tar.gz`. Then point the
zpr-compiler `Cargo.toml` at the path instead of the github repo. So change
this:

``` 
zpr-policy = { git = "https://github.com/org-zpr/zpr-policy-rs.git", tag = "v0.8.5", features = ["v1", "v2"]}
```

to this:

```
zpr-policy = { path = "/path/to/zpr-policy-rs", tag = "v0.8.5", features = ["v1", "v2"]}
```


## TODO

Work is ongoing to accept the full ZPL syntax. Note that it is one
thing for the compiler to accept the syntax and process it into a policy
and another for the Visa Service to be able to implement the policy.

Here are syntax bits that are not yet supported by the compiler:

- Limits.
- Conditions.



