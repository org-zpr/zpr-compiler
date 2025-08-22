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


## TODO

Work is ongoing to accept the full ZPL syntax. Note that it is one
thing for the compiler to accept the syntax and process it into a policy
and another for the Visa Service to be able to implement the policy.

Here are syntax bits that are not yet supported by the compiler:

- Keyword `on` for referencing endpoint class. (Issue: [#30] )
- Quoting in AKA names or defined class names. (Issue: [#31][2] )
- Set values for attributes.  Eg, `allow color:{red, blue} users to access ...` (Issue: [#32][3])
- Deny statements: `never allow...` (Issue: [#33][4] )
- Signal clause: `... and signal ...` (Issue: [#34][5])
- Limits.
- Conditions.
- Through clause.


[1]: https://github.com/org-zpr/zpr-compiler/issues/30
[2]: https://github.com/org-zpr/zpr-compiler/issues/31
[3]: https://github.com/org-zpr/zpr-compiler/issues/32
[4]: https://github.com/org-zpr/zpr-compiler/issues/33
[5]: https://github.com/org-zpr/zpr-compiler/issues/34

