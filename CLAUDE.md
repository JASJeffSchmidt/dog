# Dog - DNS client

A command-line DNS client (like dig, but more user-friendly).

## Build

The default build requires `libssl-dev` which is often missing. Use the vendored feature to statically link OpenSSL instead:

```
cargo build --release --features with_nativetls_vendored
```

## Project structure

- `dns/` - DNS protocol library (record types, wire format parsing)
- `dns-transport/` - DNS transport layer (UDP, TCP, TLS, HTTPS)
- `src/` - CLI binary (argument parsing, output formatting)

## Known issues

- `openssl-sys` build fails without `libssl-dev` installed. Use `--features with_nativetls_vendored` to avoid this.
