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

## Testing

```
cargo test --features with_nativetls_vendored
```

The test suite covers:
- DNS wire format parsing (dns crate) — record types, labels, edge cases
- CLI argument parsing (src/options.rs)
- JSON output serialization (src/output.rs) — flags, classes, record types, all record data variants, queries, answers
- Text output formatting (src/output.rs) — duration formatting, record payload summaries
- Integration tests via Specsheet (see xtests/)

## Known issues

- `openssl-sys` build fails without `libssl-dev` installed. Use `--features with_nativetls_vendored` to avoid this.
