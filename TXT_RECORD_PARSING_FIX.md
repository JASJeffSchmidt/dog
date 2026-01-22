# TXT Record Parsing Bug Fix

## Issue Description

Dog was failing to parse certain TXT DNS records with the error:
```
Malformed packet: length 256 was specified, but read 257 bytes
```

This occurred when querying DKIM records and other TXT records that contained character strings ending at specific length boundaries.

### Example Failure
```bash
$ ./target/release/dog selector1._domainkey.jschmidt.org TXT @8.8.8.8 --json
{"error":true,"error_phase":"protocol","error_message":"Malformed packet: length 256 was specified, but read 257 bytes"}
{"responses":[]}
```

Meanwhile, `dig` handled the same query successfully, returning the DKIM public key.

## Root Cause Analysis

### DNS TXT Record Structure
According to RFC 1035 §3.3.14, TXT records contain one or more character-strings, where each character-string is:
- 1 byte: length (0-255)
- N bytes: data (where N = the length byte value)

### Dog's Special Handling
Dog implements special logic for long strings: when a character-string has length=255, it treats the next character-string as a continuation of the same logical message, rather than as a separate message. This allows representing strings longer than 255 bytes.

The parsing loop works as follows:
1. Read a length byte
2. Add `length + 1` to `total_length` (accounting for the length byte itself)
3. Read that many data bytes
4. If length == 255, continue the inner loop to read more chunks
5. If length < 255, break and finalize the message

### The Bug
When a TXT record's data ended with a character-string of exactly 255 bytes at the record boundary, the code would:

1. Read length byte: 0xFF (255)
2. Update `total_length = 256` (255 + 1)
3. Read 255 data bytes
4. Check: `next_length < 255`? No (it's exactly 255)
5. Continue inner loop (expecting more data)
6. **Try to read another length byte → IO error or length mismatch**

The bug was that the code assumed if `length == 255`, there MUST be more data following. It didn't check if consuming that 255-byte chunk had already exhausted the entire record's stated length.

### Actual DNS Packet Structure
The DKIM record that triggered this bug likely had a structure similar to:
```
Stated RDATA length: 256 bytes
Data: [0xFF] [255 bytes of base64-encoded public key]
```

Or possibly:
```
Stated RDATA length: 256 bytes  
Data: [0xF0] [240 bytes] [0x0F] [15 bytes] [0x01] [1 byte]
```

Where the sum of all character-strings (including their length bytes) equals exactly 256.

## The Fix

### Code Change
Added a boundary check in `dns/src/record/txt.rs` after reading a chunk with length=255:

```rust
if next_length < 255 {
    break;
}
else if total_length >= stated_length {
    // If we've read a chunk with length 255 and we've now consumed
    // all the stated bytes, stop here. Don't try to read another
    // length byte as we've reached the end of the record.
    trace!("Got length 255 and reached stated_length, stopping");
    break;
}
else {
    trace!("Got length 255, so looping");
}
```

### Logic Flow After Fix
Now when encountering a 255-byte chunk:
1. Read length byte: 0xFF (255)
2. Update `total_length = 256`
3. Read 255 data bytes
4. Check: `next_length < 255`? No
5. **Check: `total_length >= stated_length`? Yes → break (don't try to read more)**
6. Finalize message and validate total length

This prevents the off-by-one error by checking the boundary before attempting to read beyond the record's stated length.

## Testing

### New Test Case
Added `exact_256_byte_boundary` test that reproduces the bug:
```rust
#[test]
fn exact_256_byte_boundary() {
    // TXT record with 255-byte character string at boundary
    let mut buf = vec![0xFF]; // length byte = 255
    buf.extend(vec![0x41; 255]); // 255 'A's
    
    // stated_length is 256 (exact size of buffer)
    let result = TXT::read(256, &mut Cursor::new(&buf));
    assert!(result.is_ok(), "Should parse successfully at boundary");
    let txt = result.unwrap();
    assert_eq!(txt.messages.len(), 1);
    assert_eq!(txt.messages[0].len(), 255);
}
```

### Validation
- All 131 existing DNS library tests pass
- The original failing query now works correctly:
  ```bash
  $ ./target/release/dog selector1._domainkey.jschmidt.org TXT @8.8.8.8
  TXT selector1-jschmidt-org._domainkey.jschmidt.onmicrosoft.com. 1h00m00s 
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDERlSs0gZIy..."
  ```

## Impact

This fix resolves parsing failures for:
- DKIM TXT records (common use case that triggered discovery)
- SPF records with data at specific length boundaries
- Any TXT record where character-string data aligns with the RDATA length boundary
- Edge cases where the last character-string is exactly 255 bytes

The fix is conservative and only changes behavior in the specific error case, maintaining backward compatibility with all existing valid records.

## Related Code

- **File**: `dns/src/record/txt.rs`
- **Function**: `Wire::read()` implementation for `TXT`
- **Lines**: Added check after line 47 in the inner loop
