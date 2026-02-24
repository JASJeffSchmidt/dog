use log::*;

use crate::wire::*;


/// A **DS** _(delegation signer)_ record, which contains a hash of a DNSKEY
/// record. DS records are used to verify the authenticity of child zones in
/// the DNSSEC chain of trust.
///
/// # References
///
/// - [RFC 4034 §5](https://tools.ietf.org/html/rfc4034#section-5) — Resource
///   Records for the DNS Security Extensions (March 2005)
#[derive(PartialEq, Debug)]
pub struct DS {

    /// A tag value computed from the referenced DNSKEY record, used to
    /// efficiently identify which key this DS record refers to.
    pub key_tag: u16,

    /// The algorithm number of the referenced DNSKEY record.
    pub algorithm: u8,

    /// The digest type used to create the digest of the DNSKEY record.
    pub digest_type: u8,

    /// The digest of the DNSKEY record.
    pub digest: Vec<u8>,
}

impl Wire for DS {
    const NAME: &'static str = "DS";
    const RR_TYPE: u16 = 43;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        if stated_length < 5 {
            let mandated_length = MandatedLength::AtLeast(5);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let key_tag = c.read_u16::<BigEndian>()?;
        trace!("Parsed key tag -> {:?}", key_tag);

        let algorithm = c.read_u8()?;
        trace!("Parsed algorithm -> {:?}", algorithm);

        let digest_type = c.read_u8()?;
        trace!("Parsed digest type -> {:?}", digest_type);

        let digest_length = stated_length - 4;
        let mut digest = vec![0_u8; usize::from(digest_length)];
        c.read_exact(&mut digest)?;
        trace!("Parsed digest -> {:#x?}", digest);

        Ok(Self { key_tag, algorithm, digest_type, digest })
    }
}

impl DS {

    /// Returns the hexadecimal representation of the digest.
    pub fn hex_digest(&self) -> String {
        self.digest.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }

    /// Returns a human-readable name for the algorithm number, if known.
    pub fn algorithm_name(&self) -> Option<&'static str> {
        match self.algorithm {
            1 => Some("RSAMD5"),
            3 => Some("DSA"),
            5 => Some("RSASHA1"),
            6 => Some("DSA-NSEC3-SHA1"),
            7 => Some("RSASHA1-NSEC3-SHA1"),
            8 => Some("RSASHA256"),
            10 => Some("RSASHA512"),
            12 => Some("ECC-GOST"),
            13 => Some("ECDSAP256SHA256"),
            14 => Some("ECDSAP384SHA384"),
            15 => Some("ED25519"),
            16 => Some("ED448"),
            _ => None,
        }
    }

    /// Returns a human-readable name for the digest type, if known.
    pub fn digest_type_name(&self) -> Option<&'static str> {
        match self.digest_type {
            1 => Some("SHA-1"),
            2 => Some("SHA-256"),
            3 => Some("GOST R 34.11-94"),
            4 => Some("SHA-384"),
            _ => None,
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x9F, 0x0A,  // key tag (40714)
            0x0D,        // algorithm (13 = ECDSAP256SHA256)
            0x02,        // digest type (2 = SHA-256)
            0xAA, 0xBB, 0xCC, 0xDD,  // digest (abbreviated)
        ];

        assert_eq!(DS::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   DS {
                       key_tag: 40714,
                       algorithm: 13,
                       digest_type: 2,
                       digest: vec![ 0xAA, 0xBB, 0xCC, 0xDD ],
                   });
    }

    #[test]
    fn parses_sha1() {
        let buf = &[
            0x00, 0x01,  // key tag (1)
            0x08,        // algorithm (8 = RSASHA256)
            0x01,        // digest type (1 = SHA-1)
            0x11, 0x22,  // digest
        ];

        assert_eq!(DS::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   DS {
                       key_tag: 1,
                       algorithm: 8,
                       digest_type: 1,
                       digest: vec![ 0x11, 0x22 ],
                   });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x00, 0x01,  // key tag
            0x0D,        // algorithm
            0x02,        // digest type, but no digest
        ];

        assert_eq!(DS::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 4, mandated_length: MandatedLength::AtLeast(5) }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(DS::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: MandatedLength::AtLeast(5) }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00, 0x01,  // key tag
        ];

        assert_eq!(DS::read(8, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }

    #[test]
    fn hex_rep() {
        let ds = DS {
            key_tag: 40714,
            algorithm: 13,
            digest_type: 2,
            digest: vec![ 0xf3, 0x48, 0xcd, 0xc9 ],
        };

        assert_eq!(ds.hex_digest(),
                   String::from("f348cdc9"));
    }

    #[test]
    fn known_algorithm_name() {
        let ds = DS { key_tag: 0, algorithm: 13, digest_type: 2, digest: vec![] };
        assert_eq!(ds.algorithm_name(), Some("ECDSAP256SHA256"));
    }

    #[test]
    fn known_digest_type_name() {
        let ds = DS { key_tag: 0, algorithm: 13, digest_type: 2, digest: vec![] };
        assert_eq!(ds.digest_type_name(), Some("SHA-256"));
    }

    #[test]
    fn unknown_algorithm_name() {
        let ds = DS { key_tag: 0, algorithm: 99, digest_type: 2, digest: vec![] };
        assert_eq!(ds.algorithm_name(), None);
    }

    #[test]
    fn unknown_digest_type_name() {
        let ds = DS { key_tag: 0, algorithm: 13, digest_type: 99, digest: vec![] };
        assert_eq!(ds.digest_type_name(), None);
    }
}
