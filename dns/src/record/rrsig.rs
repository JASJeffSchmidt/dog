use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;


/// An **RRSIG** _(resource record signature)_ record, which contains a
/// DNSSEC signature for an RRset. RRSIG records are used to authenticate
/// DNS data.
///
/// # References
///
/// - [RFC 4034 §3](https://tools.ietf.org/html/rfc4034#section-3) — Resource
///   Records for the DNS Security Extensions (March 2005)
#[derive(PartialEq, Debug)]
pub struct RRSIG {

    /// The type of the RRset that is covered by this signature.
    pub type_covered: u16,

    /// The algorithm number used to create the signature.
    pub algorithm: u8,

    /// The number of labels in the original owner name of the covered RRset.
    pub labels: u8,

    /// The TTL of the covered RRset as it appears in the authoritative zone.
    pub original_ttl: u32,

    /// The expiration time of the signature, as a Unix timestamp.
    pub signature_expiration: u32,

    /// The inception time of the signature, as a Unix timestamp.
    pub signature_inception: u32,

    /// A tag value to efficiently identify the DNSKEY used to verify this
    /// signature.
    pub key_tag: u16,

    /// The domain name of the zone that contains the signer's DNSKEY.
    pub signer_name: Labels,

    /// The cryptographic signature.
    pub signature: Vec<u8>,
}

impl Wire for RRSIG {
    const NAME: &'static str = "RRSIG";
    const RR_TYPE: u16 = 46;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        // Fixed fields before signer name: 2+1+1+4+4+4+2 = 18 bytes
        if stated_length < 19 {
            let mandated_length = MandatedLength::AtLeast(19);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let type_covered = c.read_u16::<BigEndian>()?;
        trace!("Parsed type covered -> {:?}", type_covered);

        let algorithm = c.read_u8()?;
        trace!("Parsed algorithm -> {:?}", algorithm);

        let labels = c.read_u8()?;
        trace!("Parsed labels -> {:?}", labels);

        let original_ttl = c.read_u32::<BigEndian>()?;
        trace!("Parsed original TTL -> {:?}", original_ttl);

        let signature_expiration = c.read_u32::<BigEndian>()?;
        trace!("Parsed signature expiration -> {:?}", signature_expiration);

        let signature_inception = c.read_u32::<BigEndian>()?;
        trace!("Parsed signature inception -> {:?}", signature_inception);

        let key_tag = c.read_u16::<BigEndian>()?;
        trace!("Parsed key tag -> {:?}", key_tag);

        let (signer_name, signer_name_length) = c.read_labels()?;
        trace!("Parsed signer name -> {:?}", signer_name);

        let signature_length = stated_length - 18 - signer_name_length;
        let mut signature = vec![0_u8; usize::from(signature_length)];
        c.read_exact(&mut signature)?;
        trace!("Parsed signature -> {:#x?}", signature);

        Ok(Self {
            type_covered, algorithm, labels, original_ttl,
            signature_expiration, signature_inception, key_tag,
            signer_name, signature,
        })
    }
}

impl RRSIG {

    /// Returns the base64-encoded signature.
    pub fn base64_signature(&self) -> String {
        base64::encode(&self.signature)
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

    /// Returns a human-readable name for the type covered, if it's a
    /// well-known record type.
    pub fn type_covered_name(&self) -> Option<&'static str> {
        match self.type_covered {
            1 => Some("A"),
            2 => Some("NS"),
            5 => Some("CNAME"),
            6 => Some("SOA"),
            12 => Some("PTR"),
            15 => Some("MX"),
            16 => Some("TXT"),
            28 => Some("AAAA"),
            33 => Some("SRV"),
            43 => Some("DS"),
            44 => Some("SSHFP"),
            46 => Some("RRSIG"),
            47 => Some("NSEC"),
            48 => Some("DNSKEY"),
            50 => Some("NSEC3"),
            51 => Some("NSEC3PARAM"),
            52 => Some("TLSA"),
            257 => Some("CAA"),
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
            0x00, 0x01,  // type covered (1 = A)
            0x0D,        // algorithm (13 = ECDSAP256SHA256)
            0x02,        // labels
            0x00, 0x00, 0x0E, 0x10,  // original TTL (3600)
            0x67, 0x8A, 0x1B, 0x80,  // signature expiration
            0x67, 0x68, 0x9C, 0x00,  // signature inception
            0x09, 0x43,  // key tag (2371)
            0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,  // "example"
            0x03, 0x63, 0x6F, 0x6D,  // "com"
            0x00,        // signer name terminator
            0xAA, 0xBB, 0xCC, 0xDD,  // signature (abbreviated)
        ];

        assert_eq!(RRSIG::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   RRSIG {
                       type_covered: 1,
                       algorithm: 13,
                       labels: 2,
                       original_ttl: 3600,
                       signature_expiration: 0x678A1B80,
                       signature_inception: 0x67689C00,
                       key_tag: 2371,
                       signer_name: Labels::encode("example.com").unwrap(),
                       signature: vec![ 0xAA, 0xBB, 0xCC, 0xDD ],
                   });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x00, 0x01,  // type covered
            0x0D,        // algorithm
            0x02,        // labels
            0x00, 0x00, 0x0E, 0x10,  // original TTL
            0x67, 0x8A, 0x1B, 0x80,  // signature expiration
            0x67, 0x68, 0x9C, 0x00,  // signature inception
            0x09, 0x43,  // key tag
            // missing signer name and signature
        ];

        assert_eq!(RRSIG::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 18, mandated_length: MandatedLength::AtLeast(19) }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(RRSIG::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: MandatedLength::AtLeast(19) }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00, 0x01,  // type covered
            0x0D,        // algorithm
        ];

        assert_eq!(RRSIG::read(30, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }

    #[test]
    fn base64_sig() {
        let rrsig = RRSIG {
            type_covered: 1,
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            signature_expiration: 0,
            signature_inception: 0,
            key_tag: 2371,
            signer_name: Labels::encode("example.com").unwrap(),
            signature: vec![ 0xAA, 0xBB, 0xCC, 0xDD ],
        };

        assert_eq!(rrsig.base64_signature(),
                   String::from("qrvM3Q=="));
    }

    #[test]
    fn known_algorithm_name() {
        let rrsig = RRSIG {
            type_covered: 1, algorithm: 13, labels: 2, original_ttl: 0,
            signature_expiration: 0, signature_inception: 0, key_tag: 0,
            signer_name: Labels::encode("example.com").unwrap(),
            signature: vec![],
        };
        assert_eq!(rrsig.algorithm_name(), Some("ECDSAP256SHA256"));
    }

    #[test]
    fn known_type_covered_name() {
        let rrsig = RRSIG {
            type_covered: 48, algorithm: 13, labels: 2, original_ttl: 0,
            signature_expiration: 0, signature_inception: 0, key_tag: 0,
            signer_name: Labels::encode("example.com").unwrap(),
            signature: vec![],
        };
        assert_eq!(rrsig.type_covered_name(), Some("DNSKEY"));
    }

    #[test]
    fn unknown_type_covered_name() {
        let rrsig = RRSIG {
            type_covered: 9999, algorithm: 13, labels: 2, original_ttl: 0,
            signature_expiration: 0, signature_inception: 0, key_tag: 0,
            signer_name: Labels::encode("example.com").unwrap(),
            signature: vec![],
        };
        assert_eq!(rrsig.type_covered_name(), None);
    }
}
