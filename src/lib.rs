//! A Bech32m address encoder/decoder for PQC public keys.
//!
//! This crate supports:
//! - Mainnet vs Testnet via HRP.
//! - Disjoint byte ranges for version and pubkey type.
//! - Support for multiple PQC public keys.
//! - Full encode/decode round‑trip with Bech32m checksum per BIP‑350.

use bech32::{Bech32m, Hrp, decode, encode};
use hex::encode as hex_encode;
use sha2::{Digest as ShaDigest, Sha256};
use std::convert::TryFrom;
use std::fmt;
use thiserror::Error;

/// A Bech32 string is at most 90 characters long [BIP-173]
/// PQ address length is 64 characters.
const ADDRESS_LENGTH: usize = 64;

/// Which network you’re on.
///
/// This determines the human‑readable part (HRP) of the Bech32m address.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Network {
    /// Mainnet addresses use `yp…`
    Mainnet,
    /// Testnet addresses use `rh…`
    Testnet,
}

impl Network {
    /// Returns the Bech32m HRP for this network.
    ///
    /// # Panics
    ///
    /// This will panic if the hard-coded HRP literal fails to parse.
    /// In practice `"yp"` and `"rh"` are spec-defined and known to be valid given `try_from`,
    /// so this only ever fires if there’s a bug in this code or in `Hrp::parse`.
    #[must_use]
    pub fn hrp(self) -> Hrp {
        match self {
            Network::Mainnet => Hrp::parse("yp").expect("Mainnet HRP is valid"),
            Network::Testnet => Hrp::parse("rh").expect("Testnet HRP is valid"),
        }
    }
}

/// Attempts to parse a network from a string.
impl TryFrom<&str> for Network {
    type Error = AddressDecodeError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "yp" => Ok(Network::Mainnet),
            "rh" => Ok(Network::Testnet),
            other => Err(AddressDecodeError::UnknownHrp(other.to_string())),
        }
    }
}

/// Address format version.
///
/// Codes are in the range `0x00..=0x3F` (64 total slots):
/// - `0x00` = V1
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Version {
    /// V1
    V1,
}

impl Version {
    /// Byte code to embed in the payload.
    ///
    /// Reserved range: 0x00..=0x3F (up to 64 versions).
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Version::V1 => 0x00,
        }
    }

    /// Reverse lookup from byte code to enum.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Version> {
        match code {
            0x00 => Some(Version::V1),
            _ => None,
        }
    }
}

/// Supported public-key types.
///
/// Codes are in the range `0x40..=0xFF` (192 total slots),
/// giving us plenty of room for future PQC schemes:
/// - `0x40` = ML-DSA 44
/// - `0x41` = SLH-DSA SHA2 128 S
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PubKeyType {
    /// ML-DSA 44 public key.
    MlDsa44,
    /// SLH-DSA-SHA2 128 s public key.
    SlhDsaSha2S128,
}

impl PubKeyType {
    /// Byte code to embed in the payload.
    ///
    /// Reserved range: 0x40..=0xFF (up to 192 public key types).
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            PubKeyType::MlDsa44 => 0x40,
            PubKeyType::SlhDsaSha2S128 => 0x41,
        }
    }

    /// Reverse lookup from byte code to enum.
    #[must_use]
    pub fn from_code(code: u8) -> Option<PubKeyType> {
        match code {
            0x40 => Some(PubKeyType::MlDsa44),
            0x41 => Some(PubKeyType::SlhDsaSha2S128),
            _ => None,
        }
    }

    /// Returns the public‐key length in bytes for this algorithm.
    #[must_use]
    pub fn pubkey_length(self) -> usize {
        match self {
            PubKeyType::MlDsa44 => 1312,
            PubKeyType::SlhDsaSha2S128 => 32,
        }
    }
}

/// The default hash function for `pq_address`: SHA-256.
///
/// 256 bit hash function is currently considered secure against Grover's attack.
/// Even if the preimage is recovered, it only reveals a PQ secure public key and thus Shor's is not applicable.
pub struct Hasher;

impl Hasher {
    /// SHA-256 digest length (bytes).
    pub const DIGEST_LENGTH: usize = 32;

    /// Compute SHA-256(data).
    #[must_use]
    pub fn digest(data: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().to_vec()
    }
}

/// Parameters needed to encode an address.
pub struct AddressParams<'a> {
    /// Mainnet vs Testnet
    pub network: Network,
    /// Which address version
    pub version: Version,
    /// Which public‑key type
    pub pubkey_type: PubKeyType,
    /// Raw public‑key bytes
    pub pubkey_bytes: &'a [u8],
}

/// Errors that can occur during address encoding.
#[derive(Error, Debug)]
pub enum AddressEncodeError {
    /// Invalid Bech32 structure or checksum
    #[error("Bech32 error: {0}")]
    Bech32(#[from] bech32::EncodeError),

    /// A PQ address is 64 characters long
    #[error("A PQ address is 64 characters long: got {0}")]
    InvalidEncodingLength(usize),

    /// Invalid public key length
    #[error("Invalid public key length: expected {0}, got {1}")]
    InvalidPubKeyLength(usize, usize),
}

/// Encodes a Bech32m address from given params.
///
/// # Errors
/// Returns a `bech32::EncodeError` if the encode step fails.
pub fn encode_address(params: &AddressParams) -> Result<String, AddressEncodeError> {
    // Check pubkey length
    let expected_pubkey_length = params.pubkey_type.pubkey_length();
    if expected_pubkey_length != params.pubkey_bytes.len() {
        return Err(AddressEncodeError::InvalidPubKeyLength(
            expected_pubkey_length,
            params.pubkey_bytes.len(),
        ));
    }

    // Hash the public key
    let digest = Hasher::digest(params.pubkey_bytes);

    // Build the raw payload:
    //  [ version.code(), pubkey_type.code(), digest bytes… ]
    let mut payload = Vec::with_capacity(2 + digest.len());
    payload.push(params.version.code());
    payload.push(params.pubkey_type.code());
    payload.extend(&digest);

    // Bech32m‑encode (adds the 6‑word checksum)
    let hrp = params.network.hrp();
    let encoded = encode::<Bech32m>(hrp, &payload)?;

    if encoded.len() != ADDRESS_LENGTH {
        return Err(AddressEncodeError::InvalidEncodingLength(encoded.len()));
    }

    Ok(encoded)
}

/// The decoded components of a Bech32m address.
#[derive(Debug)]
pub struct DecodedAddress {
    /// Which network (from the HRP)
    pub network: Network,
    /// Which address version
    pub version: Version,
    /// Which public‑key type
    pub pubkey_type: PubKeyType,
    /// The raw public key hash bytes
    pub pubkey_hash: Vec<u8>,
}

impl DecodedAddress {
    /// The raw public key hash bytes
    #[must_use]
    pub fn pubkey_hash_bytes(&self) -> &[u8] {
        &self.pubkey_hash
    }

    /// The hex representation of the public key hash
    #[must_use]
    pub fn pubkey_hash_hex(&self) -> String {
        hex_encode(&self.pubkey_hash)
    }
}

impl fmt::Display for DecodedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // rebuild the raw payload: [ version, pubkey_type, hash… ]
        let mut payload = Vec::with_capacity(2 + self.pubkey_hash.len());
        payload.push(self.version.code());
        payload.push(self.pubkey_type.code());
        payload.extend(&self.pubkey_hash);

        // hrp() gives the correct prefix for Mainnet/Testnet
        let hrp = self.network.hrp();

        // re-encode as Bech32m; map any encode error to fmt::Error
        let s = encode::<Bech32m>(hrp, &payload).map_err(|_| fmt::Error)?;
        write!(f, "{s}")
    }
}

/// Errors that can occur during address decoding.
#[derive(Error, Debug)]
pub enum AddressDecodeError {
    /// Invalid Bech32 structure or checksum
    #[error("Bech32 error: {0}")]
    Bech32(#[from] bech32::DecodeError),

    /// HRP wasn’t `yp` or `rh`
    #[error("unknown HRP: {0}")]
    UnknownHrp(String),

    /// Payload too short
    #[error("payload too short (need at least version+public key type+hash algorithm)")]
    TooShort,

    /// First byte isn’t a known version code
    #[error("unknown version code: 0x{0:02X}")]
    UnknownVersion(u8),

    /// Second byte isn’t a known public key type
    #[error("unknown public key type code: 0x{0:02X}")]
    UnknownPubKeyType(u8),

    /// Digest length didn’t match the algorithm’s expectation
    #[error("invalid digest length: got {got}, expected {expected}")]
    InvalidHashLength { got: usize, expected: usize },
}

/// Decode a Bech32m address string back into its parts.
///
/// # Errors
/// Returns `AddressDecodeError` on any failure:
/// - Bad checksum or format
/// - Unknown HRP
/// - Invalid payload length
/// - Unrecognized version, public key type or hash algorithm codes
/// - Digest length mismatch
pub fn decode_address(s: &str) -> Result<DecodedAddress, AddressDecodeError> {
    // Decode Bech32
    let (hrp, bytes) = decode(s)?;

    // Map HRP to network enum
    let network = Network::try_from(hrp.as_str())?;

    // Validate minimum length for version + public key type + hash algorithm
    if bytes.len() < 3 {
        return Err(AddressDecodeError::TooShort);
    }

    // Parse version code
    let v = bytes[0];
    let version = Version::from_code(v).ok_or(AddressDecodeError::UnknownVersion(v))?;

    // Parse public key type code
    let p = bytes[1];
    let pubkey_type = PubKeyType::from_code(p).ok_or(AddressDecodeError::UnknownPubKeyType(p))?;

    // Extract and verify digest length
    let pubkey_hash = bytes[2..].to_vec();
    let expected = Hasher::DIGEST_LENGTH;
    if pubkey_hash.len() != expected {
        return Err(AddressDecodeError::InvalidHashLength {
            got: pubkey_hash.len(),
            expected,
        });
    }

    Ok(DecodedAddress {
        network,
        version,
        pubkey_type,
        pubkey_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose};

    /// Round‑trip test on Mainnet with SHA‑256 + `ML‑DSA 44`
    #[test]
    fn roundtrip_mainnet_mldsa_44() {
        let ml_dsa_44_pub_key_str = "e+ffcul9XkuQCkiCEYX2ES6KMGJ9c7+Z0PFfhnJRckbaHzh4EH9hcEkUoFZ4gK2ta6/xPzgxB1yTT92wPZw8SmrK3DeLMz9mkst0IWkSzJ/TPPHRcSYJekO+CLV8k7uXsGSSoK4fbLqkX8leQFMCzjzRYg06zb3SD7iQwK3O8dP2WWLa9PkBMl1LECCBtTHrxoqyYtKopNbn3wICOOxI1jjTTL46AZnE6Vw2vQdLB/Qg59Pq6su8P3zEqBbsVPwPpT9ZbBNCHE+puWjdYnOfttj6DZ748CRHibQ9WTkH+VpxssIxU62nsYes/fV85nDozwddZggZoLfRsmSlG1Yz6h4m5hMMu9Nku9myTTw4UCiGSxZmad+yIjl7hh6J3wDaLMDA6SXajLSXTk2RwmnsEUlYs+uXS6Wj5wzg+bLQDQVMkU+doOf4vPTArf4uwzJdZ9Ghp8vjHd+rQgKjuo+Hy+HWz4JgvaQXlln+3yF0eY4/v01Bhe8BwVCbFZX8ts2Ay53gJmZEtsnXw3d5xedAMO9LJt4UqwovnmWCuApzAG9jyvG3Wxxe572E725S4vLtgnESzfrsD3wWo/A0oP+wk4oOFjhRDdVwHzwBDiHPhl43b/lt6omQuxK+xF0BJ77X/VhAoCx5zwIQ1GnmtXmP5xqx8f+e9ceFWNSxBPVKakKx/BveCxF1uOLc7DZUFLDVxRBURiF4BQX/670+FaYF2BWS3XtxfCqxaCz3F177qUev3pYuwpvSIj6WNSmU8uyxvibSzvYtA50gQtznTfteWja14B8AB+rgagz5nEzRzO7u1+QmxbdvEyBKvmWzNtnvsNqee4LhU9sl6rPdyUScmDrCPVLiPhrqY/sBVfxzX6z40suflYFPYU+fE6lApXnpyDB8he25DmnmPYTEsCq9d2uYaYTSBAgeir0qi9Jnjj/mcJ/3sNwwTlh7Tp6ahJlqWEUJ4myGxcHEesgWAeIrqJ6bhHTxP1n+do4ffry4CMcAjoAPAwYY0JUTYANy722LbOgiN+z5KUryC/MYjw/azOHFcpYjsGR60fARG03yVBgNBuD5okkmxtrAGdS4w85UDMAa/dwobUI5bdigFHP0Av6hHQ5uxeaxt1gAO53veGmA8aIOidhtZyHhlv+ANl9VYyZMOdPP1DjBTd8AQTIGR2JglmGzE8/00Ndx736MNdVzxNG0iKOvLlgl3cd1cEjW6hfC47juSDCgZTs9oPeo2mr1qvtak7zVd/yByjP9KHh0mjCi3cZDButaTe/oic4bdf24xQDtahSEJpAf49i9gzIpqxG92pyM7HRaVSvScFmCNnNKLJSDCeYw4+zlU+jawGKPjX6ebFDGFV1gNiPvkZdYd/5UXFwpHt5saj/Lgfoe/BtJWUx53TNkYlTNytflgV/ssFo8k9aYlIq2SDDKeZdlZexeNJOvhr8yntOQzLK6WWVONUgilTFNKX3+NQTmMR1LhA7VSP17+/3NjM0wEaz/JpKRoqMMvrgzl2A/6s019UMoT81hGXNtk9Ed8vxtdeNi1BC+SHWWyazundxXMQ4/gD7PnJXQJduz0QZ8quxRQZZTn+u+t1hKyMQikRKqephJaIQv9NLnKffPncEii9ukfRuLLCy7hPFuAho1Bfgi6rJMN0AxlX9URe6LB6vjLMNdTvWVqCHtBvay4scJg58my00razBF8BhQe7db+UJiv5JwADSJ2fwO/oooReksH3Sv1U4UOx5Y7kK8bbChFg==";

        let pub_key_bytes = general_purpose::STANDARD
            .decode(ml_dsa_44_pub_key_str)
            .expect("valid base64");

        let params = AddressParams {
            network: Network::Mainnet,
            version: Version::V1,
            pubkey_type: PubKeyType::MlDsa44,
            pubkey_bytes: &pub_key_bytes,
        };
        let addr = encode_address(&params).unwrap();
        assert_eq!(
            addr,
            "yp1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hs5cdx7q"
        );
        assert!(addr.starts_with("yp"));
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.network, params.network);
        assert_eq!(decoded.version, params.version);
        assert_eq!(decoded.pubkey_type, params.pubkey_type);
        assert_eq!(decoded.pubkey_hash, Hasher::digest(&pub_key_bytes));
        assert_eq!(decoded.pubkey_hash_bytes(), Hasher::digest(&pub_key_bytes));
        let mut hasher = Sha256::new();
        hasher.update(pub_key_bytes);
        let hash = hasher.finalize().to_vec();
        assert_eq!(decoded.pubkey_hash_hex(), hex_encode(&hash));
        assert_eq!(decoded.pubkey_hash, hash);
        assert_eq!(decoded.pubkey_hash_bytes(), hash);
        assert_eq!(
            decoded.to_string(),
            "yp1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hs5cdx7q"
        );
    }

    /// Round‑trip test on Testnet with `ML-DSA 44`
    #[test]
    fn roundtrip_testnet_mldsa_44() {
        let ml_dsa_44_pub_key_str = "e+ffcul9XkuQCkiCEYX2ES6KMGJ9c7+Z0PFfhnJRckbaHzh4EH9hcEkUoFZ4gK2ta6/xPzgxB1yTT92wPZw8SmrK3DeLMz9mkst0IWkSzJ/TPPHRcSYJekO+CLV8k7uXsGSSoK4fbLqkX8leQFMCzjzRYg06zb3SD7iQwK3O8dP2WWLa9PkBMl1LECCBtTHrxoqyYtKopNbn3wICOOxI1jjTTL46AZnE6Vw2vQdLB/Qg59Pq6su8P3zEqBbsVPwPpT9ZbBNCHE+puWjdYnOfttj6DZ748CRHibQ9WTkH+VpxssIxU62nsYes/fV85nDozwddZggZoLfRsmSlG1Yz6h4m5hMMu9Nku9myTTw4UCiGSxZmad+yIjl7hh6J3wDaLMDA6SXajLSXTk2RwmnsEUlYs+uXS6Wj5wzg+bLQDQVMkU+doOf4vPTArf4uwzJdZ9Ghp8vjHd+rQgKjuo+Hy+HWz4JgvaQXlln+3yF0eY4/v01Bhe8BwVCbFZX8ts2Ay53gJmZEtsnXw3d5xedAMO9LJt4UqwovnmWCuApzAG9jyvG3Wxxe572E725S4vLtgnESzfrsD3wWo/A0oP+wk4oOFjhRDdVwHzwBDiHPhl43b/lt6omQuxK+xF0BJ77X/VhAoCx5zwIQ1GnmtXmP5xqx8f+e9ceFWNSxBPVKakKx/BveCxF1uOLc7DZUFLDVxRBURiF4BQX/670+FaYF2BWS3XtxfCqxaCz3F177qUev3pYuwpvSIj6WNSmU8uyxvibSzvYtA50gQtznTfteWja14B8AB+rgagz5nEzRzO7u1+QmxbdvEyBKvmWzNtnvsNqee4LhU9sl6rPdyUScmDrCPVLiPhrqY/sBVfxzX6z40suflYFPYU+fE6lApXnpyDB8he25DmnmPYTEsCq9d2uYaYTSBAgeir0qi9Jnjj/mcJ/3sNwwTlh7Tp6ahJlqWEUJ4myGxcHEesgWAeIrqJ6bhHTxP1n+do4ffry4CMcAjoAPAwYY0JUTYANy722LbOgiN+z5KUryC/MYjw/azOHFcpYjsGR60fARG03yVBgNBuD5okkmxtrAGdS4w85UDMAa/dwobUI5bdigFHP0Av6hHQ5uxeaxt1gAO53veGmA8aIOidhtZyHhlv+ANl9VYyZMOdPP1DjBTd8AQTIGR2JglmGzE8/00Ndx736MNdVzxNG0iKOvLlgl3cd1cEjW6hfC47juSDCgZTs9oPeo2mr1qvtak7zVd/yByjP9KHh0mjCi3cZDButaTe/oic4bdf24xQDtahSEJpAf49i9gzIpqxG92pyM7HRaVSvScFmCNnNKLJSDCeYw4+zlU+jawGKPjX6ebFDGFV1gNiPvkZdYd/5UXFwpHt5saj/Lgfoe/BtJWUx53TNkYlTNytflgV/ssFo8k9aYlIq2SDDKeZdlZexeNJOvhr8yntOQzLK6WWVONUgilTFNKX3+NQTmMR1LhA7VSP17+/3NjM0wEaz/JpKRoqMMvrgzl2A/6s019UMoT81hGXNtk9Ed8vxtdeNi1BC+SHWWyazundxXMQ4/gD7PnJXQJduz0QZ8quxRQZZTn+u+t1hKyMQikRKqephJaIQv9NLnKffPncEii9ukfRuLLCy7hPFuAho1Bfgi6rJMN0AxlX9URe6LB6vjLMNdTvWVqCHtBvay4scJg58my00razBF8BhQe7db+UJiv5JwADSJ2fwO/oooReksH3Sv1U4UOx5Y7kK8bbChFg==";

        let pub_key_bytes = general_purpose::STANDARD
            .decode(ml_dsa_44_pub_key_str)
            .expect("valid base64");

        let params = AddressParams {
            network: Network::Testnet,
            version: Version::V1,
            pubkey_type: PubKeyType::MlDsa44,
            pubkey_bytes: &pub_key_bytes,
        };
        let addr = encode_address(&params).unwrap();
        assert_eq!(
            addr,
            "rh1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hsmmfzpd"
        );
        assert!(addr.starts_with("rh"));
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.network, params.network);
        assert_eq!(decoded.version, params.version);
        assert_eq!(decoded.pubkey_type, params.pubkey_type);
        assert_eq!(decoded.pubkey_hash, Hasher::digest(&pub_key_bytes));
        assert_eq!(decoded.pubkey_hash_bytes(), Hasher::digest(&pub_key_bytes));
        let mut hasher = Sha256::new();
        hasher.update(pub_key_bytes);
        let hash = hasher.finalize().to_vec();
        assert_eq!(decoded.pubkey_hash_hex(), hex_encode(&hash));
        assert_eq!(decoded.pubkey_hash, hash);
        assert_eq!(decoded.pubkey_hash_bytes(), hash);
        assert_eq!(
            decoded.to_string(),
            "rh1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hsmmfzpd"
        );
    }

    /// Round‑trip test on Mainnet with `SLH-DSA-SHA2 S 128`
    #[test]
    fn roundtrip_mainnet_slhdsa_sha2s128() {
        let slh_dsa_sha2s128_pub_key_str = "Wi6WLwN39BUnK7X4gkIG101E2zMZWNAVdOsrG8/IxN4=";

        let pub_key_bytes = general_purpose::STANDARD
            .decode(slh_dsa_sha2s128_pub_key_str)
            .expect("valid base64");

        let params = AddressParams {
            network: Network::Mainnet,
            version: Version::V1,
            pubkey_type: PubKeyType::SlhDsaSha2S128,
            pubkey_bytes: &pub_key_bytes,
        };
        let addr = encode_address(&params).unwrap();
        assert_eq!(
            addr,
            "yp1qpq3z7j5vfjd9y5vlc86al02ujud4tynj73rahcdaa9cdgu47matt5smc3rlz"
        );
        assert!(addr.starts_with("yp"));
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.network, params.network);
        assert_eq!(decoded.version, params.version);
        assert_eq!(decoded.pubkey_type, params.pubkey_type);
        assert_eq!(decoded.pubkey_hash, Hasher::digest(&pub_key_bytes));
        assert_eq!(decoded.pubkey_hash_bytes(), Hasher::digest(&pub_key_bytes));
        let mut hasher = Sha256::new();
        hasher.update(pub_key_bytes);
        let hash = hasher.finalize().to_vec();
        assert_eq!(decoded.pubkey_hash_hex(), hex_encode(&hash));
        assert_eq!(decoded.pubkey_hash, hash);
        assert_eq!(decoded.pubkey_hash_bytes(), hash);
        assert_eq!(
            decoded.to_string(),
            "yp1qpq3z7j5vfjd9y5vlc86al02ujud4tynj73rahcdaa9cdgu47matt5smc3rlz"
        );
    }

    /// Round‑trip test on Testnet with `SLH-DSA-SHA2 S 128`
    #[test]
    fn roundtrip_testnet_slhdsa_sha2s128() {
        let slh_dsa_sha2s128_pub_key_str = "Wi6WLwN39BUnK7X4gkIG101E2zMZWNAVdOsrG8/IxN4=";

        let pub_key_bytes = general_purpose::STANDARD
            .decode(slh_dsa_sha2s128_pub_key_str)
            .expect("valid base64");

        let params = AddressParams {
            network: Network::Testnet,
            version: Version::V1,
            pubkey_type: PubKeyType::SlhDsaSha2S128,
            pubkey_bytes: &pub_key_bytes,
        };
        let addr = encode_address(&params).unwrap();
        assert_eq!(
            addr,
            "rh1qpq3z7j5vfjd9y5vlc86al02ujud4tynj73rahcdaa9cdgu47matt5s5m48q0"
        );
        assert!(addr.starts_with("rh"));
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.network, params.network);
        assert_eq!(decoded.version, params.version);
        assert_eq!(decoded.pubkey_type, params.pubkey_type);
        assert_eq!(decoded.pubkey_hash, Hasher::digest(&pub_key_bytes));
        assert_eq!(decoded.pubkey_hash_bytes(), Hasher::digest(&pub_key_bytes));
        let mut hasher = Sha256::new();
        hasher.update(pub_key_bytes);
        let hash = hasher.finalize().to_vec();
        assert_eq!(decoded.pubkey_hash_hex(), hex_encode(&hash));
        assert_eq!(decoded.pubkey_hash, hash);
        assert_eq!(decoded.pubkey_hash_bytes(), hash);
        assert_eq!(
            decoded.to_string(),
            "rh1qpq3z7j5vfjd9y5vlc86al02ujud4tynj73rahcdaa9cdgu47matt5s5m48q0"
        );
    }
}
