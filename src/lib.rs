//! A Bech32m address encoder/decoder for PQC public keys.
//!
//! This crate supports:
//! - Mainnet vs Testnet via HRP.
//! - Disjoint byte ranges for version, hash algorithm, and pubkey type.
//! - Support for multiple hash algorithms and PQC public keys.
//! - Full encode/decode round‑trip with Bech32m checksum per BIP‑350.

use bech32::{Bech32m, Hrp, decode, encode};
use hex::encode as hex_encode;
use sha2::{Digest as ShaDigest, Sha256};
use std::convert::TryFrom;
use thiserror::Error;

/// A Bech32 string is at most 90 characters long [BIP-173]
const MAX_ADDRESS_LENGTH: usize = 90;

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
/// Codes are in the range `0x00..=0x1F` (32 total slots):
/// - `0x00` = V1
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Version {
    /// V1
    V1,
}

impl Version {
    /// Byte code to embed in the payload.
    ///
    /// Reserved range: 0x00..=0x1F (up to 32 versions).
    pub fn code(self) -> u8 {
        match self {
            Version::V1 => 0x00,
        }
    }

    /// Reverse lookup from byte code to enum.
    pub fn from_code(code: u8) -> Option<Version> {
        match code {
            0x00 => Some(Version::V1),
            _ => None,
        }
    }
}

/// Supported hash algorithms.
///
/// Codes are in the range `0x20..=0x3F` (32 total slots):
/// - `0x20` = SHA2-256
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HashAlgorithm {
    /// SHA2-256, 32-byte output.
    SHA2_256,
}

impl HashAlgorithm {
    /// Byte code to embed in the payload.
    ///
    /// Reserved range: 0x20..=0x3F (up to 32 algorithms).
    pub fn code(self) -> u8 {
        match self {
            HashAlgorithm::SHA2_256 => 0x20,
        }
    }

    /// Reverse lookup from byte code to enum.
    pub fn from_code(code: u8) -> Option<HashAlgorithm> {
        match code {
            0x20 => Some(HashAlgorithm::SHA2_256),
            _ => None,
        }
    }

    /// Expected digest length in bytes.
    pub fn digest_length(self) -> usize {
        match self {
            HashAlgorithm::SHA2_256 => 32,
        }
    }

    /// Compute the hash of the given data.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::SHA2_256 => {
                let mut h = Sha256::new();
                h.update(data);
                h.finalize().to_vec()
            }
        }
    }
}

/// Supported public-key types.
///
/// Codes are in the range `0x40..=0xFF` (192 total slots),
/// giving us plenty of room for future PQC schemes:
/// - `0x40` = ML-DSA 65
/// - `0x41` = ML-DSA 87
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PubKeyType {
    /// ML-DSA 65 public key.
    MLDSA65,
    /// ML-DSA 87 public key.
    MLDSA87,
}

impl PubKeyType {
    /// Byte code to embed in the payload.
    ///
    /// Reserved range: 0x40..=0xFF (up to 192 public key types).
    pub fn code(self) -> u8 {
        match self {
            PubKeyType::MLDSA65 => 0x40,
            PubKeyType::MLDSA87 => 0x41,
        }
    }

    /// Reverse lookup from byte code to enum.
    pub fn from_code(code: u8) -> Option<PubKeyType> {
        match code {
            0x40 => Some(PubKeyType::MLDSA65),
            0x41 => Some(PubKeyType::MLDSA87),
            _ => None,
        }
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
    /// Which hash algorithm to use
    pub hash_alg: HashAlgorithm,
    /// Raw public‑key bytes
    pub pubkey_bytes: &'a [u8],
}

/// Errors that can occur during address encoding.
#[derive(Error, Debug)]
pub enum AddressEncodeError {
    /// Invalid Bech32 structure or checksum
    #[error("Bech32 error: {0}")]
    Bech32(#[from] bech32::EncodeError),

    /// A Bech32 string is at most 90 characters long [BIP-173]
    #[error("A Bech32 string is at most 90 characters long: got {0}")]
    InvalidEncodingLength(usize),
}

/// Encodes a Bech32m address from given params.
///
/// # Errors
/// Returns a `bech32::EncodeError` if the encode step fails.
pub fn encode_address(params: &AddressParams) -> Result<String, AddressEncodeError> {
    // Hash the public key
    let digest = params.hash_alg.digest(params.pubkey_bytes);

    // Build the raw payload:
    //  [ version.code(), pubkey_type.code(), hash_alg.code(), digest bytes… ]
    let mut payload = Vec::with_capacity(3 + digest.len());
    payload.push(params.version.code());
    payload.push(params.pubkey_type.code());
    payload.push(params.hash_alg.code());
    payload.extend(&digest);

    // Bech32m‑encode (adds the 6‑word checksum)
    let encoded = encode::<Bech32m>(params.network.hrp(), &payload)?;

    if encoded.len() > MAX_ADDRESS_LENGTH {
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
    /// Which hash algorithm
    pub hash_alg: HashAlgorithm,
    /// The raw public key hash bytes
    pub pubkey_hash: Vec<u8>,
}

impl DecodedAddress {
    /// The raw public key hash bytes
    pub fn pubkey_hash_bytes(&self) -> &[u8] {
        &self.pubkey_hash
    }

    /// The hex representation of the public key hash
    pub fn pubkey_hash_hex(&self) -> String {
        hex_encode(&self.pubkey_hash)
    }
}

/// Errors that can occur during address decoding.
#[derive(Error, Debug)]
pub enum AddressDecodeError {
    /// Invalid Bech32 structure or checksum
    #[error("Bech32 error: {0}")]
    Bech32(#[from] bech32::DecodeError),

    /// HRP wasn’t `ml` or `tl`
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

    /// Third byte isn’t a known hash algorithm
    #[error("unknown hash algorithm code: 0x{0:02X}")]
    UnknownHashAlg(u8),

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

    // Parse hash algorithm code
    let h = bytes[2];
    let hash_alg = HashAlgorithm::from_code(h).ok_or(AddressDecodeError::UnknownHashAlg(h))?;

    // Extract and verify digest length
    let pubkey_hash = bytes[3..].to_vec();
    let expected = hash_alg.digest_length();
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
        hash_alg,
        pubkey_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round‑trip test on Mainnet with SHA‑256 + ML‑DSA_65
    #[test]
    fn roundtrip_mainnet_sha256_mldsa_65() {
        let key = b"hello";
        let params = AddressParams {
            network: Network::Mainnet,
            version: Version::V1,
            pubkey_type: PubKeyType::MLDSA65,
            hash_alg: HashAlgorithm::SHA2_256,
            pubkey_bytes: key,
        };
        let addr = encode_address(&params).unwrap();
        assert!(addr.starts_with("yp"));
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.network, params.network);
        assert_eq!(decoded.version, params.version);
        assert_eq!(decoded.pubkey_type, params.pubkey_type);
        assert_eq!(decoded.hash_alg, params.hash_alg);
        assert_eq!(decoded.pubkey_hash, params.hash_alg.digest(key));
        assert_eq!(decoded.pubkey_hash_bytes(), params.hash_alg.digest(key));
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hash = hasher.finalize().to_vec();
        assert_eq!(decoded.pubkey_hash_hex(), hex_encode(&hash));
        assert_eq!(decoded.pubkey_hash, hash);
        assert_eq!(decoded.pubkey_hash_bytes(), hash);
    }

    /// Round‑trip test on Testnet with Sha256 + ML_DSA_87
    #[test]
    fn roundtrip_testnet_sha256_ml_dsa_87() {
        let key = b"world";
        let params = AddressParams {
            network: Network::Testnet,
            version: Version::V1,
            pubkey_type: PubKeyType::MLDSA87,
            hash_alg: HashAlgorithm::SHA2_256,
            pubkey_bytes: key,
        };
        let addr = encode_address(&params).unwrap();
        assert!(addr.starts_with("rh"));
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.network, params.network);
        assert_eq!(decoded.version, params.version);
        assert_eq!(decoded.pubkey_type, params.pubkey_type);
        assert_eq!(decoded.hash_alg, params.hash_alg);
        assert_eq!(decoded.pubkey_hash, params.hash_alg.digest(key));
        assert_eq!(decoded.pubkey_hash_bytes(), params.hash_alg.digest(key));
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hash = hasher.finalize().to_vec();
        assert_eq!(decoded.pubkey_hash_hex(), hex_encode(&hash));
        assert_eq!(decoded.pubkey_hash, hash);
        assert_eq!(decoded.pubkey_hash_bytes(), hash);
    }
}
