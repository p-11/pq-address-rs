use pq_address::{
    AddressDecodeError, AddressEncodeError, AddressParams, Network, PubKeyType, Version,
    decode_address, encode_address,
};

fn main() {
    let params = AddressParams {
        network: Network::Mainnet,
        version: Version::V1,
        pubkey_type: PubKeyType::MLDSA44,
        pubkey_bytes: b"hello world!",
    };

    let pq_addr = match encode_address(&params) {
        Ok(pq_addr) => pq_addr,
        // Bech32‐level errors
        Err(AddressEncodeError::Bech32(e)) => {
            eprintln!("Encoding error: {e}");
            std::process::exit(1);
        }
        Err(AddressEncodeError::InvalidEncodingLength(e)) => {
            eprintln!("Invalid encoding length: {e}");
            std::process::exit(1);
        }
    };
    println!("Encoded Address          : {pq_addr}");

    match decode_address(&pq_addr) {
        Ok(decoded) => {
            println!("Decoded Network          : {:?}", decoded.network);
            println!("Decoded Version          : {:?}", decoded.version);
            println!("Decoded PubKey Type      : {:?}", decoded.pubkey_type);
            println!("Decoded PubKey Hash (hex): {}", decoded.pubkey_hash_hex());
        }

        // Bech32‐level (format/checksum) errors
        Err(AddressDecodeError::Bech32(e)) => {
            eprintln!("Bech32 decoding error: {e}");
        }
        // Unrecognized Human-Readable Part (HRP)
        Err(AddressDecodeError::UnknownHrp(hrp)) => {
            eprintln!("Unknown HRP “{hrp}”");
        }
        // Payload was too short to contain version/pub key type/hash alg + digest
        Err(AddressDecodeError::TooShort) => {
            eprintln!("Payload too short");
        }
        // First byte didn’t map to a known Version
        Err(AddressDecodeError::UnknownVersion(code)) => {
            eprintln!("Unknown version code: 0x{code:02X}");
        }
        // Second byte didn’t map to a known PubKeyType
        Err(AddressDecodeError::UnknownPubKeyType(code)) => {
            eprintln!("Unknown pubkey type code: 0x{code:02X}");
        }
        // Digest length didn’t match the algorithm’s expected size
        Err(AddressDecodeError::InvalidHashLength { got, expected }) => {
            eprintln!("Invalid hash length: got {got} bytes, expected {expected}");
        }
    }
}
