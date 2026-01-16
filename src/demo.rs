use pq_address::{Address, Network, PubKeyType};

/// Converts a hex public key string into a PQ-Address string.
pub fn hex_to_pq_address(hex_key: &str) -> Result<String, String> {
    // 1. Decode the hex string into bytes
    let bytes = hex::decode(hex_key).map_err(|e| e.to_string())?;

    // 2. Create the address (using ML-DSA type 0x40)
    let addr = Address::new(
        Network::Mainnet,
        PubKeyType::from_u8(0x40).unwrap(),
        &bytes,
    );

    // 3. Return as string
    Ok(addr.to_string())
}
