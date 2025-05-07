# PQ Address Rust

A Rust library for encoding and decoding post‑quantum public keys into human‑friendly Bech32m addresses.

## Motivation

Sharing a post‑quantum public key needs:

1. A **hash** of the public key for privacy and fixed length.
2. A strong **checksum** to catch typos and errors.
3. A readable, typo‑resistant **encoding**.
4. A clear **network flag** (production vs development).

`pq_address` provides all four. It lets you generate and parse addresses for any public‑key type (ML‑DSA, SLH‑DSA, etc.), while guaranteeing future‑proof safety.

## Design & Justification

- **Bech32m** (BIP‑350)

  - Case insensitive
  - Friendly character set
  - Strong error detection
  - Improved checksum over Bech32
  - Efficient encoding & decoding
  - Smaller QR codes due to use of alphanumeric mode

- **Disjoint byte ranges**

  - Version codes in `0x00–0x3F` (up to 64 versions).
  - PubKeyType codes in `0x40–0xFF` (up to 192 public key types).
  - Any byte‑swap or mis‑read triggers a clear “unknown code” error.

  By carving out non-overlapping slots for versions (0x00–0x3F) and public key types (0x40–0xFF), parsing becomes trivial—and any stray or swapped byte instantly flags itself as an “unknown code,” preventing silent failures.

- **HRP flag**

  - `"yp"` for production/mainnet, `"rh"` for development/testnet.

- **Extendable**

  - Add new `PubKeyType` variants without breaking old addresses.

## Anatomy of a PQ address

Address example: `yp1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hs5cdx7q`

1. **HRP** (`yp` / `rh`)

   - `yp` = Mainnet
   - `rh` = Testnet

2. **Separator**

   - Always the character `1`.

3. **Data**

   - The payload bytes:
     1. Version
     2. PubKeyType
     3. Raw pubkey hash digest
   - Converted into 5-bit words and then into Bech32 characters.

4. **Checksum**
   - 6 Bech32 characters (BIP-350)
   - Catches typos and bit-errors.

PQ address length is 64 characters.

Note: A Bech32 string is at most 90 characters long [BIP-173]

## A Note on Hash Algorithms

The default hash function for `pq_address` is SHA-256.
256 bit hash functions are currently considered secure against Grover's attack.
Even if the preimage is recovered, it only reveals a PQ secure public key and thus Shor's is not applicable.

## Quickstart

Add to your `Cargo.toml`:

```bash
cargo add pq_address
```

Import `pq_address`

```rust
use pq_address::{
    AddressDecodeError, AddressParams, Network, PubKeyType, Version, decode_address,
    encode_address,
};
```

Encoding

```rust
let params = AddressParams {
    network: Network::Mainnet,
    version: Version::V1,
    pubkey_type: PubKeyType::MlDsa44,
    pubkey_bytes: <PUB_KEY_BYTES>,
};

match encode_address(&params) {
    Ok(pq_addr) => println!("Encoded PQ Address: {}", pq_addr),
    Err(e) => eprintln!("Encoding error: {}", e),
}
```

Decoding

```rust
match decode_address(&pq_addr) {
    Ok(decoded) => {
        println!("Decoded Network: {:?}", decoded.network);
        println!("Decoded Version: {:?}", decoded.version);
        println!("Decoded PubKey Type: {:?}", decoded.pubkey_type);
        println!("Decoded PubKey Hash (hex): {}", decoded.pubkey_hash_hex());
    }
    Err(e) => eprintln!("Decoding error: {}", e),
};
```

## Errors

Encoding errors:

```rust
enum AddressEncodeError {
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
```

Decoding errors:

```rust
enum AddressDecodeError {
    /// Invalid Bech32 structure or checksum
    #[error("Bech32 error: {0}")]
    Bech32(#[from] bech32::DecodeError),

    /// HRP wasn’t `yp` or `rh`
    #[error("unknown HRP: {0}")]
    UnknownHrp(String),

    /// Payload too short
    #[error("payload too short (need at least version+public key type)")]
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
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
