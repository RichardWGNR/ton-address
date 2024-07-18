[![Build](https://github.com/RichardWGNR/ton-address/actions/workflows/build.yml/badge.svg)](https://github.com/RichardWGNR/ton-address/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/RichardWGNR/ton-address/branch/main/graph/badge.svg?token=3SY0TC20SX)](https://codecov.io/gh/RichardWGNR/ton-address)

A simple library for working with addresses on The Open Network (TON).

## Examples

### Parse address

```rust
use ton_address::{Address, ParseError, Base64Decoder};

fn main() {
    // 1. Parse the address in any form via ::parse().
    let result: Result<Address, ParseError> = "EQAOl3l3CEEcKaPLHz+BDvT4P0HZkIOPf5POcILE/5qgJuR2".parse();
    
    // 2. Parse only from base64 with alphabet guessing.
    let result: Result<Address, ParseError> = Address::from_base64(
        "EQAOl3l3CEEcKaPLHz+BDvT4P0HZkIOPf5POcILE/5qgJuR2",
        None // Means that Base64 type will be guessed
    );

    // 3. Parse the address only from base64 using the standard alphabet.
    //    
    //    Note, in this example if the address is encoded in the UrlSafe
    //    alphabet, the method will return an error.
    let result: Result<Address, ParseError> = Address::from_base64(
        "EQAOl3l3CEEcKaPLHz+BDvT4P0HZkIOPf5POcILE/5qgJuR2",
        Some(Base64Decoder::Standard) // or ::UrlSafe alphabet
    );
}
```

### Format address
```rust
use ton_address::{Address, ParseError, Base64Encoder, BASE64_STD_DEFAULT, BASE64_URL_DEFAULT};

fn main() {
    let result: Address = "EQAOl3l3CEEcKaPLHz+BDvT4P0HZkIOPf5POcILE/5qgJuR2"
        .parse()
        .unwrap();
    
    // Manual control of Base64 encoding
    println!("{}", result.to_base64(Base64Encoder::Standard {
        bounceable: false,
        production: true,
    })); // UQAOl3l3CEEcKaPLHz+BDvT4P0HZkIOPf5POcILE/5qg....

    // Constants for fast conversion (bounceable & production by default)
    println!("{}", result.to_base64(BASE64_STD_DEFAULT)); // EQAOl3l3CEEcKaPLHz-BDvT4P0HZkIOPf5POcILE_5qgJuR2
    println!("{}", result.to_base64(BASE64_URL_DEFAULT)); // EQAOl3l3CEEcKaPLHz+BDvT4P0HZkIOPf5POcILE/5qgJuR2

    // Or convert it to a raw address
    println!("{}", result.to_raw_address()); // 0:...
}
```