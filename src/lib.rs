#![forbid(unsafe_code)]

use std::fmt::{Display, Formatter};
use base64::prelude::{BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE_NO_PAD};
use base64::Engine;
use crc::Crc;
use std::str::FromStr;

pub type Workchain = i32;
pub type HashPart = [u8; 32];

/// A quick alias for converting an [`Address`] structure to
/// a Base64 Standard string representation of an address.
pub const BASE64_STD_DEFAULT: Base64Encoder = Base64Encoder::Standard {
    bounceable: true,
    production: true,
};

/// A quick alias for converting an [`Address`] structure to
/// a Base64 Url Safe string representation of an address.
pub const BASE64_URL_DEFAULT: Base64Encoder = Base64Encoder::UrlSafe {
    bounceable: true,
    production: true,
};

#[inline]
fn crc16(slice: &[u8]) -> u16 {
    Crc::<u16>::new(&crc::CRC_16_XMODEM).checksum(slice)
}

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("Error parsing TON address: {reason}")]
pub struct ParseError {
    pub address: String,
    pub reason: &'static str,
}

/// A decoder used to encrypt and decrypt Base64 addresses
/// on The Open Network (TON).
#[derive(Debug, PartialEq)]
pub enum Base64Decoder {
    /// [`STANDARD`]: base64::alphabet::STANDARD
    /// [`NO_PAD`]: base64::engine::general_purpose::NO_PAD
    ///
    /// Using the [`STANDARD`] base64 alphabet and [`NO_PAD`] config.
    Standard,

    /// [`URL_SAFE`]: base64::alphabet::URL_SAFE
    /// [`NO_PAD`]: base64::engine::general_purpose::NO_PAD
    ///
    /// Using the [`URL_SAFE`] base64 alphabet and [`NO_PAD`] config.
    UrlSafe,
}

impl Base64Decoder {
    /// Decodes a Base64 encoded string depending on the selected algorithm.
    #[inline]
    fn decode<'b: 'a, 'a>(&'a self, str: &'b str) -> Result<Vec<u8>, ParseError> {
        let res = match self {
            Self::Standard => BASE64_STANDARD_NO_PAD.decode(str),
            Self::UrlSafe => BASE64_URL_SAFE_NO_PAD.decode(str),
        };

        match res {
            Ok(v) => Ok(v),
            Err(_) => Err(ParseError {
                address: str.to_owned(),
                reason: "Invalid base64 address string: base64 decode error",
            }),
        }
    }

    /// Guesses the Base64 alphabet from the `str` argument.
    #[inline]
    fn guess(str: &str) -> Base64Decoder {
        if str.contains('+') || str.contains('/') {
            return Base64Decoder::Standard;
        } else if str.contains('-') || str.contains('_') {
            return Base64Decoder::UrlSafe;
        }

        // If there are no control characters in the encoded string,
        // then it is compatible with both types of alphabets.
        // So it's 100% safe.
        Base64Decoder::Standard
    }
}

/// An encoder that converts the Address structure to a Base64 string representation.
#[derive(Debug, Copy, Clone)]
pub enum Base64Encoder {
    Standard { bounceable: bool, production: bool },
    UrlSafe { bounceable: bool, production: bool },
}

impl Base64Encoder {
    fn encode(&self, workchain: Workchain, hash_part: &HashPart) -> String {
        let (bounceable, production) = match self {
            Self::Standard {
                bounceable,
                production,
            } => (bounceable, production),
            Self::UrlSafe {
                bounceable,
                production,
            } => (bounceable, production),
        };

        let mut buffer = [0u8; 36];

        buffer[0] = match (bounceable, production) {
            (true, true) => 0x11,
            (true, false) => 0x51,
            (false, true) => 0x91,
            (false, false) => 0xD1,
        };

        buffer[1] = (workchain & 0xFF) as u8;
        buffer[2..34].clone_from_slice(hash_part);

        let crc = crc16(&buffer[0..34]);

        buffer[34] = ((crc >> 8) & 0xFF) as u8;
        buffer[35] = (crc & 0xFF) as u8;

        match self {
            Self::Standard { .. } => BASE64_STANDARD_NO_PAD.encode(buffer),
            Self::UrlSafe { .. } => BASE64_URL_SAFE_NO_PAD.encode(buffer),
        }
    }
}

/// An intermediate structure that should not be used explicitly,
/// and represents the result of decoding an address through
/// the [`Address`] structure.
#[derive(Debug)]
pub struct EncoderResult {
    // TODO : eq
    address: Address,
    non_bounceable: bool,
    non_production: bool,
    #[allow(dead_code)]
    decoder: Base64Decoder,
}

impl EncoderResult {
    pub fn is_non_bounceable(&self) -> bool {
        self.non_bounceable
    }

    pub fn is_non_production(&self) -> bool {
        self.non_production
    }

    pub fn is_bounceable(&self) -> bool {
        !self.non_bounceable
    }

    pub fn is_production(&self) -> bool {
        !self.non_production
    }
}

impl PartialEq for EncoderResult {
    /// The logic of the comparison in this case is such that regardless of the bounceable and
    /// production, encoder flags, the result will be positive only if the workchain and
    /// hash_part of both addresses are equal.
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

/// A structure representing the internals of an address
/// in a Ton network.
///
/// Regardless of the address type, its `workchain` and `hash_part`
/// always remain the same.
#[derive(Debug, PartialEq)]
pub struct Address {
    // TODO : eq
    workchain: Workchain,
    hash_part: HashPart,
}

impl Address {
    /// Creates a new [`Address`] structure from workchain and hash_part.
    pub fn new(workchain: Workchain, hash_part: &HashPart) -> Self {
        Self {
            workchain,
            hash_part: *hash_part,
        }
    }

    /// Creates a new [`Address`] structure using the null values of workchain
    /// and hash_part.
    pub fn empty() -> Self {
        Self {
            workchain: 0,
            hash_part: [0u8; 32],
        }
    }

    /// Returns the number of the workchain.
    pub fn get_workchain(&self) -> i32 {
        self.workchain
    }

    /// Returns a reference to the hash part.
    pub fn get_hash_part(&self) -> &HashPart {
        &self.hash_part
    }

    /// Attempt to create an [`Address`] structure from the
    /// string representation of the raw address.
    pub fn from_raw_address(str: &str) -> Result<Self, ParseError> {
        let parts = str.split(':').collect::<Vec<&str>>();

        if parts.len() != 2 {
            return Err(ParseError {
                address: str.to_owned(),
                reason: "Invalid raw address string: wrong address format",
            });
        }

        let wc = match parts[0].parse::<i32>() {
            Ok(wc) => wc,
            Err(_) => {
                return Err(ParseError {
                    address: str.to_owned(),
                    reason: "Invalid raw address string: workchain number is not a 32-bit integer",
                });
            }
        };

        let hash_part = match hex::decode(parts[1]) {
            Ok(part) => part,
            Err(_) => {
                return Err(ParseError {
                    address: str.to_owned(),
                    reason: "Invalid raw address string: failed to decode hash part",
                });
            }
        };

        if hash_part.len() != 32 {
            return Err(ParseError {
                address: str.to_owned(),
                reason: "Invalid raw address string: hash part length must be 32 bytes",
            });
        }

        Ok(Self {
            workchain: wc,
            hash_part: hash_part.as_slice().try_into().expect(
                "checking for hash part length ensures that the slice is safely cast to an array",
            ),
        })
    }

    /// Decodes the base64 address of the Ton network into an [`Address`] structure.
    ///
    /// If the `encoder` argument is specified, the method decodes the address “strictly”
    /// according to the specified algorithm.
    /// Otherwise, the address algorithm will be guessed by the presence of base64 control
    /// characters.
    pub fn from_base64(
        address: &str,
        encoder: Option<Base64Decoder>,
    ) -> Result<EncoderResult, ParseError> {
        if address.len() != 48 {
            return Err(ParseError {
                address: address.to_owned(),
                reason: "Invalid base64 address string: length must be 48 characters",
            });
        }

        let encoder = encoder.unwrap_or_else(|| Base64Decoder::guess(address));
        let bytes = encoder.decode(address)?;

        if bytes.len() != 36 {
            return Err(ParseError {
                address: address.to_owned(),
                reason: "Invalid base64 address string: length of decoded bytes must be 36",
            });
        }

        let (non_production, non_bounceable) = match bytes[0] {
            0x11 => (false, false),
            0x51 => (false, true),
            0x91 => (true, false),
            0xD1 => (true, true),
            _ => {
                return Err(ParseError {
                    address: address.to_owned(),
                    reason: "Invalid base64 address string: invalid flag",
                });
            }
        };

        let workchain = bytes[1] as i32;

        let server_crc = crc16(&bytes[0..34]);
        let client_crc = ((bytes[34] as u16) << 8) | (bytes[35] as u16);

        if server_crc != client_crc {
            return Err(ParseError {
                address: address.to_owned(),
                reason: "Invalid base64 address string: CRC16 hashes do not match",
            });
        }

        let mut hash_part: HashPart = [0u8; 32];
        hash_part.clone_from_slice(&bytes[2..34]);

        Ok(EncoderResult {
            address: Address {
                workchain,
                hash_part,
            },
            non_bounceable,
            non_production,
            decoder: encoder,
        })
    }

    /// Converts the current structure to a string of the form “0:fa16bc...”
    /// also known as the “raw address”.
    pub fn to_raw_address(&self) -> String {
        format!("{}:{}", self.workchain, hex::encode(self.hash_part))
    }

    /// Converts the current structure to a Base64 string according to
    /// the specified preferences in the `encoder` argument.
    ///
    /// Use the [`BASE64_STD_DEFAULT`] and [`BASE64_URL_DEFAULT`] constants for fast conversion.
    pub fn to_base64(&self, encoder: Base64Encoder) -> String {
        encoder.encode(self.workchain, &self.hash_part)
    }
}

impl FromStr for Address {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(':') {
            Address::from_raw_address(s)
        } else {
            Ok(Address::from_base64(s, None)?.address)
        }
    }
}

impl TryFrom<String> for Address {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.contains(':') {
            Address::from_raw_address(&value)
        } else {
            Ok(Address::from_base64(&value, None)?.address)
        }
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_base64(BASE64_URL_DEFAULT).as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_address() {
        let bytes = hex::decode("e4d954ef9f4e1250a26b5bbad76a1cdd17cfd08babad6f4c23e372270aef6f76")
            .unwrap();
        let hash_part: HashPart = bytes.as_slice().try_into().unwrap();
        let workchain = 0;

        let address = Address::new(workchain, &hash_part);
        assert_eq!(address.get_workchain(), workchain);
        assert_eq!(
            address.get_hash_part(),
            &[
                0xe4, 0xd9, 0x54, 0xef, 0x9f, 0x4e, 0x12, 0x50, 0xa2, 0x6b, 0x5b, 0xba, 0xd7, 0x6a,
                0x1c, 0xdd, 0x17, 0xcf, 0xd0, 0x8b, 0xab, 0xad, 0x6f, 0x4c, 0x23, 0xe3, 0x72, 0x27,
                0x0a, 0xef, 0x6f, 0x76
            ]
        );
    }

    #[test]
    fn test_new_address_empty() {
        let address = Address::empty();

        assert_eq!(address.get_workchain(), 0);
        assert_eq!(address.get_hash_part(), &[0u8; 32]);
    }

    #[test]
    fn test_new_address_from_raw_adress() {
        // main case
        {
            let raw_address = "0:e4d954ef9f4e1250a26b5bbad76a1cdd17cfd08babad6f4c23e372270aef6f76";
            let address = Address::from_raw_address(raw_address);

            assert_eq!(
                address,
                Ok(Address::new(
                    0,
                    &[
                        0xe4, 0xd9, 0x54, 0xef, 0x9f, 0x4e, 0x12, 0x50, 0xa2, 0x6b, 0x5b, 0xba,
                        0xd7, 0x6a, 0x1c, 0xdd, 0x17, 0xcf, 0xd0, 0x8b, 0xab, 0xad, 0x6f, 0x4c,
                        0x23, 0xe3, 0x72, 0x27, 0x0a, 0xef, 0x6f, 0x76
                    ]
                ))
            );
        }

        // error cases
        {
            let raw_address = "bad_string";
            let address = Address::from_raw_address(raw_address);

            assert_eq!(
                address,
                Err(ParseError {
                    address: raw_address.to_owned(),
                    reason: "Invalid raw address string: wrong address format",
                })
            );
        }

        {
            let raw_address = "fdfd:fdfd";
            let address = Address::from_raw_address(raw_address);

            assert_eq!(
                address,
                Err(ParseError {
                    address: raw_address.to_owned(),
                    reason: "Invalid raw address string: workchain number is not a 32-bit integer",
                })
            );
        }

        {
            let raw_address = "0:][p][;cr3244";
            let address = Address::from_raw_address(raw_address);

            assert_eq!(
                address,
                Err(ParseError {
                    address: raw_address.to_owned(),
                    reason: "Invalid raw address string: failed to decode hash part",
                })
            );
        }

        {
            let raw_address = "0:ABCDE012";
            let address = Address::from_raw_address(raw_address);

            assert_eq!(
                address,
                Err(ParseError {
                    address: raw_address.to_owned(),
                    reason: "Invalid raw address string: hash part length must be 32 bytes",
                })
            );
        }
    }

    #[test]
    fn test_from_base64() {
        // main case (1): [bounceable] + [production] + [encoder guessing]
        {
            let result =
                Address::from_base64("EQDk2VTvn04SUKJrW7rXahzdF8_Qi6utb0wj43InCu9vdjrR", None)
                    .unwrap();

            // Encoder result
            assert_eq!(result.is_bounceable(), true);
            assert_eq!(result.is_production(), true);
            assert_eq!(result.decoder, Base64Decoder::UrlSafe);

            // Address
            assert_eq!(result.address.get_workchain(), 0);
            assert_eq!(
                result.address.get_hash_part(),
                &[
                    228, 217, 84, 239, 159, 78, 18, 80, 162, 107, 91, 186, 215, 106, 28, 221, 23,
                    207, 208, 139, 171, 173, 111, 76, 35, 227, 114, 39, 10, 239, 111, 118
                ]
            );
        }

        // main case (2): [non bounceable] + [production] + [encoder guessing]
        {
            let result =
                Address::from_base64("UQAWzEKcdnykvXfUNouqdS62tvrp32bCxuKS6eQrS6ISgZ8t", None)
                    .unwrap();

            // Encoder result
            assert_eq!(result.is_bounceable(), false);
            assert_eq!(result.is_production(), true);
            assert_eq!(result.decoder, Base64Decoder::Standard);

            // Address
            assert_eq!(result.address.get_workchain(), 0);
            assert_eq!(
                result.address.get_hash_part(),
                &[
                    22u8, 204, 66, 156, 118, 124, 164, 189, 119, 212, 54, 139, 170, 117, 46, 182,
                    182, 250, 233, 223, 102, 194, 198, 226, 146, 233, 228, 43, 75, 162, 18, 129
                ]
            );
        }

        // error case (1): bad length
        {
            let result = Address::from_base64("bad length", None);
            assert_eq!(
                result,
                Err(ParseError {
                    address: "bad length".to_owned(),
                    reason: "Invalid base64 address string: length must be 48 characters"
                })
            );
        }

        // error case (2): byte length
        {
            let result =
                Address::from_base64("EQDk2VTvn04SUKJrW7rXahzdF8_Qi6utb0wj43InCu9vdjrRIyM", None);
            assert_eq!(
                result,
                Err(ParseError {
                    address: "EQDk2VTvn04SUKJrW7rXahzdF8_Qi6utb0wj43InCu9vdjrRIyM".to_owned(),
                    reason: "Invalid base64 address string: length must be 48 characters"
                })
            );
        }

        // error case (3): invalid flag
        {
            let result =
                Address::from_base64("VQDk2VTvn04SUKJrW7rXahzdF8_Qi6utb0wj43InCu9vdjrR", None);
            assert_eq!(
                result,
                Err(ParseError {
                    address: "VQDk2VTvn04SUKJrW7rXahzdF8_Qi6utb0wj43InCu9vdjrR".to_owned(),
                    reason: "Invalid base64 address string: invalid flag"
                })
            );
        }

        // error case (3): bad CRC16
        {
            let result =
                Address::from_base64("EQDkqlTvn04SUKJrW7rXahzdF8_Qi6utb0wj43InCu9vdjrR", None);
            assert_eq!(
                result,
                Err(ParseError {
                    address: "EQDkqlTvn04SUKJrW7rXahzdF8_Qi6utb0wj43InCu9vdjrR".to_owned(),
                    reason: "Invalid base64 address string: CRC16 hashes do not match"
                })
            );
        }
    }

    #[test]
    fn test_compare_addresses() {
        // case (1): same addresses
        {
            let address1 =
                Address::from_base64("UQAWzEKcdnykvXfUNouqdS62tvrp32bCxuKS6eQrS6ISgZ8t", None)
                    .unwrap()
                    .address;

            let address2 =
                Address::from_base64("UQAWzEKcdnykvXfUNouqdS62tvrp32bCxuKS6eQrS6ISgZ8t", None)
                    .unwrap()
                    .address;

            assert_eq!(address1, address2);
        }

        // case (2): not same
        {
            let address1 =
                Address::from_base64("UQAWzEKcdnykvXfUNouqdS62tvrp32bCxuKS6eQrS6ISgZ8t", None)
                    .unwrap()
                    .address;

            let address2 =
                Address::from_base64("EQDk2VTvn04SUKJrW7rXahzdF8_Qi6utb0wj43InCu9vdjrR", None)
                    .unwrap()
                    .address;

            assert_ne!(address1, address2);
        }
    }

    #[test]
    fn test_multi_converts() {
        // case (1): from base64 url safe
        {
            let addr = "EQAOl3l3CEEcKaPLHz-BDvT4P0HZkIOPf5POcILE_5qgJuR2"
                .parse::<Address>()
                .unwrap();

            assert_eq!(
                addr.to_raw_address(),
                "0:0e97797708411c29a3cb1f3f810ef4f83f41d990838f7f93ce7082c4ff9aa026"
            );
            assert_eq!(
                addr.to_base64(BASE64_STD_DEFAULT),
                "EQAOl3l3CEEcKaPLHz+BDvT4P0HZkIOPf5POcILE/5qgJuR2"
            );
            assert_eq!(
                addr.to_base64(BASE64_URL_DEFAULT),
                "EQAOl3l3CEEcKaPLHz-BDvT4P0HZkIOPf5POcILE_5qgJuR2"
            );
            assert_eq!(
                addr.to_string(),
                "EQAOl3l3CEEcKaPLHz-BDvT4P0HZkIOPf5POcILE_5qgJuR2"
            );
        }

        // case (2): from base64 url std
        {
            let addr = "EQAOl3l3CEEcKaPLHz+BDvT4P0HZkIOPf5POcILE/5qgJuR2"
                .parse::<Address>()
                .unwrap();

            assert_eq!(
                addr.to_raw_address(),
                "0:0e97797708411c29a3cb1f3f810ef4f83f41d990838f7f93ce7082c4ff9aa026"
            );
            assert_eq!(
                addr.to_base64(BASE64_STD_DEFAULT),
                "EQAOl3l3CEEcKaPLHz+BDvT4P0HZkIOPf5POcILE/5qgJuR2"
            );
            assert_eq!(
                addr.to_base64(BASE64_URL_DEFAULT),
                "EQAOl3l3CEEcKaPLHz-BDvT4P0HZkIOPf5POcILE_5qgJuR2"
            );
            assert_eq!(
                addr.to_string(),
                "EQAOl3l3CEEcKaPLHz-BDvT4P0HZkIOPf5POcILE_5qgJuR2"
            );
        }

        // case (2): from raw address
        {
            let addr = "0:0e97797708411c29a3cb1f3f810ef4f83f41d990838f7f93ce7082c4ff9aa026"
                .parse::<Address>()
                .unwrap();

            assert_eq!(
                addr.to_raw_address(),
                "0:0e97797708411c29a3cb1f3f810ef4f83f41d990838f7f93ce7082c4ff9aa026"
            );
            assert_eq!(
                addr.to_base64(BASE64_STD_DEFAULT),
                "EQAOl3l3CEEcKaPLHz+BDvT4P0HZkIOPf5POcILE/5qgJuR2"
            );
            assert_eq!(
                addr.to_base64(BASE64_URL_DEFAULT),
                "EQAOl3l3CEEcKaPLHz-BDvT4P0HZkIOPf5POcILE_5qgJuR2"
            );
            assert_eq!(
                addr.to_string(),
                "EQAOl3l3CEEcKaPLHz-BDvT4P0HZkIOPf5POcILE_5qgJuR2"
            );
        }
    }
}
