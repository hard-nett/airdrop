use cosmwasm_std::CanonicalAddr;
use pasta_curves::pallas;

/// the canonical bytes of a bech32 address intended to recieve headstash distributions.
/// functions:
/// - hash: performs the blake
#[derive(Debug, Copy, Clone)]
pub struct RecpAddr([u8; 32]);

impl RecpAddr {
    /// Returns the bytes for this `RecpAddr`.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    // /// Returns the [`CanonicalAddr`] for this `RecpAddr`.
    pub fn to_canonical(&self) -> CanonicalAddr {
        CanonicalAddr::from(self.0)
    }
    /// Returns the [`pallas::Base`] for this `RecpAddr`.
    pub fn to_pallas(&self) -> pallas::Base {
        crate::spec::recp_to_fp(self)
    }
}

impl TryFrom<CanonicalAddr> for RecpAddr {
    type Error = std::array::TryFromSliceError;

    fn try_from(canonical_addr: CanonicalAddr) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = canonical_addr.as_slice().try_into()?;
        Ok(Self(bytes))
    }
}

impl TryFrom<&[u8]> for RecpAddr {
    type Error = std::array::TryFromSliceError;

    fn try_from(canonical_addr: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = canonical_addr.try_into()?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
pub mod test {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{Api, CanonicalAddr};

    #[test]
    fn test_canon() {
        let deps = mock_dependencies();
        let addr = deps.api.addr_make("ayo");
        let canon: CanonicalAddr = deps.api.addr_canonicalize(&addr.to_string()).unwrap();
        println!("{:#?}", addr.to_string());
        println!("{:#?}", canon.len());
        println!("{:#?}", canon.to_string());
    }
}
