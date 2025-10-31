use cosmwasm_std::CanonicalAddr;

use crate::spec::{NonIdentityPallasPoint, diversify_hash};

#[derive(Debug, Copy, Clone)]
pub struct HeadstashAddr([u8; 32]);

impl HeadstashAddr {
    /// Returns the [`Diversifier`] for this `Address`.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    // /// Returns the [`CanonicalAddr`] for this `Address`.
    pub fn to_canonical(&self) -> CanonicalAddr {
        CanonicalAddr::from(self.0)
    }

    pub(crate) fn g_d(&self) -> NonIdentityPallasPoint {
        diversify_hash(&self.0)
    }

    // pub(crate) fn pk_d(&self) -> &DiversifiedTransmissionKey {
    //     &self.pk_d
    // }
}

impl TryFrom<CanonicalAddr> for HeadstashAddr {
    type Error = std::array::TryFromSliceError;

    fn try_from(canonical_addr: CanonicalAddr) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = canonical_addr.as_slice().try_into()?;
        Ok(Self(bytes))
    }
}

impl TryFrom<&[u8]> for HeadstashAddr {
    type Error = std::array::TryFromSliceError;

    fn try_from(canonical_addr: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = canonical_addr.try_into()?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
pub mod test {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{Addr, Api, CanonicalAddr};

    #[test]
    fn test_canon() {
        let deps = mock_dependencies();
        let addr = deps.api.addr_make("ayo");
        let addr = deps.api.addr_make("ayo");
        let canon: CanonicalAddr = deps.api.addr_canonicalize(&addr.to_string()).unwrap();
        println!("{:#?}", addr.to_string());
        println!("{:#?}", canon.len());
        println!("{:#?}", canon.to_string());
    }
}
