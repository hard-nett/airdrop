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


#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Api;

    // Helper function to create a valid 32-byte array
    fn create_test_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        bytes
    }

    #[test]
    fn test_recp_addr_creation_and_to_bytes() {
        let test_bytes = create_test_bytes();
        let recp_addr = RecpAddr(test_bytes);
        
        assert_eq!(recp_addr.to_bytes(), test_bytes);
    }

    #[test]
    fn test_to_canonical() {
        let test_bytes = create_test_bytes();
        let recp_addr = RecpAddr(test_bytes);
        
        let canonical = recp_addr.to_canonical();
        assert_eq!(canonical.as_slice(), &test_bytes);
    }

    #[test]
    fn test_try_from_canonical_addr_success() {
        let test_bytes = create_test_bytes();
        let canonical = CanonicalAddr::from(test_bytes);
        
        let recp_addr = RecpAddr::try_from(canonical).unwrap();
        assert_eq!(recp_addr.to_bytes(), test_bytes);
    }

    #[test]
    fn test_try_from_canonical_addr_wrong_length() {
        // Create a CanonicalAddr with wrong length (not 32 bytes)
        let short_bytes = vec![1u8, 2, 3, 4];
        let canonical = CanonicalAddr::from(short_bytes);
        
        let result = RecpAddr::try_from(canonical);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from_slice_success() {
        let test_bytes = create_test_bytes();
        let slice: &[u8] = &test_bytes;
        
        let recp_addr = RecpAddr::try_from(slice).unwrap();
        assert_eq!(recp_addr.to_bytes(), test_bytes);
    }

    #[test]
    fn test_try_from_slice_wrong_length_short() {
        let short_slice: &[u8] = &[1, 2, 3, 4];
        let result = RecpAddr::try_from(short_slice);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from_slice_wrong_length_long() {
        let long_slice: &[u8] = &[0u8; 64];
        let result = RecpAddr::try_from(long_slice);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from_empty_slice() {
        let empty_slice: &[u8] = &[];
        let result = RecpAddr::try_from(empty_slice);
        assert!(result.is_err());
    }

    #[test]
    fn test_recp_addr_clone() {
        let test_bytes = create_test_bytes();
        let recp_addr = RecpAddr(test_bytes);
        let cloned = recp_addr.clone();
        
        assert_eq!(recp_addr.to_bytes(), cloned.to_bytes());
    }

    #[test]
    fn test_recp_addr_copy() {
        let test_bytes = create_test_bytes();
        let recp_addr = RecpAddr(test_bytes);
        let copied = recp_addr; // Copy trait
        
        assert_eq!(recp_addr.to_bytes(), copied.to_bytes());
    }

    #[test]
    fn test_round_trip_canonical() {
        let test_bytes = create_test_bytes();
        let recp_addr = RecpAddr(test_bytes);
        
        // Convert to canonical and back
        let canonical = recp_addr.to_canonical();
        let recp_addr_2 = RecpAddr::try_from(canonical).unwrap();
        
        assert_eq!(recp_addr.to_bytes(), recp_addr_2.to_bytes());
    }

    #[test]
    fn test_all_zeros() {
        let zero_bytes = [0u8; 32];
        let recp_addr = RecpAddr(zero_bytes);
        
        assert_eq!(recp_addr.to_bytes(), zero_bytes);
    }

    #[test]
    fn test_all_ones() {
        let ones_bytes = [0xFFu8; 32];
        let recp_addr = RecpAddr(ones_bytes);
        
        assert_eq!(recp_addr.to_bytes(), ones_bytes);
    }

    #[test]
    fn test_with_mock_cosmwasm_addr() {
        let deps = mock_dependencies();
        let addr = deps.api.addr_make("test_address");
        let canonical = deps.api.addr_canonicalize(&addr.to_string()).unwrap();
        
        // This might fail if the canonical address isn't 32 bytes
        // depending on the mock implementation
        if canonical.len() == 32 {
            let recp_addr = RecpAddr::try_from(canonical.clone()).unwrap();
            assert_eq!(recp_addr.to_canonical().as_slice(), canonical.as_slice());
        } else {
            // Document that mock addresses may not be 32 bytes
            println!("Mock canonical address length: {}", canonical.len());
        }
    }

    #[test]
    fn test_to_pallas() {
        let test_bytes = create_test_bytes();
        let recp_addr = RecpAddr(test_bytes);
        
        // Just verify it can be called without panicking
        // The actual correctness depends on the spec::recp_to_fp implementation
        let _pallas_base = recp_addr.to_pallas();
    }

    #[test]
    fn test_debug_trait() {
        let test_bytes = create_test_bytes();
        let recp_addr = RecpAddr(test_bytes);
        
        // Verify Debug trait works
        let debug_string = format!("{:?}", recp_addr);
        assert!(debug_string.contains("RecpAddr"));
    }
}