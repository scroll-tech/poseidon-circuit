use crate::primitives::{CachedSpec, ConstantLengthIden3, Domain, Hash, Spec, VariableLengthIden3};
use halo2curves::bn256::Fr;
use halo2curves::ff::FromUniformBytes;
use once_cell::sync::OnceCell;

#[cfg(not(feature = "short"))]
mod chip_long {
    use crate::primitives::P128Pow5T3;

    /// The specified base hashable trait
    pub trait Hashablebase: crate::primitives::P128Pow5T3Constants {}
    /// Set the spec type as P128Pow5T3
    pub type HashSpec<F> = P128Pow5T3<F>;
}

#[cfg(feature = "short")]
mod chip_short {
    use crate::primitives::P128Pow5T3Compact;

    /// The specified base hashable trait
    pub trait Hashablebase: crate::params::CachedConstants {}
    /// Set the spec type as P128Pow5T3Compact
    pub type HashSpec<F> = P128Pow5T3Compact<F>;
}

#[cfg(not(feature = "short"))]
pub use chip_long::*;

#[cfg(feature = "short")]
pub use chip_short::*;

/// the domain factor applied to var-len mode hash
#[cfg(not(feature = "legacy"))]
pub const HASHABLE_DOMAIN_SPEC: u128 = 0x10000000000000000;
#[cfg(feature = "legacy")]
pub const HASHABLE_DOMAIN_SPEC: u128 = 1;

/// indicate an field can be hashed in merkle tree (2 Fields to 1 Field)
pub trait Hashable: Hashablebase + FromUniformBytes<64> + Ord {
    /// the spec type used in circuit for this hashable field
    type SpecType: CachedSpec<Self, 3, 2>;
    /// the domain type used for hash calculation
    type DomainType: Domain<Self, 2>;

    /// execute hash for any sequence of fields
    #[deprecated]
    fn hash(inp: [Self; 2]) -> Self {
        Self::hash_with_domain(inp, Self::ZERO)
    }

    /// execute hash for any sequence of fields, with domain being specified
    fn hash_with_domain(inp: [Self; 2], domain: Self) -> Self;
    /// obtain the rows consumed by each circuit block
    fn hash_block_size() -> usize {
        #[cfg(feature = "short")]
        {
            1 + Self::SpecType::full_rounds()
        }
        #[cfg(not(feature = "short"))]
        {
            1 + Self::SpecType::full_rounds() + (Self::SpecType::partial_rounds() + 1) / 2
        }
    }
    /// init a hasher used for hash
    fn hasher() -> Hash<Self, Self::SpecType, Self::DomainType, 3, 2> {
        Hash::<Self, Self::SpecType, Self::DomainType, 3, 2>::init()
    }
}

/// indicate an message stream constructed by the field can be hashed, commonly
/// it just need to update the Domain
pub trait MessageHashable: Hashable {
    /// the domain type used for message hash
    type DomainType: Domain<Self, 2>;
    /// hash message, if cap is not provided, it use the basic spec: (len of msg * 2^64, or len of msg in legacy mode)
    fn hash_msg(msg: &[Self], cap: Option<u128>) -> Self;
    /// init a hasher used for hash message
    fn msg_hasher(
    ) -> Hash<Self, <Self as Hashable>::SpecType, <Self as MessageHashable>::DomainType, 3, 2> {
        Hash::<Self, <Self as Hashable>::SpecType, <Self as MessageHashable>::DomainType, 3, 2>::init()
    }
}

impl Hashablebase for Fr {}

impl Hashable for Fr {
    type SpecType = HashSpec<Self>;
    type DomainType = ConstantLengthIden3<2>;

    fn hash_with_domain(inp: [Self; 2], domain: Self) -> Self {
        Self::hasher().hash(inp, domain)
    }

    fn hasher() -> Hash<Self, Self::SpecType, Self::DomainType, 3, 2> {
        static INIT: OnceCell<
            Hash<Fr, <Fr as Hashable>::SpecType, <Fr as Hashable>::DomainType, 3, 2>,
        > = OnceCell::new();
        INIT.get_or_init(Hash::init).clone()
    }
}

impl MessageHashable for Fr {
    type DomainType = VariableLengthIden3;

    fn hash_msg(msg: &[Self], cap: Option<u128>) -> Self {
        Self::msg_hasher()
            .hash_with_cap(msg, cap.unwrap_or(msg.len() as u128 * HASHABLE_DOMAIN_SPEC))
    }

    fn msg_hasher(
    ) -> Hash<Self, <Self as Hashable>::SpecType, <Self as MessageHashable>::DomainType, 3, 2> {
        static INIT: OnceCell<
            Hash<Fr, <Fr as Hashable>::SpecType, <Fr as MessageHashable>::DomainType, 3, 2>,
        > = OnceCell::new();
        INIT.get_or_init(Hash::init).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lazy_init() {
        let _ = Fr::hasher();
        let _ = Fr::msg_hasher();

        let _ = Fr::hasher();
        let _ = Fr::msg_hasher();
    }
}
