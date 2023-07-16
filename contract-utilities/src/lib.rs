#![cfg_attr(not(feature = "std"), no_std)]
pub struct Mapping<T1, T2: casper_types::CLTyped + casper_types::bytesrepr::ToBytes> {
    _t1: T1,
    _t2: T2,
}

pub struct NestedMapping<T1, T2, T3: casper_types::CLTyped + casper_types::bytesrepr::ToBytes> {
    _t1: T1,
    _t2: T2,
    _t3: T3,
}

pub struct NestedNestedMapping<T1, T2, T3, T4: casper_types::CLTyped + casper_types::bytesrepr::ToBytes> {
    _t1: T1,
    _t2: T2,
    _t3: T3,
    _t4: T4,
}

pub mod address;
pub mod helpers;
pub mod error;
