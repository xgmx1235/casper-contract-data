extern crate alloc;
use crate::address::Address;
use crate::error::Error;
use alloc::string::String;
use alloc::{vec, vec::Vec};
use casper_contract::contract_api::system;
use casper_contract::{
    contract_api::{self, runtime, runtime::get_blocktime, storage},
    ext_ffi,
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_types::bytesrepr::FromBytes;
use casper_types::CLTyped;
use casper_types::{api_error, bytesrepr, bytesrepr::ToBytes, ApiError, ContractPackageHash, Key};
use casper_types::{runtime_args, system::CallStackElement, RuntimeArgs, URef, U256, U512};
use core::convert::TryInto;
use core::mem::MaybeUninit;
use core::u64;

// Helper functions

pub fn get_key<T: FromBytes + CLTyped>(name: &str) -> Option<T> {
    match runtime::get_key(name) {
        None => None,
        Some(value) => {
            let key = value.try_into().unwrap_or_revert();
            let result = storage::read(key).unwrap_or_revert().unwrap_or_revert();
            Some(result)
        }
    }
}

pub fn get_key_from_address(addr: &Address) -> Key {
    match *addr {
        Address::Account(acc) => Key::from(acc),
        Address::Contract(contract_package_hash) => Key::from(contract_package_hash),
    }
}

pub fn get_self_key() -> Key {
    let self_addr = get_self_address().unwrap_or_revert();
    get_key_from_address(&self_addr)
}

pub fn set_key<T: ToBytes + CLTyped>(name: &str, value: T) {
    match runtime::get_key(name) {
        Some(key) => {
            let key_ref = key.try_into().unwrap_or_revert();
            storage::write(key_ref, value);
        }
        None => {
            let key = storage::new_uref(value).into();
            runtime::put_key(name, key);
        }
    }
}

pub fn get_self_address() -> Result<Address, ApiError> {
    get_last_call_stack_item()
        .map(call_stack_element_to_address)
        .ok_or(Error::InvalidContext.into())
}

fn get_last_call_stack_item() -> Option<CallStackElement> {
    let call_stack = runtime::get_call_stack();
    call_stack.iter().rev().next().cloned()
}

/// Gets the immediate call stack element of the current execution.
fn get_immediate_call_stack_item() -> Option<CallStackElement> {
    let call_stack = runtime::get_call_stack();
    call_stack.into_iter().rev().nth(1)
}

/// Returns address based on a [`CallStackElement`].
///
/// For `Session` and `StoredSession` variants it will return account hash, and for `StoredContract`
/// case it will use contract hash as the address.
fn call_stack_element_to_address(call_stack_element: CallStackElement) -> Address {
    match call_stack_element {
        CallStackElement::Session { account_hash } => Address::from(account_hash),
        CallStackElement::StoredSession { account_hash, .. } => {
            // Stored session code acts in account's context, so if stored session wants to interact
            // with an ERC20 token caller's address will be used.
            Address::from(account_hash)
        }
        CallStackElement::StoredContract {
            contract_package_hash,
            ..
        } => Address::from(contract_package_hash),
    }
}

/// Gets the immediate session caller of the current execution.
///
/// This function ensures that only session code can execute this function, and disallows stored
/// session/stored contracts.
pub fn get_immediate_caller_address() -> Result<Address, ApiError> {
    get_immediate_call_stack_item()
        .map(call_stack_element_to_address)
        .ok_or(ApiError::User(Error::InvalidContext as u16))
}

pub fn get_immediate_caller_key() -> Key {
    let addr = get_immediate_caller_address().unwrap_or_revert();
    get_key_from_address(&addr)
}

pub(crate) fn _get_stored_value_with_user_errors<T: CLTyped + FromBytes>(
    name: &str,
    missing: ApiError,
    invalid: ApiError,
) -> T {
    let uref = get_uref(name);
    _read_with_user_errors(uref, missing, invalid)
}

pub(crate) fn _read_with_user_errors<T: CLTyped + FromBytes>(
    uref: URef,
    missing: ApiError,
    invalid: ApiError,
) -> T {
    let key: Key = uref.into();
    let (key_ptr, key_size, _bytes) = _to_ptr(key);

    let value_size = {
        let mut value_size = MaybeUninit::uninit();
        let ret = unsafe { ext_ffi::casper_read_value(key_ptr, key_size, value_size.as_mut_ptr()) };
        match api_error::result_from(ret) {
            Ok(_) => unsafe { value_size.assume_init() },
            Err(ApiError::ValueNotFound) => runtime::revert(missing),
            Err(e) => runtime::revert(e),
        }
    };

    let value_bytes = _read_host_buffer(value_size).unwrap_or_revert();

    bytesrepr::deserialize(value_bytes).unwrap_or_revert_with(invalid)
}

pub(crate) fn _to_ptr<T: ToBytes>(t: T) -> (*const u8, usize, Vec<u8>) {
    let bytes = t.into_bytes().unwrap_or_revert();
    let ptr = bytes.as_ptr();
    let size = bytes.len();
    (ptr, size, bytes)
}

pub(crate) fn _read_host_buffer(size: usize) -> Result<Vec<u8>, ApiError> {
    let mut dest: Vec<u8> = if size == 0 {
        Vec::new()
    } else {
        let bytes_non_null_ptr = contract_api::alloc_bytes(size);
        unsafe { Vec::from_raw_parts(bytes_non_null_ptr.as_ptr(), size, size) }
    };
    _read_host_buffer_into(&mut dest)?;
    Ok(dest)
}
pub(crate) fn _read_host_buffer_into(dest: &mut [u8]) -> Result<usize, ApiError> {
    let mut bytes_written = MaybeUninit::uninit();
    let ret = unsafe {
        ext_ffi::casper_read_host_buffer(dest.as_mut_ptr(), dest.len(), bytes_written.as_mut_ptr())
    };
    // NOTE: When rewriting below expression as `result_from(ret).map(|_| unsafe { ... })`, and the
    // caller ignores the return value, execution of the contract becomes unstable and ultimately
    // leads to `Unreachable` error.
    api_error::result_from(ret)?;
    Ok(unsafe { bytes_written.assume_init() })
}

#[no_mangle]
pub fn dictionary_write(dictionary_uref: URef, address: Address, amount: U256) {
    let dictionary_item_key = make_dictionary_item_key(address);
    storage::dictionary_put(dictionary_uref, &dictionary_item_key, amount);
}

/// Creates a dictionary item key for a dictionary item.
#[no_mangle]
fn make_dictionary_item_key(owner: Address) -> String {
    let preimage = owner.to_bytes().unwrap_or_revert();
    // NOTE: As for now dictionary item keys are limited to 64 characters only. Instead of using
    // hashing (which will effectively hash a hash) we'll use base64. Preimage is about 33 bytes for
    // both Address variants, and approximated base64-encoded length will be 4 * (33 / 3) ~ 44
    // characters.
    // Even if the preimage increased in size we still have extra space but even in case of much
    // larger preimage we can switch to base85 which has ratio of 4:5.
    base64::encode(preimage)
}

/// Creates a dictionary item key for a dictionary item.
#[no_mangle]
pub fn make_dictionary_item_key_for_key(contract_hash: Key) -> String {
    let preimage = contract_hash.into_hash().unwrap_or_revert();
    // NOTE: As for now dictionary item keys are limited to 64 characters only. Instead of using
    // hashing (which will effectively hash a hash) we'll use base64. Preimage is about 33 bytes for
    // both Address variants, and approximated base64-encoded length will be 4 * (33 / 3) ~ 44
    // characters.
    // Even if the preimage increased in size we still have extra space but even in case of much
    // larger preimage we can switch to base85 which has ratio of 4:5.
    hex::encode(preimage)
}

#[no_mangle]
pub fn dictionary_read(dictionary_uref: URef, address: Address) -> U256 {
    let dictionary_item_key = make_dictionary_item_key(address);

    storage::dictionary_get(dictionary_uref, &dictionary_item_key)
        .unwrap_or_revert()
        .unwrap_or_default()
}

pub fn get_uref(name: &str) -> URef {
    let key = runtime::get_key(name).unwrap_or_revert();
    key.into_uref().unwrap_or_revert()
}

pub fn get_dictionary_value_from_key<T: CLTyped + FromBytes>(
    dictionary_name: &str,
    key: &str,
) -> Option<T> {
    let seed_uref = get_uref(dictionary_name);

    match storage::dictionary_get::<T>(seed_uref, key) {
        Ok(maybe_value) => maybe_value,
        Err(_) => None,
    }
}

pub fn write_dictionary_value_from_key<T: CLTyped + FromBytes + ToBytes>(
    dictionary_name: &str,
    key: &str,
    value: T,
) {
    let seed_uref = get_uref(dictionary_name);

    match storage::dictionary_get::<T>(seed_uref, key) {
        Ok(None | Some(_)) => storage::dictionary_put(seed_uref, key, value),
        Err(error) => runtime::revert(error),
    }
}

/// Helper function that returns the current block timestamp within the range of [`u64`], i.e. `[0, 2**64 - 1]`.
pub fn current_block_timestamp() -> u64 {
    if runtime::has_key("fake_timestamp") {
        get_key::<u64>("fake_timestamp").unwrap()
    } else {
        u64::from(get_blocktime()).checked_rem(u64::MAX).unwrap() / 1000
    }
}

pub fn current_block_number() -> u64 {
    current_block_timestamp()
}

pub fn require(v: bool, e: ApiError) {
    if !v {
        runtime::revert(e);
    }
}

pub fn encode_dictionary_item_key(key: Key) -> String {
    match key {
        Key::Account(account_hash) => hex::encode(account_hash.value()),
        Key::Hash(hash_addr) => hex::encode(hash_addr),
        _ => runtime::revert(Error::InvalidKey),
    }
}

pub fn encode_key_and_value<T: CLTyped + ToBytes>(key: &Key, value: &T) -> String {
    let mut bytes_a = key.to_bytes().unwrap_or_revert();
    let mut bytes_b = value.to_bytes().unwrap_or_revert();

    bytes_a.append(&mut bytes_b);

    let bytes = runtime::blake2b(bytes_a);
    hex::encode(bytes)
}

pub fn null_key() -> Key {
    let null_hash: [u8; 32] = vec![0u8; 32].try_into().unwrap();
    Key::from(ContractPackageHash::new(null_hash))
}

pub fn default_cspr_key() -> Key {
    let one_hash: [u8; 32] = vec![1u8; 32].try_into().unwrap();
    Key::from(ContractPackageHash::new(one_hash))
}

pub fn encode_1<T1: CLTyped + ToBytes>(t1: &T1) -> Vec<u8> {
    t1.to_bytes().unwrap_or_revert()
}

pub fn decode_1<T1: CLTyped + FromBytes>(bytes: &[u8]) -> T1 {
    let (t1, _) = T1::from_bytes(bytes).unwrap();
    t1
}

pub fn encode_2<T1: CLTyped + ToBytes, T2: CLTyped + ToBytes>(t1: &T1, t2: &T2) -> Vec<u8> {
    let mut bytes_1 = t1.to_bytes().unwrap_or_revert();
    let mut bytes_2 = t2.to_bytes().unwrap_or_revert();
    bytes_1.append(&mut bytes_2);
    bytes_1
}

pub fn decode_2<T1: CLTyped + FromBytes, T2: CLTyped + FromBytes>(bytes: &[u8]) -> (T1, T2) {
    let (t1, remainder) = T1::from_bytes(bytes).unwrap();
    let (t2, _) = T2::from_bytes(remainder).unwrap();
    (t1, t2)
}

pub fn encode_3<T1: CLTyped + ToBytes, T2: CLTyped + ToBytes, T3: CLTyped + ToBytes>(
    t1: &T1,
    t2: &T2,
    t3: &T3,
) -> Vec<u8> {
    let mut bytes_1 = t1.to_bytes().unwrap_or_revert();
    let mut bytes_2 = t2.to_bytes().unwrap_or_revert();
    let mut bytes_3 = t3.to_bytes().unwrap_or_revert();
    bytes_1.append(&mut bytes_2);
    bytes_1.append(&mut bytes_3);
    bytes_1
}

pub fn decode_3<T1: CLTyped + FromBytes, T2: CLTyped + FromBytes, T3: CLTyped + FromBytes>(
    bytes: &[u8],
) -> (T1, T2, T3) {
    let (t1, remainder) = T1::from_bytes(bytes).unwrap();
    let (t2, remainder) = T2::from_bytes(remainder).unwrap();
    let (t3, _) = T3::from_bytes(remainder).unwrap();
    (t1, t2, t3)
}

pub fn encode_4<
    T1: CLTyped + ToBytes,
    T2: CLTyped + ToBytes,
    T3: CLTyped + ToBytes,
    T4: CLTyped + ToBytes,
>(
    t1: &T1,
    t2: &T2,
    t3: &T3,
    t4: &T4,
) -> Vec<u8> {
    let mut bytes_1 = t1.to_bytes().unwrap_or_revert();
    let mut bytes_2 = t2.to_bytes().unwrap_or_revert();
    let mut bytes_3 = t3.to_bytes().unwrap_or_revert();
    let mut bytes_4 = t4.to_bytes().unwrap_or_revert();
    bytes_1.append(&mut bytes_2);
    bytes_1.append(&mut bytes_3);
    bytes_1.append(&mut bytes_4);
    bytes_1
}

pub fn decode_4<
    T1: CLTyped + FromBytes,
    T2: CLTyped + FromBytes,
    T3: CLTyped + FromBytes,
    T4: CLTyped + FromBytes,
>(
    bytes: &[u8],
) -> (T1, T2, T3, T4) {
    let (t1, remainder) = T1::from_bytes(bytes).unwrap();
    let (t2, remainder) = T2::from_bytes(remainder).unwrap();
    let (t3, remainder) = T3::from_bytes(remainder).unwrap();
    let (t4, _) = T4::from_bytes(remainder).unwrap();
    (t1, t2, t3, t4)
}

pub fn encode_5<
    T1: CLTyped + ToBytes,
    T2: CLTyped + ToBytes,
    T3: CLTyped + ToBytes,
    T4: CLTyped + ToBytes,
    T5: CLTyped + ToBytes,
>(
    t1: &T1,
    t2: &T2,
    t3: &T3,
    t4: &T4,
    t5: &T5,
) -> Vec<u8> {
    let mut bytes_1 = t1.to_bytes().unwrap_or_revert();
    let mut bytes_2 = t2.to_bytes().unwrap_or_revert();
    let mut bytes_3 = t3.to_bytes().unwrap_or_revert();
    let mut bytes_4 = t4.to_bytes().unwrap_or_revert();
    let mut bytes_5 = t5.to_bytes().unwrap_or_revert();
    bytes_1.append(&mut bytes_2);
    bytes_1.append(&mut bytes_3);
    bytes_1.append(&mut bytes_4);
    bytes_1.append(&mut bytes_5);
    bytes_1
}

pub fn decode_5<
    T1: CLTyped + FromBytes,
    T2: CLTyped + FromBytes,
    T3: CLTyped + FromBytes,
    T4: CLTyped + FromBytes,
    T5: CLTyped + FromBytes,
>(
    bytes: &[u8],
) -> (T1, T2, T3, T4, T5) {
    let (t1, remainder) = T1::from_bytes(bytes).unwrap();
    let (t2, remainder) = T2::from_bytes(remainder).unwrap();
    let (t3, remainder) = T3::from_bytes(remainder).unwrap();
    let (t4, remainder) = T4::from_bytes(remainder).unwrap();
    let (t5, _) = T5::from_bytes(remainder).unwrap();
    (t1, t2, t3, t4, t5)
}

pub fn wrap_cspr(wcspr: Key, purse: URef, amount: U512) {
    let _: () = runtime::call_versioned_contract(
        wcspr.into_hash().unwrap().into(),
        None,
        "deposit",
        runtime_args! {
            "amount" => amount,
            "purse" => purse
        },
    );
}

pub fn unwrap_wcspr(wcspr: Key, to: Key, amount: U512) {
    let purse = system::create_purse();
    let _: () = runtime::call_versioned_contract(
        wcspr.into_hash().unwrap().into(),
        None,
        "withdraw",
        runtime_args! {
            "amount" => amount,
            "purse" => purse
        },
    );
    system::transfer_to_account(to.into_account().unwrap(), amount, None).unwrap_or_revert();
}

pub fn u256_to_u512(nb: U256) -> U512 {
    let mut b = [0u8; 32];
    nb.to_big_endian(&mut b);
    U512::from_big_endian(&b)
}

pub fn u512_to_u256(nb: U512) -> U256 {
    let mut b = [0u8; 64];
    nb.to_big_endian(&mut b);
    U256::from_big_endian(&b[32..64])
}

pub(crate) fn get_named_arg_size(name: &str) -> Option<usize> {
    let mut arg_size: usize = 0;
    let ret = unsafe {
        ext_ffi::casper_get_named_arg_size(
            name.as_bytes().as_ptr(),
            name.len(),
            &mut arg_size as *mut usize,
        )
    };
    match api_error::result_from(ret) {
        Ok(_) => Some(arg_size),
        Err(ApiError::MissingArgument) => None,
        Err(e) => runtime::revert(e),
    }
}

// The optional here is literal and does not co-relate to an Option enum type.
// If the argument has been provided it is accepted, and is then turned into a Some.
// If the argument is not provided at all, then it is considered as None.
pub fn get_optional_named_arg_with_user_errors<T: FromBytes>(
    name: &str,
    invalid: ApiError,
) -> Option<T> {
    match get_named_arg_with_user_errors::<T>(name, Error::Phantom.into(), invalid) {
        Ok(val) => Some(val),
        Err(_) => None,
    }
}

pub(crate) fn get_named_arg_with_user_errors<T: FromBytes>(
    name: &str,
    missing: ApiError,
    invalid: ApiError,
) -> Result<T, ApiError> {
    let arg_size = get_named_arg_size(name).ok_or(missing)?;
    let arg_bytes = if arg_size > 0 {
        let res = {
            let data_non_null_ptr = contract_api::alloc_bytes(arg_size);
            let ret = unsafe {
                ext_ffi::casper_get_named_arg(
                    name.as_bytes().as_ptr(),
                    name.len(),
                    data_non_null_ptr.as_ptr(),
                    arg_size,
                )
            };
            let data =
                unsafe { Vec::from_raw_parts(data_non_null_ptr.as_ptr(), arg_size, arg_size) };
            api_error::result_from(ret).map(|_| data)
        };
        // Assumed to be safe as `get_named_arg_size` checks the argument already
        res.unwrap_or_revert_with(Error::FailedToGetArgBytes)
    } else {
        // Avoids allocation with 0 bytes and a call to get_named_arg
        Vec::new()
    };

    bytesrepr::deserialize(arg_bytes).map_err(|_| invalid)
}

pub fn get_named_args_1<T: FromBytes>(names: Vec<String>) -> T {
    runtime::get_named_arg(&names[0])
}

pub fn get_named_args_2<T1: FromBytes, T2: FromBytes>(names: Vec<String>) -> (T1, T2) {
    (
        runtime::get_named_arg(&names[0]),
        runtime::get_named_arg(&names[1]),
    )
}

pub fn get_named_args_3<T1: FromBytes, T2: FromBytes, T3: FromBytes>(
    names: Vec<String>,
) -> (T1, T2, T3) {
    (
        runtime::get_named_arg(&names[0]),
        runtime::get_named_arg(&names[1]),
        runtime::get_named_arg(&names[2]),
    )
}

pub fn get_named_args_4<T1: FromBytes, T2: FromBytes, T3: FromBytes, T4: FromBytes>(
    names: Vec<String>,
) -> (T1, T2, T3, T4) {
    (
        runtime::get_named_arg(&names[0]),
        runtime::get_named_arg(&names[1]),
        runtime::get_named_arg(&names[2]),
        runtime::get_named_arg(&names[3]),
    )
}

pub fn get_named_args_5<
    T1: FromBytes,
    T2: FromBytes,
    T3: FromBytes,
    T4: FromBytes,
    T5: FromBytes,
>(
    names: Vec<String>,
) -> (T1, T2, T3, T4, T5) {
    (
        runtime::get_named_arg(&names[0]),
        runtime::get_named_arg(&names[1]),
        runtime::get_named_arg(&names[2]),
        runtime::get_named_arg(&names[3]),
        runtime::get_named_arg(&names[4]),
    )
}

pub fn get_named_args_6<
    T1: FromBytes,
    T2: FromBytes,
    T3: FromBytes,
    T4: FromBytes,
    T5: FromBytes,
    T6: FromBytes,
>(
    names: Vec<String>,
) -> (T1, T2, T3, T4, T5, T6) {
    (
        runtime::get_named_arg(&names[0]),
        runtime::get_named_arg(&names[1]),
        runtime::get_named_arg(&names[2]),
        runtime::get_named_arg(&names[3]),
        runtime::get_named_arg(&names[4]),
        runtime::get_named_arg(&names[5]),
    )
}

pub fn get_named_args_7<
    T1: FromBytes,
    T2: FromBytes,
    T3: FromBytes,
    T4: FromBytes,
    T5: FromBytes,
    T6: FromBytes,
    T7: FromBytes,
>(
    names: Vec<String>,
) -> (T1, T2, T3, T4, T5, T6, T7) {
    (
        runtime::get_named_arg(&names[0]),
        runtime::get_named_arg(&names[1]),
        runtime::get_named_arg(&names[2]),
        runtime::get_named_arg(&names[3]),
        runtime::get_named_arg(&names[4]),
        runtime::get_named_arg(&names[5]),
        runtime::get_named_arg(&names[6]),
    )
}
