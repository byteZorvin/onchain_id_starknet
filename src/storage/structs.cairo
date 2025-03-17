use core::num::traits::{Pow, Zero};
use core::poseidon::poseidon_hash_span;
use core::starknet::storage_access::StorePacking;
use onchain_id_starknet::storage::storage::StorageArrayFelt252;
use starknet::ContractAddress;
use starknet::storage_access::{
    StorageBaseAddress, storage_address_from_base, storage_base_address_from_felt252,
};
use starknet::{Store, SyscallResult, SyscallResultTrait};

/// Struct that holds details about key.
#[derive(Drop, Copy)]
pub struct KeyDetails {
    /// 128 bit bitmap. Capable of holding 128 purposes for a single key.
    pub purposes: u128,
    /// Indicates the type of the key.
    pub key_type: u64,
}

pub impl KeyDetailsPacking of StorePacking<KeyDetails, felt252> {
    fn pack(value: KeyDetails) -> felt252 {
        u256 { low: value.purposes, high: value.key_type.into() }.try_into().unwrap()
    }

    fn unpack(value: felt252) -> KeyDetails {
        let value_u256: u256 = value.into();
        KeyDetails { purposes: value_u256.low, key_type: value_u256.high.try_into().unwrap() }
    }
}

pub trait BitmapTrait<T> {
    fn set(bitmap: T, index: usize) -> T;
    fn unset(bitmap: T, index: usize) -> T;
    fn get(bitmap: T, index: usize) -> bool;
}

impl BitmapTraitImpl of BitmapTrait<u128> {
    fn set(bitmap: u128, index: usize) -> u128 {
        bitmap | 2_u128.pow(index)
    }

    fn unset(bitmap: u128, index: usize) -> u128 {
        bitmap & (~2_u128.pow(index))
    }

    fn get(bitmap: u128, index: usize) -> bool {
        (bitmap & 2_u128.pow(index)).is_non_zero()
    }
}

/// Returns all the purposes stored in bitmap.
pub fn get_all_purposes(purposes: u128) -> Array<felt252> {
    let mut index = 0;
    let mut all_purposes = array![];
    let mut _purpose = purposes;
    while _purpose.is_non_zero() {
        if (_purpose & 1).is_non_zero() {
            all_purposes.append(index.into());
        }
        _purpose /= 2;
        index += 1;
    };
    all_purposes
}

#[starknet::storage_node]
pub struct Execution {
    /// The address of contract to call.
    pub to: ContractAddress,
    /// The entry point selector in the called contract.
    pub selector: felt252,
    /// The calldata to pass to entry point.
    pub calldata: StorageArrayFelt252,
    /// Bitmap that holds execution request status. index 0 is approved, index 1 is rejected, index
    /// 2 is executed.
    pub execution_request_status: u128,
}
// TODO: Go over comments
#[starknet::storage_node]
pub struct Claim {
    /// A `felt252` which represents the topic of the claim. (e.g. 1 biometric, 2 residence etc...)
    pub topic: felt252,
    /// The scheme with which this claim SHOULD be verified or how it should be processed. Its a
    /// felt252 for different schemes. E.g. could 3 mean contract verification, where the data will
    /// be call data, and the issuer a contract address to call (ToBeDefined). Those can also mean
    /// different key types e.g. 1 = ECDSA, 2 = RSA, etc.
    /// (ToBeDefined)
    pub scheme: felt252,
    /// The issuers identity contract address, or the address used to sign the above signature. If
    /// an identity contract, it should hold the key with which the above message was signed, if the
    /// key is not present anymore, the claim SHOULD be treated as invalid. The issuer can also be a
    /// contract address itself, at which the claim can be verified using the call data.
    pub issuer: ContractAddress,
    /// Signature which is the proof that the claim issuer issued a claim of topic for this
    /// identity. it MUST be a signed message of the following structure: TODO: Define the SNIP12
    pub signature: Signature,
    /// The hash of the claim data, sitting in another location, a bit-mask, call data, or actual
    /// data based on the claim scheme.
    pub data: ByteArray,
    /// The location of the claim, this can be HTTP links, swarm hashes, IPFS hashes, and such.
    pub uri: ByteArray,
}
// NOTE: Implement StoragePacking if this type of sig can comply with compact signatures

#[derive(Copy, Drop, Serde, Hash, Default, starknet::Store)]
pub struct StarkSignature {
    pub r: felt252,
    pub s: felt252,
    pub public_key: felt252,
}

#[derive(Copy, Drop, Serde, Hash, Default, starknet::Store)]
pub struct EthSignature {
    pub r: u256,
    pub s: u256,
    pub public_key: starknet::EthAddress,
}

impl DefaultEthAddress of Default<starknet::EthAddress> {
    fn default() -> starknet::EthAddress {
        Zero::zero()
    }
}

//#[derive(Copy, Drop, Serde, starknet::Store)]
//pub struct Secp256r1Signature {
//    pub r: u256,
//    pub s: u256,
//    pub public_key: starknet::secp256r1::Secp256r1Point
//}

#[derive(Copy, Drop, Serde, Hash)]
pub enum Signature {
    StarkSignature: StarkSignature,
    EthSignature: EthSignature,
    //SmartContract
}

impl SignatureIntoU8 of Into<Signature, u8> {
    fn into(self: Signature) -> u8 {
        match self {
            Signature::StarkSignature => 0,
            Signature::EthSignature => 1,
            //Signature::SmartContract => 2
        }
    }
}

pub mod Err {
    pub const NOT_IMPLEMENTED: felt252 = 'Not implemented!';
}

impl StoreSignature of starknet::Store<Signature> {
    /// Reads a value from storage from domain `address_domain` and base address `base`.
    fn read(address_domain: u32, base: StorageBaseAddress) -> SyscallResult<Signature> {
        let kind = Store::<u8>::read(address_domain, base).unwrap_syscall();
        let signature = match kind {
            0 => Signature::StarkSignature(
                Store::<
                    StarkSignature,
                >::read(
                    address_domain,
                    storage_base_address_from_felt252(
                        storage_address_from_base(base).into() + 1_felt252,
                    ),
                )?,
            ),
            1 => Signature::EthSignature(
                Store::<
                    EthSignature,
                >::read(
                    address_domain,
                    storage_base_address_from_felt252(
                        storage_address_from_base(base).into() + 1_felt252,
                    ),
                )?,
            ),
            //2 => Signature::SmartContract,
            _ => panic!("Invalid Signature Type"),
        };

        SyscallResult::Ok(signature)
    }
    /// Writes a value to storage to domain `address_domain` and base address `base`.
    fn write(address_domain: u32, base: StorageBaseAddress, value: Signature) -> SyscallResult<()> {
        Store::<u8>::write(address_domain, base, value.into()).unwrap_syscall();
        match value {
            Signature::StarkSignature(signature) => Store::<
                StarkSignature,
            >::write(
                address_domain,
                storage_base_address_from_felt252(
                    storage_address_from_base(base).into() + 1_felt252,
                ),
                signature,
            )?,
            Signature::EthSignature(signature) => Store::<
                EthSignature,
            >::write(
                address_domain,
                storage_base_address_from_felt252(
                    storage_address_from_base(base).into() + 1_felt252,
                ),
                signature,
            )?,
            // no-op
        //Signature::SmartContract => {},
        }
        SyscallResult::Ok(())
    }
    /// Reads a value from storage from domain `address_domain` and base address `base` at offset
    /// `offset`.
    fn read_at_offset(
        address_domain: u32, base: StorageBaseAddress, offset: u8,
    ) -> SyscallResult<Signature> {
        SyscallResult::Err(array![Err::NOT_IMPLEMENTED])
    }
    /// Writes a value to storage to domain `address_domain` and base address `base` at offset
    /// `offset`.
    fn write_at_offset(
        address_domain: u32, base: StorageBaseAddress, offset: u8, value: Signature,
    ) -> SyscallResult<()> {
        SyscallResult::Err(array![Err::NOT_IMPLEMENTED])
    }
    fn size() -> u8 {
        0
    }
}

pub fn is_valid_signature(message_hash: felt252, signature: Signature) -> bool {
    match signature {
        Signature::StarkSignature(sig) => {
            core::ecdsa::check_ecdsa_signature(message_hash, sig.public_key, sig.r, sig.s)
        },
        Signature::EthSignature(sig) => {
            starknet::eth_signature::is_eth_signature_valid(
                message_hash.into(),
                starknet::secp256_trait::Signature { r: sig.r, s: sig.s, y_parity: true },
                sig.public_key,
            )
                .is_ok()
                || starknet::eth_signature::is_eth_signature_valid(
                    message_hash.into(),
                    starknet::secp256_trait::Signature { r: sig.r, s: sig.s, y_parity: false },
                    sig.public_key,
                )
                    .is_ok()
        },
        //Signature::SmartContract
    }
}

pub fn get_public_key_hash(signature: Signature) -> felt252 {
    match signature {
        Signature::StarkSignature(sig) => poseidon_hash_span(array![sig.public_key].span()),
        Signature::EthSignature(sig) => {
            let mut serialized_pub_key: Array<felt252> = array![];
            sig.public_key.serialize(ref serialized_pub_key);
            poseidon_hash_span(serialized_pub_key.span())
        },
    }
}
