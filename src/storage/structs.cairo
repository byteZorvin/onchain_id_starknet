use core::num::traits::Zero;
use core::poseidon::poseidon_hash_span;
use onchain_id_starknet::storage::storage::StorageArrayFelt252;
use starknet::ContractAddress;
use starknet::storage::{StoragePointerWriteAccess, StoragePath, Mutable,};
use starknet::storage_access::{
    StorageBaseAddress, storage_address_from_base, storage_base_address_from_felt252
};
use starknet::{SyscallResult, SyscallResultTrait, Store,};

// TODO: Go over comments
#[starknet::storage_node]
pub struct Key {
    /// Array of the key purposes, like 1 = MANAGEMENT, 2 = EXECUTION.
    pub purposes: StorageArrayFelt252,
    /// The type of key used, which would be a uint256 for different key types. e.g. 1 = ECDSA, 2 =
    /// RSA, etc.
    pub key_type: felt252,
    /// Hash of the public key or ContractAddress
    pub key: felt252
}

#[starknet::storage_node]
pub struct Execution {
    /// The address of contract to call.
    pub to: ContractAddress,
    /// The entry point selector in the called contract.
    pub selector: felt252,
    /// The calldata to pass to entry point.
    pub calldata: StorageArrayFelt252,
    /// The bool that indicates if execution is approved or not.
    pub approved: bool,
    /// The bool that indicates if execution is already executed or not.
    pub executed: bool
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
    pub uri: ByteArray
}
// NOTE: Implement StoragePacking if this type of sig can comply with compact signatures

// Note: Assumes purposes are already cleared
pub fn delete_key(self: StoragePath<Mutable<Key>>) {
    self.key_type.write(Zero::zero());
    self.key.write(Zero::zero());
}

pub fn delete_claim(self: StoragePath<Mutable<Claim>>) {
    self.topic.write(Default::default());
    self.scheme.write(Default::default());
    self.issuer.write(Zero::zero());
    //self.signature.write(Default::default());
    self.data.write(Default::default());
    self.uri.write(Default::default());
}

#[derive(Copy, Drop, Serde, Hash, Default, starknet::Store)]
pub struct StarkSignature {
    pub r: felt252,
    pub s: felt252,
    pub public_key: felt252
}

#[derive(Copy, Drop, Serde, Hash, Default, starknet::Store)]
pub struct EthSignature {
    pub r: u256,
    pub s: u256,
    pub public_key: starknet::EthAddress
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
                    StarkSignature
                >::read(
                    address_domain,
                    storage_base_address_from_felt252(
                        storage_address_from_base(base).into() + 1_felt252
                    )
                )?
            ),
            1 => Signature::EthSignature(
                Store::<
                    EthSignature
                >::read(
                    address_domain,
                    storage_base_address_from_felt252(
                        storage_address_from_base(base).into() + 1_felt252
                    )
                )?
            ),
            //2 => Signature::SmartContract,
            _ => panic!("Invalid Signature Type")
        };

        SyscallResult::Ok(signature)
    }
    /// Writes a value to storage to domain `address_domain` and base address `base`.
    fn write(address_domain: u32, base: StorageBaseAddress, value: Signature) -> SyscallResult<()> {
        Store::<u8>::write(address_domain, base, value.into()).unwrap_syscall();
        match value {
            Signature::StarkSignature(signature) => Store::<
                StarkSignature
            >::write(
                address_domain,
                storage_base_address_from_felt252(
                    storage_address_from_base(base).into() + 1_felt252
                ),
                signature
            )?,
            Signature::EthSignature(signature) => Store::<
                EthSignature
            >::write(
                address_domain,
                storage_base_address_from_felt252(
                    storage_address_from_base(base).into() + 1_felt252
                ),
                signature
            )?,
            // no-op
        //Signature::SmartContract => {},
        }
        SyscallResult::Ok(())
    }
    /// Reads a value from storage from domain `address_domain` and base address `base` at offset
    /// `offset`.
    fn read_at_offset(
        address_domain: u32, base: StorageBaseAddress, offset: u8
    ) -> SyscallResult<Signature> {
        SyscallResult::Err(array![Err::NOT_IMPLEMENTED])
    }
    /// Writes a value to storage to domain `address_domain` and base address `base` at offset
    /// `offset`.
    fn write_at_offset(
        address_domain: u32, base: StorageBaseAddress, offset: u8, value: Signature
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
                sig.public_key
            )
                .is_ok()
                || starknet::eth_signature::is_eth_signature_valid(
                    message_hash.into(),
                    starknet::secp256_trait::Signature { r: sig.r, s: sig.s, y_parity: false },
                    sig.public_key
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
        }
    }
}
