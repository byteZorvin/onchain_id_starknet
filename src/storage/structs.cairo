use core::num::traits::Zero;
use onchain_id_starknet::storage::storage::StorageArrayFelt252;
use starknet::ContractAddress;
use starknet::storage::{StoragePointerWriteAccess, StoragePath, Mutable};

#[starknet::storage_node]
pub struct Key {
    pub purposes: StorageArrayFelt252,
    pub key_type: felt252,
    pub key: felt252
}

#[starknet::storage_node]
pub struct Execution {
    pub to: ContractAddress,
    pub calldata: StorageArrayFelt252,
    pub selector: felt252,
    pub approved: bool,
    pub executed: bool
}

#[starknet::storage_node]
pub struct Claim {
    pub topic: felt252,
    pub scheme: felt252,
    pub issuer: ContractAddress,
    pub signature: Signature,
    pub data: ByteArray,
    pub uri: ByteArray
}
// NOTE: Implement StoragePacking if this type of sig can comply with compact signatures
#[derive(Copy, Debug, Default, Drop, Serde, Hash, starknet::Store)]
pub struct Signature {
    pub r: felt252,
    pub s: felt252,
    pub y_parity: bool
}

// Note: Assumes purposes are already cleared
pub fn delete_key(self: StoragePath<Mutable<Key>>) {
    self.key_type.write(Zero::zero());
    self.key.write(Zero::zero());
}

pub fn delete_claim(self: StoragePath<Mutable<Claim>>) {
    self.topic.write(Zero::zero());
    self.scheme.write(Zero::zero());
    self.issuer.write(Zero::zero());
    self.signature.write(Default::default());
    self.data.write(Default::default());
    self.uri.write(Default::default());
}
