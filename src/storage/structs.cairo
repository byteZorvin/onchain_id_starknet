use starknet::ContractAddress;
use starknet::storage::Vec;

#[starknet::storage_node]
pub struct Key {
    pub purposes: Vec<felt252>,
    pub key_type: felt252,
    pub key: felt252
}

#[starknet::storage_node]
pub struct Execution {
    pub to: ContractAddress,
    pub data: ByteArray,
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

