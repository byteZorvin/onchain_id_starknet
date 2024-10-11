use starknet::ContractAddress;
use starknet::storage::Vec;

#[starknet::storage_node]
pub struct Key {
    purposes: Vec<u256>,
    key_type: u256,
    key: felt252
}

#[starknet::storage_node]
pub struct Execution {
    to: ContractAddress,
    value: u256,
    data: ByteArray,
    approved: bool,
    executed: bool
}

#[starknet::storage_node]
pub struct Claim {
    topic: u256,
    scheme: u256,
    issuer: ContractAddress,
    signature: Signature,
    data: ByteArray,
    uri: ByteArray
}

#[derive(Copy, Debug, Default, Drop, Serde, starknet::Store)]
pub struct Signature {
    pub r: felt252,
    pub s: felt252,
}

pub type SignatureHash = felt252;
