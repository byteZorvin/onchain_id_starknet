use onchain_id_starknet::storage::structs::Signature;
use starknet::ContractAddress;

#[event]
#[derive(Drop, starknet::Event)]
pub enum ERC735Event {
    ClaimAdded: ClaimAdded,
    ClaimRemoved: ClaimRemoved,
    ClaimChanged: ClaimChanged,
}

#[derive(Drop, starknet::Event)]
pub struct ClaimAdded {
    #[key]
    claim_id: felt252,
    #[key]
    topic: u256,
    scheme: u256,
    #[key]
    issuer: ContractAddress,
    signature: Signature,
    uri: ByteArray,
    data: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct ClaimRemoved {
    #[key]
    claim_id: felt252,
    #[key]
    topic: u256,
    scheme: u256,
    #[key]
    issuer: ContractAddress,
    signature: Signature,
    uri: ByteArray,
    data: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct ClaimChanged {
    #[key]
    claim_id: felt252,
    #[key]
    topic: u256,
    scheme: u256,
    #[key]
    issuer: ContractAddress,
    signature: Signature,
    uri: ByteArray,
    data: ByteArray,
}

#[starknet::interface]
pub trait IERC735<TContractState> {
    fn add_claim(
        ref self: TContractState,
        topic: u256,
        scheme: u256,
        issuer: ContractAddress,
        signature: Signature,
        data: ByteArray,
        uri: ByteArray
    ) -> felt252;
    fn remove_claim(ref self: TContractState, claim_id: felt252) -> bool;
    fn get_claim(
        self: @TContractState, claim_id: felt252
    ) -> (u256, u256, ContractAddress, Signature, ByteArray, ByteArray); // turn this into a struct?
    fn get_claim_ids_by_topics(self: @TContractState, topic: u256) -> Array<felt252>;
}
