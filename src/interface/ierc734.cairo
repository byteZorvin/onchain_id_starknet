use starknet::ContractAddress;

#[event]
#[derive(Drop, starknet::Event)]
pub enum ERC734Event {
    Approved: Approved,
    Executed: Executed,
    ExecutionRequested: ExecutionRequested,
    ExecutionFailed: ExecutionFailed,
    KeyAdded: KeyAdded,
    KeyRemoved: KeyRemoved
}

#[derive(Drop, starknet::Event)]
pub struct Approved {
    #[key]
    execution_id: u256,
    approved: bool
}

#[derive(Drop, starknet::Event)]
pub struct Executed {
    #[key]
    execution_id: u256,
    #[key]
    to: ContractAddress,
    #[key]
    value: u256,
    data: ByteArray
}

#[derive(Drop, starknet::Event)]
pub struct ExecutionRequested {
    #[key]
    execution_id: u256,
    #[key]
    to: ContractAddress,
    #[key]
    value: u256,
    data: ByteArray
}

#[derive(Drop, starknet::Event)]
pub struct ExecutionFailed {
    #[key]
    execution_id: u256,
    #[key]
    to: ContractAddress,
    #[key]
    value: u256,
    data: ByteArray
}

#[derive(Drop, starknet::Event)]
pub struct KeyAdded {
    #[key]
    key: felt252,
    #[key]
    purpose: u256,
    #[key]
    key_type: u256
}

#[derive(Drop, starknet::Event)]
pub struct KeyRemoved {
    #[key]
    key: felt252,
    #[key]
    purpose: u256,
    #[key]
    key_type: u256
}

#[starknet::interface]
pub trait IERC734<TContractState> {
    fn add_key(ref self: TContractState, key: felt252, purpose: u256, key_type: u256) -> bool;
    fn approve(ref self: TContractState, id: u256, approve: bool) -> bool;
    fn remove_key(ref self: TContractState, key: felt252, purpose: u256) -> bool;
    fn execute(ref self: TContractState, to: ContractAddress, value: u256, data: ByteArray) -> u256;
    fn get_key(self: @TContractState, key: felt252) -> (Array<u256>, u256, felt252);
    fn get_key_purposes(self: @TContractState, key: felt252) -> Array<u256>;
    fn get_keys_by_purpose(self: @TContractState, purpose: u256) -> Array<felt252>;
    fn key_has_purpose(self: @TContractState, key: felt252, purpose: u256) -> bool;
}
