pub const VERSION: felt252 = '0.1.0';

#[starknet::interface]
pub trait Version<TContractState> {
    fn version(self: @TContractState) -> felt252 {
        VERSION
    }
}
