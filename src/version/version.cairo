#[starknet::interface]
pub trait IVersion<TContractState> {
    fn version(self: @TContractState) -> felt252;
}

#[starknet::component]
pub mod VersionComponent {
    #[storage]
    pub struct Storage {}

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {}

    pub const VERSION: felt252 = '0.1.0';

    #[embeddable_as(VersionImpl)]
    pub impl Version<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of super::IVersion<ComponentState<TContractState>> {
        fn version(self: @ComponentState<TContractState>) -> felt252 {
            VERSION
        }
    }
}

