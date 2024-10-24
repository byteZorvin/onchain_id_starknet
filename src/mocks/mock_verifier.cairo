#[starknet::interface]
pub trait IMockVerifier<TContractState> {
    fn do_something(ref self: TContractState);
}

#[starknet::contract]
pub mod MockVerifier {
    use onchain_id_starknet::verifiers::verifier::VerifierComponent;
    use openzeppelin_access::ownable::ownable::OwnableComponent;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    component!(path: VerifierComponent, storage: verifier, event: VerifierEvent);

    #[abi(embed_v0)]
    impl VerifierImpl = VerifierComponent::VerifierABIImpl<ContractState>;
    impl VerifierInternalImpl = VerifierComponent::InternalImpl<ContractState>;

    #[storage]
    pub struct Storage {
        #[substorage(v0)]
        verifier: VerifierComponent::Storage,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        VerifierEvent: VerifierComponent::Event,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: starknet::ContractAddress) {
        self.ownable.initializer(owner);
    }

    #[abi(embed_v0)]
    pub impl MockVerifierImpl of super::IMockVerifier<ContractState> {
        fn do_something(ref self: ContractState) {
            self.verifier.only_verified_sender();
        }
    }
}
