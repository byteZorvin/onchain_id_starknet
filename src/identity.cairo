#[starknet::contract]
mod Identity {
    use onchain_id_starknet::identity_component::IdentityComponent;
    use onchain_id_starknet::version::version::VersionComponent;
    use starknet::ContractAddress;

    component!(path: VersionComponent, storage: version, event: VersionEvent);
    component!(path: IdentityComponent, storage: identity, event: IdentityEvent);

    #[abi(embed_v0)]
    impl VersionImpl = VersionComponent::VersionImpl<ContractState>;

    #[abi(embed_v0)]
    impl IdentityImpl = IdentityComponent::IdentityImpl<ContractState>;
    impl IdentityInternalImpl = IdentityComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        version: VersionComponent::Storage,
        #[substorage(v0)]
        identity: IdentityComponent::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        VersionEvent: VersionComponent::Event,
        #[flat]
        IdentityEvent: IdentityComponent::Event
    }

    #[constructor]
    fn constructor(ref self: ContractState, initialManagementKey: ContractAddress) {}
}
