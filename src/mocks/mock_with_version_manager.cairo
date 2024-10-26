#[starknet::interface]
pub trait IMockWithVersionManager<TContractState> {
    fn do_something(ref self: TContractState);
}

#[starknet::contract]
pub mod MockWithVersionManager {
    use onchain_id_starknet::proxy::version_manager::VersionManagerComponent;
    use openzeppelin_upgrades::upgradeable::UpgradeableComponent;
    use starknet::ContractAddress;

    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    component!(path: VersionManagerComponent, storage: version_manager, event: VersionManagerEvent);

    #[abi(embed_v0)]
    impl UpgradeableImpl = VersionManagerComponent::UpgradeableImpl<ContractState>;
    impl VersionManagerInternalImpl = VersionManagerComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        version_manager: VersionManagerComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        VersionManagerEvent: VersionManagerComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState, implementation_authority: ContractAddress) {
        self.version_manager.initialize(implementation_authority);
    }

    #[abi(embed_v0)]
    impl MockWithVersionManagerImpl of super::IMockWithVersionManager<ContractState> {
        fn do_something(ref self: ContractState) {
            self.version_manager.assert_up_to_date_implementation();
        }
    }
}
