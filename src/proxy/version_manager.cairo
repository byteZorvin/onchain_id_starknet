#[starknet::interface]
pub trait IUpgradeable<TContractState> {
    fn upgrade(ref self: TContractState) -> bool;
}
#[starknet::component]
pub mod VersionManagerComponent {
    use onchain_id_starknet::interface::iimplementation_authority::{
        IImplementationAuthorityDispatcher, IImplementationAuthorityDispatcherTrait
    };
    use openzeppelin_upgrades::upgradeable::{
        UpgradeableComponent, UpgradeableComponent::InternalTrait as UpgradeableInternalTrait
    };
    use starknet::ClassHash;
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    pub struct Storage {
        VersionManager_implementation_class_hash: ClassHash,
        VersionManager_implementation_authority: ContractAddress
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {}

    #[embeddable_as(UpgradeableImpl)]
    pub impl Upgradeable<
        TContractState,
        +HasComponent<TContractState>,
        impl UpgradeImpl: UpgradeableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of super::IUpgradeable<ComponentState<TContractState>> {
        fn upgrade(ref self: ComponentState<TContractState>) -> bool {
            let ia_class_hash = IImplementationAuthorityDispatcher {
                contract_address: self.VersionManager_implementation_authority.read()
            }
                .get_implementation();
            let local_class_hash = self.VersionManager_implementation_class_hash.read();
            if ia_class_hash == local_class_hash {
                return false;
            }
            let mut upgrade_component = get_dep_component_mut!(ref self, UpgradeImpl);
            upgrade_component.upgrade(ia_class_hash);
            true
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        impl UpgradeImpl: UpgradeableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of InternalTrait<TContractState> {
        fn initialize(
            ref self: ComponentState<TContractState>, implementation_authority: ContractAddress
        ) {
            let ia_class_hash = IImplementationAuthorityDispatcher {
                contract_address: implementation_authority
            }
                .get_implementation();
            self.VersionManager_implementation_authority.write(implementation_authority);
            self.VersionManager_implementation_class_hash.write(ia_class_hash);
        }
        /// TODO: might implement custom upgrade call to use lib call instead of contract call.
        /// Cuz when contract call to self caller will be contract address which might result in
        /// elevation of priviliges.
        #[must_use]
        fn check_upgrade_and_call(
            ref self: ComponentState<TContractState>, selector: felt252, calldata: Span<felt252>
        ) -> (bool, Option<Span<felt252>>) {
            let ia_class_hash = IImplementationAuthorityDispatcher {
                contract_address: self.VersionManager_implementation_authority.read()
            }
                .get_implementation();
            let local_class_hash = self.VersionManager_implementation_class_hash.read();
            if ia_class_hash == local_class_hash {
                return (false, Option::None);
            }
            let mut upgrade_component = get_dep_component_mut!(ref self, UpgradeImpl);
            let return_data = upgrade_component.upgrade_and_call(ia_class_hash, selector, calldata);
            (true, Option::Some(return_data))
        }
    }
}
