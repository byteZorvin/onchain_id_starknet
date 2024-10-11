#[starknet::contract]
mod IdFactory {
    use core::num::traits::Zero;
    use onchain_id_starknet::factory::iid_factory::IIdFactory;
    use openzeppelin_access::ownable::ownable::OwnableComponent;
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, //StorageMapReadAccess,
        StorageMapWriteAccess, // StoragePathEntry, StoragePointerReadAccess,
        StoragePointerWriteAccess, Vec, //VecTrait, MutableVecTrait,
    };

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        token_factories: Map<ContractAddress, bool>,
        implementation_authority: ContractAddress, // immutable
        salt_taken: Map<ByteArray, bool>,
        user_identity: Map<ContractAddress, ContractAddress>,
        wallets: Map<ContractAddress, Vec<ContractAddress>>,
        token_identity: Map<ContractAddress, ContractAddress>,
        token_address: Map<ContractAddress, ContractAddress>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        Deployed: Deployed,
        WalletLinked: WalletLinked,
        WalletUnlinked: WalletUnlinked,
        TokenLinked: TokenLinked,
        TokenFactoryAdded: TokenFactoryAdded,
        TokenFactoryRemoved: TokenFactoryRemoved,
        #[flat]
        OwnableEvent: OwnableComponent::Event
    }

    #[derive(Drop, starknet::Event)]
    pub struct Deployed {
        #[key]
        _addr: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct WalletLinked {
        #[key]
        wallet: ContractAddress,
        #[key]
        identity: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct WalletUnlinked {
        #[key]
        wallet: ContractAddress,
        #[key]
        identity: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenLinked {
        #[key]
        token: ContractAddress,
        #[key]
        identity: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenFactoryAdded {
        #[key]
        factory: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenFactoryRemoved {
        #[key]
        factory: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, implementation_authority: ContractAddress, owner: ContractAddress
    ) {
        assert!(implementation_authority.is_non_zero(), "implementation authority zero address");
        assert!(owner.is_non_zero(), "owner is zero address");
        self.implementation_authority.write(implementation_authority);
        self.ownable.initializer(owner);
    }

    #[abi(embed_v0)]
    impl IdFactoryImpl of IIdFactory<ContractState> {
        fn add_token_factory(ref self: ContractState, factory: ContractAddress) {
            self.ownable.assert_only_owner();
            assert!(factory.is_non_zero(), "token factory address zero");
            assert!(!self.is_token_factory(factory), "already a factory");
            self.token_factories.write(factory, true);
            self.emit(TokenFactoryAdded { factory });
        }

        fn remove_token_factory(ref self: ContractState, factory: ContractAddress) {
            self.ownable.assert_only_owner();
            assert!(factory.is_non_zero(), "token factory address zero");
            assert!(self.is_token_factory(factory), "not a factory");
            self.token_factories.write(factory, false);
            self.emit(TokenFactoryRemoved { factory });
        }

        fn create_identity(
            ref self: ContractState, wallet: ContractAddress, salt: ByteArray
        ) -> ContractAddress {
            Zero::zero()
        }

        fn create_identity_with_management_keys(
            ref self: ContractState,
            wallet: ContractAddress,
            salt: ByteArray,
            management_keys: Array<felt252>
        ) -> ContractAddress {
            Zero::zero()
        }

        fn create_token_identity(
            ref self: ContractState,
            token: ContractAddress,
            token_owner: ContractAddress,
            salt: ByteArray
        ) -> ContractAddress {
            Zero::zero()
        }

        fn link_wallet(ref self: ContractState, new_wallet: ContractAddress) {}

        fn unlink_wallet(ref self: ContractState, old_wallet: ContractAddress) {}

        fn get_identity(self: @ContractState, wallet: ContractAddress) -> ContractAddress {
            Zero::zero()
        }

        fn get_wallets(self: @ContractState, identity: ContractAddress) -> Array<ContractAddress> {
            array![]
        }
        fn get_token(self: @ContractState, identity: ContractAddress) -> ContractAddress {
            Zero::zero()
        }
        fn is_token_factory(self: @ContractState, factory: ContractAddress) -> bool {
            true
        }
        fn is_salt_taken(self: @ContractState, salt: ByteArray) -> bool {
            true
        }
        fn implemenatation_authority(self: @ContractState) -> ContractAddress {
            Zero::zero()
        }
    }
}
