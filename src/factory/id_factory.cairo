#[starknet::contract]
mod IdFactory {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::factory::iid_factory::IIdFactory;
    use onchain_id_starknet::interface::{
        ierc734::{IERC734Dispatcher, IERC734DispatcherTrait},
        iimplementation_authority::{
            IImplementationAuthorityDispatcher, IImplementationAuthorityDispatcherTrait
        }
    };
    use onchain_id_starknet::storage::storage::{
        StorageArrayContractAddress, MutableStorageArrayTrait,
        ContractAddressVecToContractAddressArray, StorageArrayContractAddressIndexView,
        MutableStorageArrayContractAddressIndexView
    };
    use openzeppelin_access::ownable::ownable::OwnableComponent;
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess
    };

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableTwoStepImpl = OwnableComponent::OwnableTwoStepImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        token_factories: Map<ContractAddress, bool>,
        implementation_authority: ContractAddress,
        salt_taken: Map<felt252, bool>,
        user_identity: Map<ContractAddress, ContractAddress>,
        wallets: Map<ContractAddress, StorageArrayContractAddress>,
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
        addr: ContractAddress,
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

    pub mod Errors {
        pub fn ZERO_ADDRESS(variable_name: felt252) {
            panic!("{} : address zero", variable_name);
        }
        pub const ALREADY_FACTORY: felt252 = 'already a factory';
        pub const NOT_FACTORY: felt252 = 'not a factory';
        pub fn NEW_WALLET_ALREADY_LINKED() {
            panic!("new wallet already linked");
        }
        pub fn WALLET_NOT_LINKED() {
            panic!("wallet not linked to an identity");
        }
        pub fn MAX_WALLET_PER_IDENTITY() {
            panic!("max amount of wallets per ID exceeded");
        }
        pub fn NEW_WALLET_IS_ALREADY_TOKEN() {
            panic!("invalid argument - token address");
        }
        pub fn NOT_FACTORY_NOR_OWNER() {
            panic!("only Factory or owner can call");
        }
        pub const SALT_TAKEN: felt252 = 'salt already taken';
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
        /// This function registers an address as a token factory.
        ///
        /// # Arguments
        ///
        /// * `factory` - A 'ContractAddress' respresenting the address to be registered as token
        /// factory.
        ///
        /// # Requirements
        ///
        /// Caller must be the factory owner.
        /// `factory` must not be already registered as token factory.
        ///
        /// # Panics
        ///
        /// If called by any other address than factory owner.
        /// If `factory` already registered as token factory.
        fn add_token_factory(ref self: ContractState, factory: ContractAddress) {
            self.ownable.assert_only_owner();
            assert!(factory.is_non_zero(), "token factory address zero");
            let token_factory_storage_path = self.token_factories.entry(factory);
            assert!(!token_factory_storage_path.read(), "already a factory");
            token_factory_storage_path.write(true);
            self.emit(TokenFactoryAdded { factory });
        }

        /// This function unregisters an address previously registered as token factory.
        ///
        /// # Arguments
        ///
        /// * `factory` - A 'ContractAddress' respresenting the address of token factory to be
        /// unregistered.
        ///
        /// # Requirements
        ///
        /// Caller must be the factory owner.
        /// `factory` must be already registered as token factory.
        ///
        /// # Panics
        ///
        /// If called by any other address than factory owner.
        /// If `factory` not already registered as token factory.
        fn remove_token_factory(ref self: ContractState, factory: ContractAddress) {
            self.ownable.assert_only_owner();
            assert!(factory.is_non_zero(), "token factory address zero");
            let token_factory_storage_path = self.token_factories.entry(factory);
            assert!(token_factory_storage_path.read(), "not a factory");
            token_factory_storage_path.write(false);
            self.emit(TokenFactoryRemoved { factory });
        }

        /// This function deploys a new identity from the factory
        ///
        /// # Arguments
        ///
        /// * `wallet` - A `ContractAddress` respresenting the address to be added as MANAGEMENT
        /// key.
        /// * `salt` - A `felt252` representing the salt used while deployment.
        ///
        /// # Requirements
        ///
        /// `wallet` must not linked to another identity.
        /// Unique `salt` for each deployment.
        /// Caller must be the factory owner.
        ///
        /// # Panics
        ///
        /// If called by any address other than factory owner.
        /// If `salt` is zero.
        /// If `wallet` is zero.
        /// If `wallet` already linked to an existing identity.
        /// If `salt` is already taken.
        fn create_identity(
            ref self: ContractState, wallet: ContractAddress, salt: felt252
        ) -> ContractAddress {
            self.ownable.assert_only_owner();
            if wallet.is_zero() {
                Errors::ZERO_ADDRESS('wallet');
            }
            assert!(
                salt.is_non_zero(), "salt cannot be zero"
            ); // decide felt252 ok for salt or ByteArray needed
            let oid_salt = poseidon_hash_span(array!['OID', salt].span());
            let salt_taken_storage_path = self.salt_taken.entry(oid_salt);
            assert(!salt_taken_storage_path.read(), Errors::SALT_TAKEN);
            let user_identity_storage_path = self.user_identity.entry(wallet);
            assert!(
                user_identity_storage_path.read().is_zero(), "wallet already linked to identity"
            );
            assert!(
                self.token_identity.entry(wallet).read().is_zero(),
                "wallet already linked to token identity"
            ); // solidity does not have this check ensure required
            let identity = self
                .deploy_identity(oid_salt, self.implementation_authority.read(), wallet);
            salt_taken_storage_path.write(true);
            user_identity_storage_path.write(identity);
            self.wallets.entry(identity).append().write(wallet);
            self.emit(WalletLinked { wallet, identity });
            identity
        }

        /// This function deploys a new identity from the factory, setting the wallet and listed
        /// keys as MANAGEMENT keys.
        ///
        /// # Arguments
        ///
        /// * `wallet` - A `ContractAddress` respresenting the primary owner of deployed identity
        /// contract.
        /// * `salt` - A `felt252` representing the salt used while deployment.
        /// * `management_keys` - A `Array<felt252>` representing the array of keys hash(poseidon
        /// hash) to add as MANAGEMENT keys.
        ///
        /// # Requirements
        ///
        /// `wallet` must not linked to another identity.
        /// Unique `salt` for each deployment.
        /// Caller must be the factory owner.
        /// Length of the `management_keys` should be greater than 0.
        /// `wallet` must not be in `management_keys``
        ///
        /// # Panics
        ///
        /// If called by any address other than factory owner.
        /// If `salt` is zero.
        /// If `wallet` is zero.
        /// If `wallet` already linked to an existing identity.
        /// If length of `management_keys` equals to zero.
        /// If `wallet` hash is in `management_keys`.
        /// If `salt` is already taken.
        fn create_identity_with_management_keys(
            ref self: ContractState,
            wallet: ContractAddress,
            salt: felt252,
            management_keys: Array<felt252>
        ) -> ContractAddress {
            self.ownable.assert_only_owner();
            if wallet.is_zero() {
                Errors::ZERO_ADDRESS('wallet');
            }
            assert!(
                salt.is_non_zero(), "salt cannot be zero"
            ); // decide felt252 ok for salt or ByteArray needed
            let oid_salt = poseidon_hash_span(array!['OID', salt].span());
            let salt_taken_storage_path = self.salt_taken.entry(oid_salt);
            assert(!salt_taken_storage_path.read(), Errors::SALT_TAKEN);
            let user_identity_storage_path = self.user_identity.entry(wallet);
            assert!(
                user_identity_storage_path.read().is_zero(), "wallet already linked to identity"
            );
            assert!(
                self.token_identity.entry(wallet).read().is_zero(),
                "wallet already linked to token identity"
            ); // solidity does not have this check ensure required
            assert!(management_keys.len() > 0, "invalid argument - empty list of keys");

            let identity = self
                .deploy_identity(
                    oid_salt, self.implementation_authority.read(), starknet::get_contract_address()
                );
            let mut identity_dispatcher = IERC734Dispatcher { contract_address: identity };
            // NOTE: Maybe add batch {add/remove}_key
            for key in management_keys {
                // Why not let wallet to be registered as management key, is this a flaw? wallet
                // will not be initial key but will be linked wallet?
                assert!(
                    key != poseidon_hash_span(array![wallet.into()].span()),
                    "invalid argument - wallet is also listed in management keys"
                );
                identity_dispatcher.add_key(key, 1, 1);
            };
            identity_dispatcher
                .remove_key(
                    poseidon_hash_span(array![starknet::get_contract_address().into()].span()), 1
                );
            salt_taken_storage_path.write(true);
            user_identity_storage_path.write(identity);
            self.wallets.entry(identity).append().write(wallet);
            self.emit(WalletLinked { wallet, identity });
            identity
        }

        /// This function deploys a new token identity from the factory
        ///
        /// # Arguments
        ///
        /// * `token` - A `ContractAddress` respresenting the address of the token contract.
        /// * `token_owner` - A `ContractAddress` respresenting the address of the owner of token.
        /// * `salt` - A `felt252` representing the salt used while deployment.
        ///
        /// # Requirements
        ///
        /// `token_owner` must not be zero address.
        /// `token` must not linked to another identity.
        /// Unique `salt` for each deployment.
        /// Caller must be factory owner or registered as token_factory.
        ///
        /// # Panics
        ///
        /// If called by any address other than factory owner or token_factory.
        /// If `salt` is zero.
        /// If `token` is zero address.
        /// If `token_owner` is zero address
        /// If `token` already linked to an existing identity.
        /// If `salt` is already taken.
        fn create_token_identity(
            ref self: ContractState,
            token: ContractAddress,
            token_owner: ContractAddress,
            salt: felt252
        ) -> ContractAddress {
            if !self.is_token_factory(starknet::get_caller_address())
                && self.ownable.owner() != starknet::get_caller_address() {
                Errors::NOT_FACTORY_NOR_OWNER();
            }
            if token.is_zero() {
                Errors::ZERO_ADDRESS('token');
            }
            if token_owner.is_zero() {
                Errors::ZERO_ADDRESS('token_owner');
            }
            assert!(
                salt.is_non_zero(), "salt cannot be zero"
            ); // decide felt252 ok for salt or ByteArray needed
            let token_salt = poseidon_hash_span(array!['Token', salt].span());
            let salt_taken_storage_path = self.salt_taken.entry(token_salt);
            assert(!salt_taken_storage_path.read(), Errors::SALT_TAKEN);
            let token_identity_storage_path = self.token_identity.entry(token);
            assert!(
                token_identity_storage_path.read().is_zero(),
                "wallet already linked to token identity"
            ); // solidity does not have this check ensure required
            assert!(
                self.user_identity.entry(token).read().is_zero(),
                "wallet already linked to identity"
            );
            let identity = self
                .deploy_identity(token_salt, self.implementation_authority.read(), token_owner);
            salt_taken_storage_path.write(true);
            token_identity_storage_path.write(identity);
            self.wallets.entry(identity).append().write(token);
            self.emit(TokenLinked { token, identity });
            identity
        }

        /// This function links a new wallet to existing identity of the caller.
        ///
        /// # Arguments
        ///
        /// * `new_wallet` - A 'ContractAddress' respresenting the address of wallet to link.
        ///
        /// # Requirements
        ///
        /// Caller address must be linked to an existing identity.
        /// `new_wallet` must not be already linked to an identity.
        /// `new_wallet` cannot be zero address.
        /// Cannot link more than 100 wallet per identity.
        ///
        /// # Panics
        ///
        /// If caller address is not linked to the same identity as `old_wallet`.
        /// If caller address is not linked to an existing identity.
        /// If `new_wallet` already linked to an identity.
        /// If `new_wallet` equals to zero address.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` - representing the address of identity corresponding wallet/token.
        fn link_wallet(ref self: ContractState, new_wallet: ContractAddress) {
            assert!(new_wallet.is_non_zero(), "invalid argument - zero address");
            let caller_user_identity = self
                .user_identity
                .entry(starknet::get_caller_address())
                .read();
            assert!(caller_user_identity.is_non_zero(), "wallet not linked to an identity");
            let new_wallet_user_identity_storage_path = self.user_identity.entry(new_wallet);
            assert!(
                new_wallet_user_identity_storage_path.read().is_zero(), "new wallet already linked"
            );
            assert!(
                self.token_identity.entry(new_wallet).read().is_zero(),
                "new wallet already linked token"
            );
            let caller_user_identity_wallets_storage_path = self
                .wallets
                .entry(caller_user_identity);
            assert!(
                caller_user_identity_wallets_storage_path.len() < 101,
                "max amount of wallets per ID exceeded"
            );
            new_wallet_user_identity_storage_path.write(caller_user_identity);
            caller_user_identity_wallets_storage_path.append().write(new_wallet);
            self.emit(WalletLinked { wallet: new_wallet, identity: caller_user_identity });
        }

        /// This function unlinks given wallet from an existing identity.
        ///
        /// # Arguments
        ///
        /// * `old_wallet` - A 'ContractAddress' respresenting the address of wallet to unlink.
        ///
        /// # Requirements
        ///
        /// Caller address to be linked to the same identity as `old_wallet`.
        /// Caller address cannot be `old_wallet` to keep at least 1 wallet linked to any identity.
        /// `old_wallet` cannot be zero address.
        ///
        /// # Panics
        ///
        /// If caller address is not linked to the same identity as `old_wallet`.
        /// If caller address is equalt to `old_wallet`.
        /// If `old_wallet` equals to zero address.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` - representing the address of identity corresponding wallet/token.
        fn unlink_wallet(ref self: ContractState, old_wallet: ContractAddress) {
            assert!(old_wallet.is_non_zero(), "invalid argument - zero address");
            let caller = starknet::get_caller_address();
            assert!(old_wallet != caller, "cannot be called on sender address");
            let old_wallet_user_identity_storage_path = self.user_identity.entry(old_wallet);
            let old_wallet_user_identity = old_wallet_user_identity_storage_path.read();
            assert!(
                self.user_identity.entry(caller).read() == old_wallet_user_identity,
                "only a linked wallet can unlink"
            );

            old_wallet_user_identity_storage_path.write(Zero::zero());
            let wallets_storage_path = self.wallets.entry(old_wallet_user_identity);
            for wallet_index in 0
                ..wallets_storage_path
                    .len() {
                        if wallets_storage_path[wallet_index].read() == old_wallet {
                            wallets_storage_path.delete(wallet_index);
                            break;
                        }
                    };
            self.emit(WalletUnlinked { wallet: old_wallet, identity: old_wallet_user_identity });
        }


        /// Returns identity for corresponding wallet/token
        ///
        /// # Arguments
        ///
        /// * `wallet` - A 'ContractAddress' respresenting the address of wallet/token to query for.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` - representing the address of identity corresponding wallet/token.
        fn get_identity(self: @ContractState, wallet: ContractAddress) -> ContractAddress {
            let token_identity = self.token_identity.entry(wallet).read();
            if token_identity.is_non_zero() {
                token_identity
            } else {
                self.user_identity.entry(wallet).read()
            }
        }

        /// Returns array of wallets linked to given identity
        ///
        /// # Arguments
        ///
        /// * `identity` - A 'ContractAddress' respresenting the address of identity.
        ///
        /// # Returns
        ///
        /// A `Array<ContractAddress>` - representing the addresses linked to given identity.
        fn get_wallets(self: @ContractState, identity: ContractAddress) -> Array<ContractAddress> {
            let wallet_storage_path = self.wallets.entry(identity);
            wallet_storage_path.into()
        }

        /// Returns token address linked to given identity
        ///
        /// # Arguments
        ///
        /// * `identity` - A 'ContractAddress' respresenting the address of identity.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` - representing the address of token linked to given identity.
        fn get_token(self: @ContractState, identity: ContractAddress) -> ContractAddress {
            self.token_address.entry(identity).read()
        }

        /// Determines if given address is token factory.
        ///
        /// # Arguments
        ///
        /// * `factory` - A 'ContractAddress' respresenting the address to check.
        ///
        /// # Returns
        ///
        /// A `boolean` - representing wether given address is registered as token factory. True if
        /// registered token factory.
        fn is_token_factory(self: @ContractState, factory: ContractAddress) -> bool {
            self.token_factories.entry(factory).read()
        }

        /// Determines if given 'salt' has been taken.
        ///
        /// # Arguments
        ///
        /// * `salt` - A 'felt252' respresenting the salt to check.
        ///
        /// # Returns
        ///
        /// A `boolean` - representing wether salt is taken. True for taken.
        fn is_salt_taken(self: @ContractState, salt: felt252) -> bool {
            self.salt_taken.entry(salt).read()
        }

        /// Returns the implementation authority used by this factory.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` - representing the implementation authority.
        fn implementation_authority(self: @ContractState) -> ContractAddress {
            self.implementation_authority.read()
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        /// This function deploys the identity contract referenced by the implementation authority
        /// using custom salt.
        ///
        /// # Arguments
        ///
        /// * `salt` - A `felt252` representing the salt used while deployment.
        /// * `implementation_authority` - A `ContractAddress` representing the address of
        /// implementation authority to query the implementation to deploy and set as implementation
        /// authority of identity contract.
        /// * `wallet`- A `ContractAddress` representing the initial management key for the identity
        /// to be deployed.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` - representing the deployed identity.
        fn deploy_identity(
            ref self: ContractState,
            salt: felt252,
            implementation_authority: ContractAddress,
            wallet: ContractAddress
        ) -> ContractAddress {
            let implementation_class_hash: starknet::ClassHash =
                IImplementationAuthorityDispatcher {
                contract_address: implementation_authority
            }
                .get_implementation();

            let mut ctor_data: Array<felt252> = array![
                implementation_authority.into(), wallet.into()
            ];
            let (deployed_address, _) = starknet::syscalls::deploy_syscall(
                implementation_class_hash, salt, ctor_data.span(), false
            )
                .unwrap();
            self.emit(Deployed { addr: deployed_address });
            deployed_address
        }
    }
}
