#[starknet::component]
pub mod IdentityComponent {
    use core::ecdsa::recover_public_key;
    use core::num::traits::{Bounded, Zero};
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::interface::{
        iidentity::{IIdentityDispatcher, IIdentityDispatcherTrait, IIdentity},
        ierc734::{IERC734, ERC734Event}, ierc735::{IERC735, ERC735Event}, ierc734, ierc735
    };
    use onchain_id_starknet::storage::{
        storage::{
            MutableFelt252VecToFelt252Array, Felt252VecToFelt252Array, MutableStorageArrayTrait,
            StorageArrayTrait, StorageArrayFelt252, StorageArrayFelt252IndexView,
            MutableStorageArrayFelt252IndexView
        },
        structs::{Signature, Key, Claim, Execution, delete_key, delete_claim}
    };
    use onchain_id_starknet::version::version::VersionComponent;
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StoragePointerReadAccess, StoragePointerWriteAccess, StoragePathEntry, StorageAsPath
    };

    #[storage]
    pub struct Storage {
        execution_nonce: felt252,
        keys: Map<felt252, Key>,
        keys_by_purpose: Map<felt252, StorageArrayFelt252>,
        executions: Map<felt252, Execution>,
        claims: Map<felt252, Claim>,
        claims_by_topic: Map<felt252, StorageArrayFelt252>,
        // TODO: Decide we need this variable or not
        initialized: bool,
        // TODO: Decide we need this variable or not
        can_interact: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        ERC734Event: ERC734Event,
        #[flat]
        ERC735Event: ERC735Event
    }

    pub mod Errors {
        pub const KEY_ALREADY_HAS_PURPOSE: felt252 = 'Key already has purpose';
        pub const KEY_DOES_NOT_HAVE_PURPOSE: felt252 = 'Key doesnt have such purpose';
        pub const CLAIM_DOES_NOT_EXIST: felt252 = 'There is no claim with this ID';
        pub const INVALID_CLAIM: felt252 = 'Invalid claim';
        pub const KEY_NOT_REGISTERED: felt252 = 'Key is not registered';
        pub const NOT_HAVE_ACTION_KEY: felt252 = 'Sender not have action key';
        pub const NOT_HAVE_MANAGEMENT_KEY: felt252 = 'Sender not have management key';
        pub const ALREADY_EXECUTED: felt252 = 'Request already executed';
        pub const NON_EXISTING_EXECUTION: felt252 = 'Non-existing execution';
        pub const ZERO_ADDRESS: felt252 = 'Zero address';
        pub const NOT_HAVE_CLAIM_KEY: felt252 = 'Sender not have claim key';
    }

    #[embeddable_as(IdentityImpl)]
    pub impl Identity<
        TContractState,
        +Drop<TContractState>,
        +HasComponent<TContractState>,
        +VersionComponent::HasComponent<TContractState>
    > of IIdentity<ComponentState<TContractState>> {
        fn is_claim_valid(
            self: @ComponentState<TContractState>,
            identity: ContractAddress,
            claim_topic: felt252,
            signature: Signature,
            data: ByteArray
        ) -> bool {
            // NOTE: How about comply with SNIP12
            let mut seralized_claim: Array<felt252> = array![];
            identity.serialize(ref seralized_claim);
            seralized_claim.append(claim_topic);
            data.serialize(ref seralized_claim);
            // TODO: Add prefix
            let data_hash = poseidon_hash_span(
                array!['Starknet Message', poseidon_hash_span(seralized_claim.span())].span()
            );
            let pub_key = self.get_recovered_public_key(signature, data_hash);
            // TODO: consider using hash required or not? Are we going to support multiple signature
            // type?
            let pub_key_hash = poseidon_hash_span(array![pub_key].span());
            self.key_has_purpose(pub_key_hash, 3)
        }
    }

    #[embeddable_as(ERC734Impl)]
    pub impl ERC734<
        TContractState,
        +Drop<TContractState>,
        +HasComponent<TContractState>,
        +VersionComponent::HasComponent<TContractState>
    > of IERC734<ComponentState<TContractState>> {
        fn add_key(
            ref self: ComponentState<TContractState>,
            key: felt252,
            purpose: felt252,
            key_type: felt252
        ) -> bool {
            self.delegated_only();
            self.only_manager();
            let mut key_storage_path = self.keys.entry(key);
            if key_storage_path.key.read() == key {
                let purposes_storage_path = key_storage_path.purposes.as_path();
                for i in 0
                    ..purposes_storage_path
                        .len() {
                            assert(
                                purpose != purposes_storage_path[i].read(),
                                Errors::KEY_ALREADY_HAS_PURPOSE
                            );
                        };
                purposes_storage_path.append().write(purpose);
            } else {
                key_storage_path.key.write(key);
                key_storage_path.key_type.write(key_type);
                key_storage_path.purposes.as_path().append().write(purpose);
            }
            self.keys_by_purpose.entry(purpose).append().write(key);
            self.emit(ERC734Event::KeyAdded(ierc734::KeyAdded { key, purpose, key_type }));
            true
        }

        fn remove_key(
            ref self: ComponentState<TContractState>, key: felt252, purpose: felt252
        ) -> bool {
            self.delegated_only();
            self.only_manager();
            let key_storage_path = self.keys.entry(key);
            assert(key_storage_path.key.read() == key, Errors::KEY_NOT_REGISTERED);

            let purposes_storage_path = key_storage_path.purposes.as_path();
            let purpose_size = purposes_storage_path.len();
            let mut purpose_index = Bounded::MAX;
            for i in 0
                ..purpose_size {
                    if purpose == purposes_storage_path[i].read() {
                        purpose_index = i;
                        break;
                    }
                };
            assert(purpose_index != Bounded::MAX, Errors::KEY_DOES_NOT_HAVE_PURPOSE);
            purposes_storage_path.delete(purpose_index);

            let keys_by_purpose_key_storage_path = self.keys_by_purpose.entry(purpose);
            let mut keys_len = keys_by_purpose_key_storage_path.len();
            // MOTE: this loops assumes that whenever key is added to keys mapping it
            // keys_by_purpose mapping is also updated thus no need to check for
            // purpose exist for key or not if this invariant holds check for
            // removal above should guarantee purpose exist for key
            let mut key_index = 0;
            for i in 0
                ..keys_len {
                    if keys_by_purpose_key_storage_path[i].read() == key {
                        key_index = i;
                        break;
                    }
                };
            keys_by_purpose_key_storage_path.delete(key_index);
            let key_type = key_storage_path.key_type.read();

            /// if (_purposes.length - 1 == 0) {
            ///     delete _keys[_key];
            ///}
            if purposes_storage_path.len().is_zero() {
                delete_key(key_storage_path);
            }

            self.emit(ERC734Event::KeyRemoved(ierc734::KeyRemoved { key, purpose, key_type }));
            true
        }

        // TODO:
        // NOTE: Solidity version uses msg.sender interchangebly for contract acccounts and signer
        // pub_key
        fn approve(
            ref self: ComponentState<TContractState>, execution_id: felt252, approve: bool
        ) -> bool {
            self.delegated_only();
            assert(
                Into::<felt252, u256>::into(execution_id) < self.execution_nonce.read().into(),
                Errors::NON_EXISTING_EXECUTION
            );
            let execution_storage_path = self.executions.entry(execution_id);
            assert(!execution_storage_path.executed.read(), Errors::ALREADY_EXECUTED);
            let caller_hash = poseidon_hash_span(
                array![starknet::get_caller_address().into()].span()
            );
            assert(self.key_has_purpose(caller_hash, 1), Errors::NOT_HAVE_MANAGEMENT_KEY);
            let to_address = execution_storage_path.to.read();
            if to_address == starknet::get_contract_address() {
                assert(self.key_has_purpose(caller_hash, 1), Errors::NOT_HAVE_MANAGEMENT_KEY);
            } else {
                assert(self.key_has_purpose(caller_hash, 2), Errors::NOT_HAVE_MANAGEMENT_KEY);
            }
            self.emit(ERC734Event::Approved(ierc734::Approved { execution_id, approved: approve }));
            if !approve {
                return false;
            }
            execution_storage_path.approved.write(true);
            let selector = execution_storage_path.selector.read();
            let calldata: Array<felt252> = execution_storage_path.calldata.deref().into();

            match starknet::syscalls::call_contract_syscall(to_address, selector, calldata.span()) {
                Result::Ok => {
                    execution_storage_path.executed.write(true);
                    self
                        .emit(
                            ERC734Event::Executed(
                                ierc734::Executed { execution_id, to: to_address, data: calldata }
                            )
                        );
                    true
                },
                Result::Err => {
                    self
                        .emit(
                            ERC734Event::ExecutionFailed(
                                ierc734::ExecutionFailed {
                                    execution_id, to: to_address, data: calldata
                                }
                            )
                        );
                    false
                },
            }
        }
        /// NOTE: Consider implementing Account interface + this so keys + ContractAddresses can
        /// call this
        fn execute(
            ref self: ComponentState<TContractState>,
            to: ContractAddress,
            selector: felt252,
            calldata: Array<felt252>
        ) -> felt252 {
            self.delegated_only();
            let execution_nonce = self.execution_nonce.read();
            let execution_storage_path = self.executions.entry(execution_nonce);
            execution_storage_path.to.write(to);
            for chunk in calldata
                .clone() {
                    execution_storage_path.calldata.deref().append().write(chunk);
                };

            self.execution_nonce.write(execution_nonce + 1);

            self
                .emit(
                    ERC734Event::ExecutionRequested(
                        ierc734::ExecutionRequested {
                            execution_id: execution_nonce, to, data: calldata
                        }
                    )
                );

            let caller_hash = poseidon_hash_span(
                array![starknet::get_caller_address().into()].span()
            );

            if self.key_has_purpose(caller_hash, 1) {
                self.approve(execution_nonce, true);
            } else if to != starknet::get_contract_address()
                && self.key_has_purpose(caller_hash, 2) {
                self.approve(execution_nonce, true);
            }

            execution_nonce
        }

        fn get_key(
            self: @ComponentState<TContractState>, key: felt252
        ) -> (Array<felt252>, felt252, felt252) {
            let key_storage_path = self.keys.entry(key);
            (
                key_storage_path.purposes.deref().into(),
                key_storage_path.key_type.read(),
                key_storage_path.key.read()
            )
        }

        fn get_key_purposes(self: @ComponentState<TContractState>, key: felt252) -> Array<felt252> {
            self.keys.entry(key).purposes.deref().into()
        }

        fn get_keys_by_purpose(
            self: @ComponentState<TContractState>, purpose: felt252
        ) -> Array<felt252> {
            self.keys_by_purpose.entry(purpose).into()
        }

        fn key_has_purpose(
            self: @ComponentState<TContractState>, key: felt252, purpose: felt252
        ) -> bool {
            let key_storage_path = self.keys.entry(key);
            if key_storage_path.key.read().is_zero() {
                return false;
            }
            let purposes_storage_path = key_storage_path.purposes.as_path();
            let mut has_purpose = false;
            for i in 0
                ..purposes_storage_path
                    .len() {
                        let _purpose = purposes_storage_path[i].read();
                        if _purpose == 1 || purpose == _purpose {
                            has_purpose = true;
                            break;
                        }
                    };
            has_purpose
        }
    }

    #[embeddable_as(ERC735Impl)]
    pub impl ERC735<
        TContractState,
        +Drop<TContractState>,
        +HasComponent<TContractState>,
        +VersionComponent::HasComponent<TContractState>,
    > of IERC735<ComponentState<TContractState>> {
        fn add_claim(
            ref self: ComponentState<TContractState>,
            topic: felt252,
            scheme: felt252,
            issuer: ContractAddress,
            signature: Signature,
            data: ByteArray,
            uri: ByteArray
        ) -> felt252 {
            self.delegated_only();
            self.only_claim_key();
            let this_address = starknet::get_contract_address();
            let is_valid_claim = IIdentityDispatcher { contract_address: issuer }
                .is_claim_valid(this_address, topic, signature, data.clone());
            if issuer != this_address {
                assert(is_valid_claim, Errors::INVALID_CLAIM);
            }

            let mut claim_data_serialized: Array<felt252> = array![];
            issuer.serialize(ref claim_data_serialized);
            topic.serialize(ref claim_data_serialized);
            let claim_id = poseidon_hash_span(claim_data_serialized.span());

            let claim_storage_path = self.claims.entry(claim_id);
            claim_storage_path.topic.write(topic);
            claim_storage_path.scheme.write(scheme);
            claim_storage_path.signature.write(signature);
            claim_storage_path.data.write(data.clone());
            claim_storage_path.uri.write(uri.clone());

            if claim_storage_path.issuer.read() != issuer {
                self.claims_by_topic.entry(topic).append().write(claim_id);
                claim_storage_path.issuer.write(issuer);
                self
                    .emit(
                        ERC735Event::ClaimAdded(
                            ierc735::ClaimAdded {
                                claim_id, topic, scheme, issuer, signature, data, uri
                            }
                        )
                    );
            } else {
                self
                    .emit(
                        ERC735Event::ClaimChanged(
                            ierc735::ClaimChanged {
                                claim_id, topic, scheme, issuer, signature, data, uri
                            }
                        )
                    );
            }

            claim_id
        }

        fn remove_claim(ref self: ComponentState<TContractState>, claim_id: felt252) -> bool {
            self.delegated_only();
            self.only_claim_key();
            let claim_storage_path = self.claims.entry(claim_id);
            let topic = claim_storage_path.topic.read();
            assert(topic.is_non_zero(), Errors::CLAIM_DOES_NOT_EXIST);
            let claims_by_topic_storage_path = self.claims_by_topic.entry(topic);
            let mut claim_index = Bounded::MAX; // TODO: Might turn into Option<index>
            let claims_len = claims_by_topic_storage_path.len();
            for i in 0
                ..claims_len {
                    if claims_by_topic_storage_path[i].read() == claim_id {
                        claim_index = i;
                        break;
                    }
                };
            assert(
                claim_index == Bounded::MAX, Errors::CLAIM_DOES_NOT_EXIST
            ); // NOTE: this check might not be necessary due to above assertion we might assume claim_id will always be there

            claims_by_topic_storage_path.delete(claim_index);

            self
                .emit(
                    ERC735Event::ClaimRemoved(
                        ierc735::ClaimRemoved {
                            claim_id,
                            topic,
                            scheme: claim_storage_path.scheme.read(),
                            issuer: claim_storage_path.issuer.read(),
                            signature: claim_storage_path.signature.read(),
                            data: claim_storage_path.data.read(),
                            uri: claim_storage_path.uri.read()
                        }
                    )
                );
            delete_claim(claim_storage_path);
            true
        }

        fn get_claim(
            self: @ComponentState<TContractState>, claim_id: felt252
        ) -> (felt252, felt252, ContractAddress, Signature, ByteArray, ByteArray) {
            let claim_storage_path = self.claims.entry(claim_id);
            (
                claim_storage_path.topic.read(),
                claim_storage_path.scheme.read(),
                claim_storage_path.issuer.read(),
                claim_storage_path.signature.read(),
                claim_storage_path.data.read(),
                claim_storage_path.uri.read()
            )
        }

        fn get_claim_ids_by_topics(
            self: @ComponentState<TContractState>, topic: felt252
        ) -> Array<felt252> {
            self.claims_by_topic.entry(topic).into()
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        +Drop<TContractState>,
        +HasComponent<TContractState>,
        +VersionComponent::HasComponent<TContractState>,
    > of InternalTrait<TContractState> {
        // TODO: Finalize decision on type of key, pub_key and ContractAddress is not interchangebly
        // used in Starknet as in EVM
        fn initialize(
            ref self: ComponentState<TContractState>, initial_management_key_hash: felt252
        ) {
            assert(initial_management_key_hash.is_non_zero(), Errors::ZERO_ADDRESS);
            let key_storage_path = self.keys.entry(initial_management_key_hash);
            key_storage_path.key.write(initial_management_key_hash);
            key_storage_path.key_type.write(1);
            key_storage_path.purposes.as_path().append().write(1);

            self.keys_by_purpose.entry(1).append().write(initial_management_key_hash);
            self
                .emit(
                    ERC734Event::KeyAdded(
                        ierc734::KeyAdded {
                            key: initial_management_key_hash, key_type: 1, purpose: 1
                        }
                    )
                );
        }

        // TODO : decide do we need this
        fn delegated_only(self: @ComponentState<TContractState>) {
            assert!(
                self.can_interact.read(), "Interacting with the library contract is forbidden."
            );
        }
        // TODO: Should caller expected to be pubkey and/or ContractAddress
        // TODO: Finalize decision on type of key, pub_key and ContractAddress is not interchangebly
        // used in Starknet as in EVM
        fn only_manager(self: @ComponentState<TContractState>) {
            let caller = starknet::get_caller_address();
            assert(
                caller == starknet::get_contract_address()
                    || self.key_has_purpose(poseidon_hash_span(array![caller.into()].span()), 1),
                Errors::NOT_HAVE_MANAGEMENT_KEY
            );
        }
        // TODO: Finalize decision on type of key, pub_key and ContractAddress is not interchangebly
        // used in Starknet as in EVM NOTE: Claim key is also represents pub_key that signs the
        // claims and this func expects it to be ContractAddress -
        // `starknet::get_contract_address()`
        fn only_claim_key(self: @ComponentState<TContractState>) {
            let caller = starknet::get_caller_address();
            assert(
                caller == starknet::get_contract_address()
                    || self.key_has_purpose(poseidon_hash_span(array![caller.into()].span()), 1),
                Errors::NOT_HAVE_CLAIM_KEY
            );
        }

        fn get_recovered_public_key(
            self: @ComponentState<TContractState>, signature: Signature, data_hash: felt252
        ) -> felt252 {
            recover_public_key(data_hash, signature.r, signature.s, signature.y_parity).unwrap()
        }
    }
}
