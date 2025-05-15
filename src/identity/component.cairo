//! The `IdentityComponent` is a crucial part of the OnchainID protocol, responsible for managing
//! identities and their associated claims. It implements the IERC734 `KeyHolder` and IERC735
//! `ClaimHolder` interfaces, providing a robust framework for identity management on the Starknet
//! blockchain.
//!
//! # Features
//!
//! - **Key Management**: Functions for adding/removing keys and their purposes. Provides getters
//! for the key details. Purposes are limited to 128 at most, and key types are limited to
//! 64 at most. Keys are stored as hash of the public key, in order to support various key types.
//!
//! - **Arbitrary External Calls**: Functions to create arbitrary execution requests and make
//! external calls on behalf of the Identity itself.
//!
//! - **Claim Management**: Functions for adding, updating, and removing claims, along with getters
//! for them. Signature/Proof field of claim is stored as `Vec<felt252>` to hold arbitrary proof to
//! allow various verification schemas.
//!
//! - **Claim Validation**: Validates claims using Stark signatures over SNIP12 compliant hashed
//! claims. Additional verifications schemas can be introduced by enhancing `Signature` enum with
//! different proof schemas or completely replacing 'IIdentity' interface implementation with custom
//! one rather than using `IIdentity` implementation provided by this component while utilizing the
//! `ERC734` and `ERC735` implementations.
//!
//! # Constants
//!
//! - `Purpose`: Defines roles for role-based authentication for keys, including management, action,
//!   and claim purposes.
//!
//! This component is intended for use within the OnchainID protocol providing core functionalities
//! for Identity.
//!
//! ## Security Notice
//!
//! This component has not undergone a formal security audit and should be considered experimental.
//! Users should exercise caution when implementing or deploying this code in production
//! environments.

#[starknet::component]
pub mod IdentityComponent {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use openzeppelin_utils::cryptography::interface::ISNIP12Metadata;
    use openzeppelin_utils::cryptography::snip12::{OffchainMessageHash, SNIP12Metadata};
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, MutableVecTrait, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
        Vec, StorageAsPath
    };
    use crate::identity::interface::ierc734::{ERC734Event, IERC734};
    use crate::identity::interface::ierc735::{ERC735Event, IERC735};
    use crate::identity::interface::iidentity::{
        IIdentity, IIdentityDispatcher, IIdentityDispatcherTrait,
    };
    use crate::identity::interface::{ierc734, ierc735};
    use crate::identity::structs::{
        Claim, Execution, ExecutionRequestStatus, KeyDetails, KeyDetailsTrait,
    };
    use crate::libraries::signature::{ClaimMessage, get_public_key_hash, is_valid_signature};
    use crate::libraries::vec_ext::VecToArrayTrait;

    #[storage]
    pub struct Storage {
        Identity_execution_nonce: felt252,
        Identity_keys: Map<felt252, KeyDetails>,
        Identity_keys_by_purpose: Map<felt252, Vec<felt252>>,
        Identity_executions: Map<felt252, Execution>,
        Identity_claims: Map<felt252, Claim>,
        Identity_claims_by_topic: Map<felt252, Vec<felt252>>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        ERC734Event: ERC734Event,
        #[flat]
        ERC735Event: ERC735Event,
    }

    pub mod Errors {
        pub const KEY_ALREADY_HAS_PURPOSE: felt252 = 'Key already has given purpose';
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
        pub const EXECUTION_REJECTED: felt252 = 'Request has been rejected';
    }

    pub mod Purpose {
        pub const MANAGEMENT: felt252 = 1;
        pub const ACTION: felt252 = 2;
        pub const CLAIM: felt252 = 3;
    }

    #[embeddable_as(IdentityImpl)]
    pub impl Identity<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>, +SNIP12Metadata,
    > of IIdentity<ComponentState<TContractState>> {
        /// Checks if a claim is valid for given identity.
        ///
        /// # Arguments
        ///
        /// * `identity` - `ContractAddress` representing the identity related to claim.
        /// * `claim_topic` - `felt252` representing the topic of the claim.
        /// * `signature` - `Span<felt252> representing the signature of the claim`.
        /// * `data` - `ByteArray` representing the data field of the claim.
        ///
        /// # Requirements
        ///
        /// - The issuer of the claim must have a key with CLAIM purpose on the identity.
        ///
        /// # Dev
        ///
        /// - Identity does not have a built-in revocation mechanism and claims are considered valid
        /// as long as their signature is valid and they are stored by the identity contract.
        ///
        /// # Returns
        ///
        /// A `bool` indicating whether claim is valid or not.
        fn is_claim_valid(
            self: @ComponentState<TContractState>,
            identity: ContractAddress,
            claim_topic: felt252,
            signature: Span<felt252>,
            data: Span<felt252>,
        ) -> bool {
            let pub_key_hash = get_public_key_hash(signature);
            if !self.key_has_purpose(pub_key_hash, Purpose::CLAIM) {
                return false;
            }

            let message = ClaimMessage { identity, topic: claim_topic, data };

            let message_hash = message.get_message_hash(starknet::get_contract_address());

            is_valid_signature(message_hash, signature)
        }
    }

    #[embeddable_as(ERC734Impl)]
    pub impl ERC734<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>,
    > of IERC734<ComponentState<TContractState>> {
        /// This function adds a key to the identity with given purpose, creates the key if not
        /// present else adds purpose
        ///
        /// # Arguments
        ///
        /// * `key` - A `felt252` representing hash of the key(public key, ContractAddress).
        /// * `purpose` A `felt252` representing the purpose of key. For example 1 : MANAGEMENT, 2 :
        /// ACTION, 3: CLAIM.
        /// * `key_type` TODO: To Be Defined!
        ///
        /// # Requirements
        ///
        /// Must called by this contract or caller has MANAGEMENT key.
        /// - `key` must not already have given purpose.
        ///
        /// # Returns
        ///
        /// A `bool` indicating whether key is added successfully or not
        fn add_key(
            ref self: ComponentState<TContractState>,
            key: felt252,
            purpose: felt252,
            key_type: felt252,
        ) -> bool {
            self.only_manager();
            let key_storage = self.Identity_keys.entry(key);
            let mut key_details = key_storage.read();
            let purpose_bit_index = purpose.try_into().expect('Invalid Purpose');
            assert(!key_details.has_purpose(purpose_bit_index), Errors::KEY_ALREADY_HAS_PURPOSE);
            key_details.grant_purpose(purpose_bit_index);
            key_details.key_type = key_type.try_into().expect('Invalid Key Type');
            key_storage.write(key_details);

            self.Identity_keys_by_purpose.entry(purpose).append().write(key);
            self.emit(ERC734Event::KeyAdded(ierc734::KeyAdded { key, purpose, key_type }));
            true
        }

        /// This function removes given purpose from key of identity.
        ///
        /// # Arguments
        ///
        /// * `key` - A `felt252` representing hash of the key(public key, ContractAddress).
        /// * `purpose` A `felt252` representing the purpose of key. For example 1 : MANAGEMENT, 2 :
        /// ACTION, 3: CLAIM.
        ///
        /// # Requirements
        ///
        /// Must called by this contract or caller has MANAGEMENT key.
        /// - `key` should be registered and has the given purpose.
        ///
        /// # Returns
        ///
        /// A `bool` indicating whether key is removed successfully or not
        fn remove_key(
            ref self: ComponentState<TContractState>, key: felt252, purpose: felt252,
        ) -> bool {
            self.only_manager();
            let key_storage = self.Identity_keys.entry(key);
            let mut key_details = key_storage.read();
            assert(key_details.purposes.is_non_zero(), Errors::KEY_NOT_REGISTERED);
            assert(key_details.has_purpose(purpose), Errors::KEY_DOES_NOT_HAVE_PURPOSE);

            key_details.revoke_purpose(purpose);

            let key_type: felt252 = key_details.key_type.into();
            if key_details.purposes.is_zero() {
                key_details.key_type = Zero::zero();
            }

            key_storage.write(key_details);

            let keys_by_purpose_key_storage = self.Identity_keys_by_purpose.entry(purpose);
            // let mut iterator = keys_by_purpose_key_storage.into_iter_full_range().enumerate();

            // let (index, _) = iterator
            //     .find(|iter| {
            //         let (_, storage) = iter;
            //         storage.read() == key
            //     })
            //     .expect(Errors::KEY_DOES_NOT_HAVE_PURPOSE);

            let mut index = 0;
            {
                let mut found = false;
                for i in 0..keys_by_purpose_key_storage.len() {
                    if keys_by_purpose_key_storage.at(i).read() == key {
                        index = i;
                        found = true;
                        break;
                    }
                };
                assert(found, Errors::KEY_DOES_NOT_HAVE_PURPOSE);
            }

            // TODO: Fix this
            // keys_by_purpose_key_storage
            //     .pop_swap(index.into(), keys_by_purpose_key_storage.__base_address__);
            self.emit(ERC734Event::KeyRemoved(ierc734::KeyRemoved { key, purpose, key_type }));
            true
        }

        /// This function approves or reject the execution with given execution_id.
        ///
        /// # Arguments
        ///
        /// * `execution_id` A `felt252` representing the identifier of execution to approve/reject.
        /// * `approve` A `bool` representing the status of approval. (true for approve, false
        /// for reject).
        ///
        /// # Requirements
        ///
        /// - If target of the call is identity itself caller should have MANAGEMENT key else ACTION
        /// key.
        /// - Execution request must not be already executed or rejected.
        ///
        /// # Returns
        ///
        /// A `bool` indicating success of approve operation.
        fn approve(
            ref self: ComponentState<TContractState>, execution_id: felt252, approve: bool,
        ) -> bool {
            assert(
                Into::<felt252, u256>::into(execution_id) < self
                    .Identity_execution_nonce
                    .read()
                    .into(),
                Errors::NON_EXISTING_EXECUTION,
            );
            let execution_storage = self.Identity_executions.entry(execution_id);
            let mut execution_request_status = execution_storage.execution_request_status.read();

            assert(
                execution_request_status != ExecutionRequestStatus::Executed,
                Errors::ALREADY_EXECUTED,
            );
            assert(
                execution_request_status != ExecutionRequestStatus::Rejected,
                Errors::EXECUTION_REJECTED,
            );
            let caller_hash = poseidon_hash_span(
                array![starknet::get_caller_address().into()].span(),
            );
            let to_address = execution_storage.to.read();
            if to_address == starknet::get_contract_address() {
                assert(
                    self.key_has_purpose(caller_hash, Purpose::MANAGEMENT),
                    Errors::NOT_HAVE_MANAGEMENT_KEY,
                );
            } else {
                assert(
                    self.key_has_purpose(caller_hash, Purpose::ACTION), Errors::NOT_HAVE_ACTION_KEY,
                );
            }
            self.emit(ERC734Event::Approved(ierc734::Approved { execution_id, approved: approve }));
            if !approve {
                execution_storage.execution_request_status.write(ExecutionRequestStatus::Rejected);
                return false;
            }

            execution_request_status = ExecutionRequestStatus::Approved;
            let selector = execution_storage.selector.read();

            let calldata = execution_storage.calldata.to_array().span();

            let execution_result =
                match starknet::syscalls::call_contract_syscall(to_address, selector, calldata) {
                Result::Ok => {
                    self
                        .emit(
                            ERC734Event::Executed(
                                ierc734::Executed {
                                    execution_id, to: to_address, selector, data: calldata,
                                },
                            ),
                        );
                    true
                },
                Result::Err => {
                    self
                        .emit(
                            ERC734Event::ExecutionFailed(
                                ierc734::ExecutionFailed {
                                    execution_id, to: to_address, selector, data: calldata,
                                },
                            ),
                        );
                    false
                },
            };

            if execution_result {
                execution_request_status = ExecutionRequestStatus::Executed;
            }
            execution_storage.execution_request_status.write(execution_request_status);

            execution_result
        }

        /// Passes execution request to the key manager, executed immediately if caller has MANAGENT
        /// key or ACTION key if target is not self. Else execution request is stored to get
        /// approval by authorized key.
        ///
        /// # Arguments
        ///
        /// * `to` - `ContractAddress` to call.
        /// * `selector` - Selector of the function to call.
        /// * `calldata` - Arguments to pass to external call.
        ///
        /// # Returns
        ///
        /// A `felt252` representing execution ID.
        fn execute(
            ref self: ComponentState<TContractState>,
            to: ContractAddress,
            selector: felt252,
            calldata: Span<felt252>,
        ) -> felt252 {
            let execution_nonce = self.Identity_execution_nonce.read();
            self.Identity_execution_nonce.write(execution_nonce + 1);

            let execution_storage = self.Identity_executions.entry(execution_nonce);
            execution_storage.to.write(to);
            execution_storage.selector.write(selector);
            let calldata_storage = execution_storage.calldata.deref();
            for chunk in calldata {
                calldata_storage.append().write(*chunk);
            };

            self
                .emit(
                    ERC734Event::ExecutionRequested(
                        ierc734::ExecutionRequested {
                            execution_id: execution_nonce, to, selector, data: calldata,
                        },
                    ),
                );

            let caller_hash = poseidon_hash_span(
                array![starknet::get_caller_address().into()].span(),
            );

            if to != starknet::get_contract_address()
                && self.key_has_purpose(caller_hash, Purpose::ACTION) {
                self._approve(execution_nonce, to, selector, calldata);
            } else if self.key_has_purpose(caller_hash, Purpose::MANAGEMENT) {
                self._approve(execution_nonce, to, selector, calldata);
            }

            execution_nonce
        }

        /// Returns the full key data
        ///
        /// # Arguments
        ///
        /// * `key` A `felt252` representing key identifier (hash of public key, ContractAddress).
        ///
        /// # Returns
        ///
        /// A `Span<felt252>` representing purposes this key has.
        /// A `felt252` representing key_type of the key.
        /// A `felt252` representing the hashed key.
        fn get_key(
            self: @ComponentState<TContractState>, key: felt252,
        ) -> (Span<felt252>, felt252, felt252) {
            let key_details = self.Identity_keys.entry(key).read();
            if key_details.purposes.is_zero() {
                return ([].span(), Zero::zero(), Zero::zero());
            }
            (key_details.get_all_purposes().span(), key_details.key_type.into(), key)
        }

        /// Returns the purposes given key has.
        ///
        /// # Arguments
        ///
        /// * `key` A `felt252` representing the key to get purposes for.
        ///
        /// # Returns
        ///
        /// A `Span<felt252>` representing the array of purposes given key has.
        fn get_key_purposes(self: @ComponentState<TContractState>, key: felt252) -> Span<felt252> {
            self.Identity_keys.entry(key).read().get_all_purposes().span()
        }

        /// Returns the keys which has given purpose.
        ///
        /// # Arguments
        ///
        /// * `purpose` A `felt252` representing the purpose to get keys for.
        ///
        /// # Returns
        ///
        /// A `Span<felt252>` representing the array of keys which has given purpose.
        fn get_keys_by_purpose(
            self: @ComponentState<TContractState>, purpose: felt252,
        ) -> Span<felt252> {
            self.Identity_keys_by_purpose.entry(purpose).to_array().span()
        }

        /// Determines if key has given purpose.
        ///
        /// # Arguments
        ///
        /// * `key` A `felt252` representing the key to query for.
        /// * `purpose` A `felt252` representing the purpose to query for.
        ///
        /// # Returns
        ///
        /// A `bool` representing the key has given purpose or not.
        fn key_has_purpose(
            self: @ComponentState<TContractState>, key: felt252, purpose: felt252,
        ) -> bool {
            let key_details = self.Identity_keys.entry(key).read();
            key_details.has_purpose(Purpose::MANAGEMENT) || key_details.has_purpose(purpose)
        }
    }

    #[embeddable_as(ERC735Impl)]
    pub impl ERC735<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>,
    > of IERC735<ComponentState<TContractState>> {
        /// Registers a claim, if the claim already exists, it will update the existing claim
        /// instead of creating a new one.
        ///
        /// # Arguments
        ///
        /// * `topic` - Topic of the claim.
        /// * `scheme` - The scheme that describes how to verify the claim.
        /// * `issuer` - The issuers identity contract address.
        /// * `signature` - Signature of the claim, which is a proof that claim is issued by
        /// provided issuer.
        /// * `data` - Any data attached to claim, usually a hash of the data to not leak private
        /// information.
        /// * `uri` - Pointer to the location of the claim, such as HTTP links, IPFS hashes.
        ///
        /// # Dev
        ///
        /// - Self attested claims are not validated by this function, one can register invalid
        /// claims if self attested.
        /// - Issuer and topic cannot be updated since change in those parameters yields in
        /// different claim_id.
        ///
        /// # Returns
        ///
        /// A `felt252` representing the id of the claim.
        fn add_claim(
            ref self: ComponentState<TContractState>,
            topic: felt252,
            scheme: felt252,
            issuer: ContractAddress,
            signature: Span<felt252>,
            data: Span<felt252>,
            uri: ByteArray,
        ) -> felt252 {
            self.only_claim_key();
            let this_address = starknet::get_contract_address();

            if issuer != this_address {
                let is_valid_claim = IIdentityDispatcher { contract_address: issuer }
                    .is_claim_valid(this_address, topic, signature, data);
                assert(is_valid_claim, Errors::INVALID_CLAIM);
            }

            let claim_id = poseidon_hash_span([issuer.into(), topic].span());

            let claim_storage = self.Identity_claims.entry(claim_id);

            claim_storage.scheme.write(scheme);

            let signature_storage = claim_storage.signature.deref();
            // TODO: Fix this
            // signature_storage.clear(claim_storage.signature.as_path().__base_address__);


            for chunk in signature {
                signature_storage.append().write(*chunk);
            };

            let data_storage = claim_storage.data.deref();

            // TODO: Fix this
            // data_storage.clear();
            for chunk in data {
                data_storage.append().write(*chunk);
            };

            claim_storage.uri.write(uri.clone());

            if claim_storage.issuer.read().is_zero() {
                self.Identity_claims_by_topic.entry(topic).append().write(claim_id);
                claim_storage.issuer.write(issuer);
                claim_storage.topic.write(topic);
                self
                    .emit(
                        ERC735Event::ClaimAdded(
                            ierc735::ClaimAdded {
                                claim_id, topic, scheme, issuer, signature, data, uri,
                            },
                        ),
                    );
            } else {
                self
                    .emit(
                        ERC735Event::ClaimChanged(
                            ierc735::ClaimChanged {
                                claim_id, topic, scheme, issuer, signature, data, uri,
                            },
                        ),
                    );
            }

            claim_id
        }

        /// Removes claim from identity.
        ///
        /// # Arguments
        ///
        /// * `claim_id` - Identifier of the claim to remove.
        ///
        /// # Requirements
        ///
        /// - Caller must have CLAIM key.
        ///
        /// # Returns
        ///
        /// A `bool` true if claim removed successfully.
        fn remove_claim(ref self: ComponentState<TContractState>, claim_id: felt252) -> bool {
            self.only_claim_key();
            let claim_storage = self.Identity_claims.entry(claim_id);
            let topic = claim_storage.topic.read();
            assert(topic.is_non_zero(), Errors::CLAIM_DOES_NOT_EXIST);

            let mut claims_by_topic_storage = self.Identity_claims_by_topic.entry(topic);
            // let mut iterator = claims_by_topic_storage.into_iter_full_range().enumerate();
            // let (index, _) = iterator
            //     .find(|iter| {
            //         let (_, storage) = iter;
            //         storage.read() == claim_id
            //     })
            //     .expect(Errors::CLAIM_DOES_NOT_EXIST);

            let mut index = 0;
            {
                let mut found = false;
                for i in 0..claims_by_topic_storage.len() {
                    if claims_by_topic_storage.at(i).read() == claim_id {
                        index = i;
                        found = true;
                        break;
                    }
                };
                assert(found, Errors::CLAIM_DOES_NOT_EXIST);
            }

            // TODO: Fix this
            // claims_by_topic_storage
            //     .pop_swap(index.into(), claims_by_topic_storage.__base_address__);

            self
                .emit(
                    ERC735Event::ClaimRemoved(
                        ierc735::ClaimRemoved {
                            claim_id,
                            topic,
                            scheme: claim_storage.scheme.read(),
                            issuer: claim_storage.issuer.read(),
                            signature: claim_storage.signature.to_array().span(),
                            data: claim_storage.data.to_array().span(),
                            uri: claim_storage.uri.read(),
                        },
                    ),
                );

            // Delete claim data
            claim_storage.topic.write(Default::default());
            claim_storage.scheme.write(Default::default());
            claim_storage.issuer.write(Zero::zero());
            // Clear signature
            // TODO: Fix this
            // claim_storage.signature.clear();
            // Clear data
            // TODO: Fix this
            // claim_storage.data.clear();
            claim_storage.uri.write(Default::default());
            true
        }

        /// Returns all information about the queried `claim_id`.
        ///
        /// # Arguments
        ///
        /// * `claim_id` - Identifier of the claim to query for.
        ///
        /// # Returns
        ///
        /// A `felt252` - representing claim topic.
        /// A `felt252` - representing scheme.
        /// A `ContractAddress` - representing the issuers identity contract.
        /// A `Span<felt252>` - representing signature of the claim.
        /// A `ByteArray` - representing data attached to claim.
        /// A `ByteArray` - representing URI of the claim.
        fn get_claim(
            self: @ComponentState<TContractState>, claim_id: felt252,
        ) -> (felt252, felt252, ContractAddress, Span<felt252>, Span<felt252>, ByteArray) {
            let claim_storage = self.Identity_claims.entry(claim_id);
            (
                claim_storage.topic.read(),
                claim_storage.scheme.read(),
                claim_storage.issuer.read(),
                claim_storage.signature.as_path().to_array().span(),
                claim_storage.data.as_path().to_array().span(),
                claim_storage.uri.read(),
            )
        }

        /// Returns `Span<felt252>` representing claim ids for given topic.
        fn get_claim_ids_by_topics(
            self: @ComponentState<TContractState>, topic: felt252,
        ) -> Span<felt252> {
            self.Identity_claims_by_topic.entry(topic).to_array().span()
        }
    }

    #[embeddable_as(SNIP12MetadataExternalImpl)]
    pub impl SNIP12MetadataExternal<
        TContractState, +HasComponent<TContractState>, impl Metadata: SNIP12Metadata,
    > of ISNIP12Metadata<ComponentState<TContractState>> {
        /// Returns the domain name and version used to generate the message hash.
        fn snip12_metadata(self: @ComponentState<TContractState>) -> (felt252, felt252) {
            (Metadata::name(), Metadata::version())
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>,
    > of InternalTrait<TContractState> {
        /// Initializer of the component. Registers initial management key.
        fn initialize(
            ref self: ComponentState<TContractState>, initial_management_key: ContractAddress,
        ) {
            assert(initial_management_key.is_non_zero(), Errors::ZERO_ADDRESS);
            let initial_management_key_hash = poseidon_hash_span(
                array![initial_management_key.into()].span(),
            );
            self
                .Identity_keys
                .entry(initial_management_key_hash)
                .write(KeyDetails { purposes: 2, key_type: 1 });

            self.Identity_keys_by_purpose.entry(1).append().write(initial_management_key_hash);
            self
                .emit(
                    ERC734Event::KeyAdded(
                        ierc734::KeyAdded {
                            key: initial_management_key_hash, key_type: 1, purpose: 1,
                        },
                    ),
                );
        }

        /// Asserts if caller has MANAGEMENT key on this identity.
        fn only_manager(self: @ComponentState<TContractState>) {
            let caller = starknet::get_caller_address();
            assert(
                caller == starknet::get_contract_address()
                    || self
                        .key_has_purpose(
                            poseidon_hash_span(array![caller.into()].span()), Purpose::MANAGEMENT,
                        ),
                Errors::NOT_HAVE_MANAGEMENT_KEY,
            );
        }

        /// Asserts if caller has CLAIM key on this identity.
        fn only_claim_key(self: @ComponentState<TContractState>) {
            let caller = starknet::get_caller_address();
            assert(
                caller == starknet::get_contract_address()
                    || self
                        .key_has_purpose(
                            poseidon_hash_span(array![caller.into()].span()), Purpose::CLAIM,
                        ),
                Errors::NOT_HAVE_CLAIM_KEY,
            );
        }

        /// Internal function that executes the execution request and updates it status.
        fn _approve(
            ref self: ComponentState<TContractState>,
            execution_id: felt252,
            to: ContractAddress,
            selector: felt252,
            data: Span<felt252>,
        ) -> bool {
            self.emit(ERC734Event::Approved(ierc734::Approved { execution_id, approved: true }));

            let execution_result =
                match starknet::syscalls::call_contract_syscall(to, selector, data) {
                Result::Ok => {
                    self
                        .emit(
                            ERC734Event::Executed(
                                ierc734::Executed { execution_id, to, selector, data },
                            ),
                        );
                    true
                },
                Result::Err => {
                    self
                        .emit(
                            ERC734Event::ExecutionFailed(
                                ierc734::ExecutionFailed { execution_id, to, selector, data },
                            ),
                        );
                    false
                },
            };

            let status = if execution_result {
                ExecutionRequestStatus::Executed
            } else {
                ExecutionRequestStatus::Approved
            };

            self.Identity_executions.entry(execution_id).execution_request_status.write(status);
            execution_result
        }
    }
}
