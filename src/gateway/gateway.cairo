//! The `Gateway` contract acts as a gateway to the `IdFactory`. This contract must be the owner of
//! the `IdFactory` to orchestrate `Identity` deployments. By introducing approved signers, it
//! allows multiple entities to sign deployment messages. Additionally, it implements a signature
//! revocation mechanism to invalidate deployment messages.
//!
//! # Features
//!
//! - **Identity Deployment**: Facilitates the deployment of new identity contracts through the
//! factory.
//! - **Signer Management**: Allows the approval and revocation of signers who can sign deployment
//! requests.
//! - **Signature Management**: Supports the approval and revocation of signatures used in
//! deployment requests.
//! - **Ownership Management**: Implements ownership logic to ensure that only the owner can perform
//! sensitive operations.
//!
//! # Components
//!
//! - **OwnableComponent**: Implements ownership logic, ensuring that only the owner can perform
//!   sensitive operations such as approving signers and transferring factory ownership.
//!
//! # Security Notice
//!
//! This contract has not undergone a formal security audit and should be considered experimental.
//! Users should exercise caution when implementing or deploying this code in production
//! environments.

#[starknet::contract]
pub mod Gateway {
    use core::ecdsa::recover_public_key;
    use core::num::traits::Zero;
    use openzeppelin_access::ownable::interface::{IOwnableDispatcher, IOwnableDispatcherTrait};
    use openzeppelin_access::ownable::ownable::OwnableComponent;
    use openzeppelin_utils::cryptography::interface::ISNIP12Metadata;
    use openzeppelin_utils::cryptography::snip12::{OffchainMessageHash, SNIP12Metadata};
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use crate::factory::interface::{IIdFactoryDispatcher, IIdFactoryDispatcherTrait};
    use crate::gateway::interface::{Deployment, DeploymentWithManagementKeys, IGateway, Signature};

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableTwoStepImpl = OwnableComponent::OwnableTwoStepImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        id_factory: ContractAddress,
        approved_signers: Map<felt252, bool>,
        revoked_signatures: Map<Signature, bool>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        SignerApproved: SignerApproved,
        SignerRevoked: SignerRevoked,
        SignatureApproved: SignatureApproved,
        SignatureRevoked: SignatureRevoked,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    /// Event emitted when a signer is approved to sign deployment requests.
    #[derive(Drop, starknet::Event)]
    pub struct SignerApproved {
        #[key]
        pub signer: felt252,
    }

    /// Event emitted when a signer is revoked.
    #[derive(Drop, starknet::Event)]
    pub struct SignerRevoked {
        #[key]
        pub signer: felt252,
    }

    /// Event emitted when a revoked signature is approved.
    #[derive(Drop, starknet::Event)]
    pub struct SignatureApproved {
        #[key]
        pub signature: Signature,
    }

    /// Event emitted when the signature of a deployment request is revoked.
    #[derive(Drop, starknet::Event)]
    pub struct SignatureRevoked {
        #[key]
        pub signature: Signature,
    }

    pub mod Errors {
        pub fn ZeroAddress() {
            panic!("A required parameter was set to the zero address.");
        }
        pub fn TooManySigners() {
            panic!("The maximum number of signers was reached during deployment.");
        }
        pub fn SignerAlreadyApproved() {
            panic!("The signer attempted to add was already approved.");
        }
        pub fn SignerNotApproved() {
            panic!("The signer attempted to remove was not approved.");
        }
        pub fn UnsignedDeployment() {
            panic!(
                "A requested ONCHAINID deployment was made without a valid signature while the Gateway requires one.",
            );
        }
        pub fn UnapprovedSigner() {
            panic!(
                "A requested ONCHAINID deployment was made and signed by a non-approved signer.",
            );
        }
        pub fn RevokedSignature() {
            panic!("A requested ONCHAINID deployment was made with a revoked signature.");
        }
        pub fn ExpiredSignature() {
            panic!("A requested ONCHAINID deployment was made with an expired signature.");
        }
        pub fn SignatureAlreadyRevoked() {
            panic!("Attempted to revoke a signature that was already revoked.");
        }
        pub fn SignatureNotRevoked() {
            panic!("Attempted to approve a signature that was not revoked.");
        }
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        id_factory_address: ContractAddress,
        signers_to_approve: Span<felt252>,
        owner: ContractAddress,
    ) {
        if owner.is_zero() {
            Errors::ZeroAddress();
        }

        if id_factory_address.is_zero() {
            Errors::ZeroAddress();
        }

        if signers_to_approve.len() > 10 {
            Errors::TooManySigners();
        }

        self.ownable.initializer(owner);

        for signer in signers_to_approve {
            self.approved_signers.entry(*signer).write(true);
        };

        self.id_factory.write(id_factory_address);
    }

    #[abi(embed_v0)]
    pub impl SNIP12MetadataExternal of ISNIP12Metadata<ContractState> {
        /// Returns the domain name and version used to generate the message hash.
        fn snip12_metadata(self: @ContractState) -> (felt252, felt252) {
            (SNIP12MetadataImpl::name(), SNIP12MetadataImpl::version())
        }
    }

    pub impl SNIP12MetadataImpl of SNIP12Metadata {
        /// Returns the name of the SNIP-12 metadata.
        fn name() -> felt252 {
            'OnchainID.Gateway'
        }

        /// Returns the version of the SNIP-12 metadata.
        fn version() -> felt252 {
            'v1'
        }
    }

    #[abi(embed_v0)]
    impl GatewayImpl of IGateway<ContractState> {
        /// This function approves a signer to sign identity deployments.
        ///
        /// # Arguments
        /// * `signer` - A `felt252` representing the public key of the signer to approve.
        ///
        /// # Requirements
        ///
        /// Must be called by the gateway owner.
        /// `signer` must not be zero.
        /// `signer` must not already be approved.
        fn approve_signer(ref self: ContractState, signer: felt252) {
            self.ownable.assert_only_owner();

            if signer.is_zero() {
                Errors::ZeroAddress();
            }

            let approved_signer_storage = self.approved_signers.entry(signer);
            if approved_signer_storage.read() {
                Errors::SignerAlreadyApproved();
            }

            approved_signer_storage.write(true);
            self.emit(SignerApproved { signer });
        }

        /// This function revokes a signer's privileges to sign identity deployments.
        ///
        /// # Arguments
        ///
        /// * `signer` - A `felt252` representing the public key of the signer to revoke.
        ///
        /// # Requirements
        ///
        /// Must be called by the gateway owner.
        /// `signer` must not be zero.
        /// `signer` must be already approved.
        fn revoke_signer(ref self: ContractState, signer: felt252) {
            self.ownable.assert_only_owner();

            if signer.is_zero() {
                Errors::ZeroAddress();
            }

            let approved_signer_storage = self.approved_signers.entry(signer);
            if !approved_signer_storage.read() {
                Errors::SignerNotApproved();
            }

            approved_signer_storage.write(false);
            self.emit(SignerRevoked { signer });
        }

        /// This function deploys an identity using a factory with a custom `salt` and registers
        /// `identity_owner` as the initial MANAGEMENT key.
        ///
        /// This operation must be signed by an approved public key. This method allows deploying an
        /// identity using a custom salt.
        ///
        /// # Arguments
        ///
        /// * `identity_owner` - A `ContractAddress` representing the address to be added as
        /// MANAGEMENT key.
        /// * `salt` - A `felt252` representing the salt used during deployment.
        /// * `signature_expiry` - A `u64` representing the block timestamp when the signature will
        /// expire.
        /// * `signature` - A `Signature` representing the signature of the deployment message.
        ///
        /// # Requirements
        ///
        /// - `identity_owner` must be non-zero.
        /// - `signature` must be signed by an approved signer.
        /// - `signature` must not have expired.
        /// - `signature` must not be revoked.
        /// - `salt` must be non-zero and not already taken.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` representing the deployed identity.
        fn deploy_identity_with_salt(
            ref self: ContractState,
            identity_owner: ContractAddress,
            salt: felt252,
            signature_expiry: u64,
            signature: Signature,
        ) -> ContractAddress {
            if identity_owner.is_zero() {
                Errors::ZeroAddress();
            }

            if signature_expiry.is_non_zero()
                && signature_expiry < starknet::get_block_timestamp() {
                Errors::ExpiredSignature();
            }

            let message = Deployment { identity_owner, salt, expiration: signature_expiry };

            let message_hash: felt252 = message.get_message_hash(starknet::get_contract_address());

            let signer: felt252 = recover_public_key(
                message_hash, signature.r, signature.s, signature.y_parity,
            )
                .expect('recover_public_key failed');

            if !self.approved_signers.entry(signer).read() {
                Errors::UnapprovedSigner();
            }

            if self.revoked_signatures.entry(signature).read() {
                Errors::RevokedSignature();
            }

            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity(identity_owner, salt)
        }

        /// This function deploys an identity using a factory with a custom salt and registers
        /// `management_keys` as the initial MANAGEMENT keys.
        ///
        /// The operation must be signed by an approved public key. This method allows deploying an
        /// identity using a custom salt. `identity_owner` will not be added as a MANAGEMENT key; if
        /// this is desired, add the poseidon hash of `identity_owner` in `management_keys`.
        ///
        /// # Arguments
        ///
        /// * `identity_owner` - A `ContractAddress` representing the address to be added as
        /// MANAGEMENT key.
        /// * `salt` - A `felt252` representing the salt used during deployment.
        /// * `signature_expiry` - A `u64` representing the block timestamp when the signature will
        /// expire.
        /// * `signature` - A `Signature` representing the signature of the deployment message.
        /// * `management_keys` - A `Span<felt252>` representing the array of keys hash(poseidon
        /// hash) to add as MANAGEMENT keys.
        ///
        /// # Requirements
        ///
        /// - `identity_owner` must be non-zero.
        /// - `signature` must be signed by an approved signer.
        /// - `signature` must not have expired.
        /// - `signature` must not be revoked.
        /// - `management_keys` length must be greater than 0.
        /// - `salt` must be non-zero and not already taken.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` representing the deployed identity.
        fn deploy_identity_with_salt_and_management_keys(
            ref self: ContractState,
            identity_owner: ContractAddress,
            salt: felt252,
            management_keys: Span<felt252>,
            signature_expiry: u64,
            signature: Signature,
        ) -> ContractAddress {
            if identity_owner.is_zero() {
                Errors::ZeroAddress();
            }

            if signature_expiry.is_non_zero()
                && signature_expiry < starknet::get_block_timestamp() {
                Errors::ExpiredSignature();
            }

            let message = DeploymentWithManagementKeys {
                identity_owner, salt, management_keys, expiration: signature_expiry,
            };

            let message_hash: felt252 = message.get_message_hash(starknet::get_contract_address());
            let signer: felt252 = recover_public_key(
                message_hash, signature.r, signature.s, signature.y_parity,
            )
                .expect('recover_public_key failed');

            if !self.approved_signers.entry(signer).read() {
                Errors::UnapprovedSigner();
            }

            if self.revoked_signatures.entry(signature).read() {
                Errors::RevokedSignature();
            }

            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity_with_management_keys(identity_owner, salt, management_keys)
        }

        /// This function deploys an identity using a factory with the identity_owner as salt.
        ///
        /// # Arguments
        ///
        /// * `identity_owner` - A `ContractAddress` representing the address to be added as
        /// MANAGEMENT key and will be used as the salt value.
        ///
        /// # Requirements
        ///
        /// - `identity_owner` must be non-zero.
        /// - `identity_owner` must not already have a deployed identity via this function.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` representing the deployed identity.
        fn deploy_identity_for_wallet(
            ref self: ContractState, identity_owner: ContractAddress,
        ) -> ContractAddress {
            if identity_owner.is_zero() {
                Errors::ZeroAddress();
            }

            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity(identity_owner, identity_owner.into())
        }

        /// This function revokes the given signature.
        ///
        /// If the signature is used to sign a deployment, revoking the signature will invalidate
        /// the deployment, thus the deployment will be rejected.
        ///
        /// # Arguments
        ///
        /// * `signature` - A `Signature` representing the signature to revoke.
        ///
        /// # Requirements
        ///
        /// Must be called by the gateway owner.
        /// - `signature` must not already be revoked.
        fn revoke_signature(ref self: ContractState, signature: Signature) {
            self.ownable.assert_only_owner();
            let revoked_signature_storage = self.revoked_signatures.entry(signature);
            if revoked_signature_storage.read() {
                Errors::SignatureAlreadyRevoked();
            }
            revoked_signature_storage.write(true);
            self.emit(SignatureRevoked { signature });
        }

        /// This function removes the given signature from the revoked list.
        ///
        /// # Arguments
        ///
        /// * `signature` - A `Signature` representing the signature to remove from the revoked
        /// list.
        ///
        /// # Requirements
        ///
        /// Must be called by the gateway owner.
        /// - `signature` must already be revoked.
        fn approve_signature(ref self: ContractState, signature: Signature) {
            self.ownable.assert_only_owner();
            let revoked_signature_storage = self.revoked_signatures.entry(signature);
            if !revoked_signature_storage.read() {
                Errors::SignatureNotRevoked();
            }
            revoked_signature_storage.write(false);
            self.emit(SignatureApproved { signature });
        }

        /// This function transfers the ownership of the IdFactory contract.
        ///
        /// # Arguments
        ///
        /// * `new_owner` - A `ContractAddress` representing the new owner of the IdFactory.
        ///
        /// # Requirements
        ///
        /// Must be called by the gateway owner.
        fn transfer_factory_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self.ownable.assert_only_owner();
            IOwnableDispatcher { contract_address: self.id_factory.read() }
                .transfer_ownership(new_owner);
        }

        /// This function calls the IdFactory contract with the given arbitrary call parameters.
        ///
        /// # Arguments
        ///
        /// * `selector` - A `felt252` representing the entry point selector to call.
        /// * `calldata` - A `Span<felt252>` representing the serialized calldata to be passed to
        /// the factory.
        ///
        /// # Requirements
        ///
        /// Must be called by the gateway owner.
        fn call_factory(ref self: ContractState, selector: felt252, calldata: Span<felt252>) {
            self.ownable.assert_only_owner();
            starknet::syscalls::call_contract_syscall(self.id_factory.read(), selector, calldata)
                .unwrap();
        }

        /// Determines if the given signer is approved to sign deployments.
        ///
        /// # Returns
        ///
        /// A `bool` representing whether the signer is approved or not. Returns true if approved.
        fn is_approved_signer(self: @ContractState, signer: felt252) -> bool {
            self.approved_signers.entry(signer).read()
        }

        /// Determines if the given signature is revoked or not.
        ///
        /// # Returns
        ///
        /// A `bool` representing whether the signature is revoked. Returns true if revoked.
        fn is_revoked_signature(self: @ContractState, signature: Signature) -> bool {
            self.revoked_signatures.entry(signature).read()
        }

        /// Returns the identity factory used by this contract.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` representing the address of the identity factory.
        fn get_id_factory(self: @ContractState) -> ContractAddress {
            self.id_factory.read()
        }
    }
}
