use onchain_id_starknet::storage::structs::Signature;
use starknet::ContractAddress;

#[starknet::interface]
trait IGateway<TContractState> {
    fn approve_signer(ref self: TContractState, signer: felt252);
    fn revoke_signer(ref self: TContractState, signer: felt252);
    fn deploy_identity_with_salt(
        ref self: TContractState,
        identity_owner: ContractAddress,
        salt: felt252,
        signature_expiry: u64,
        signature: Signature
    ) -> ContractAddress;
    fn deploy_identity_with_salt_and_management_keys(
        ref self: TContractState,
        identity_owner: ContractAddress,
        salt: felt252,
        management_keys: Array<felt252>,
        signature_expiry: u64,
        signature: Signature
    ) -> ContractAddress;
    fn deploy_identity_for_wallet(
        ref self: TContractState, identity_owner: ContractAddress
    ) -> ContractAddress;
    fn revoke_signature(ref self: TContractState, signature: Signature);
    fn approve_signature(ref self: TContractState, signature: Signature);
    fn transfer_factory_ownership(ref self: TContractState, new_owner: ContractAddress);
    fn call_factory(ref self: TContractState, selector: felt252, call_data: Span<felt252>);
}

#[starknet::contract]
mod Gateway {
    use core::ecdsa::recover_public_key;
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::factory::iid_factory::{
        IIdFactoryDispatcher, IIdFactoryDispatcherTrait
    };
    use onchain_id_starknet::storage::structs::Signature;
    use openzeppelin_access::ownable::{
        ownable::OwnableComponent, interface::{IOwnableDispatcher, IOwnableDispatcherTrait},
    };
    use starknet::ContractAddress;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, Map, StoragePathEntry
    };

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl =
        OwnableComponent::OwnableImpl<ContractState>; // NOTE: consider making it 2 step
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        id_factory: ContractAddress,
        approved_signers: Map<felt252, bool>,
        revoked_signatures: Map<Signature, bool>, //Map<ByteArray, bool> in sol
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        SignerApproved: SignerApproved,
        SignerRevoked: SignerRevoked,
        SignatureApproved: SignatureApproved,
        SignatureRevoked: SignatureRevoked,
        #[flat]
        OwnableEvent: OwnableComponent::Event
    }

    #[derive(Drop, starknet::Event)]
    struct SignerApproved {
        #[key]
        signer: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct SignerRevoked {
        #[key]
        signer: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct SignatureApproved {
        #[key]
        signature: Signature,
    }

    #[derive(Drop, starknet::Event)]
    struct SignatureRevoked {
        #[key]
        signature: Signature,
    }

    pub mod Errors {
        use super::Signature;
        pub fn ZeroAddress() {
            panic!("A required parameter was set to the Zero address.");
        }
        pub fn TooManySigners() {
            panic!("The maximum number of signers was reached at deployment.");
        }
        pub fn SignerAlreadyApproved(signer: felt252) {
            panic!("The signed attempted to add was already approved. Signer: {:?}", signer);
        }
        pub fn SignerAlreadyNotApproved(signer: felt252) {
            panic!("The signed attempted to remove was not approved. Signer {:?}", signer);
        }
        pub fn UnsignedDeployment() {
            panic!(
                "A requested ONCHAINID deployment was requested without a valid signature while the Gateway requires one."
            );
        }
        pub fn UnapprovedSigner(signer: felt252) {
            panic!(
                "A requested ONCHAINID deployment was requested and signer by a non approved signer."
            );
        }
        pub fn RevokedSignature(signature: Signature) {
            panic!(
                "A requested ONCHAINID deployment was requested with a signature revoked. Signature: {:?}",
                signature
            );
        }
        pub fn ExpiredSignature(signature: Signature) {
            panic!(
                "A requested ONCHAINID deployment was requested with a signature that expired. Signature: {:?}",
                signature
            );
        }
        pub fn SignatureAlreadyRevoked(signature: Signature) {
            panic!(
                "Attempted to revoke a signature that was already revoked. Signature: {:?}",
                signature
            );
        }
        pub fn SignatureNotRevoked(signature: Signature) {
            panic!(
                "Attempted to approve a signature that was not revoked. Signature: {:?}", signature
            );
        }
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        id_factory_address: ContractAddress,
        signers_to_approve: Array<felt252>
    ) {
        if owner.is_zero() {
            Errors::ZeroAddress();
        }
        self.ownable.initializer(owner);

        if id_factory_address.is_zero() {
            Errors::ZeroAddress();
        }

        if signers_to_approve.len() > 10 {
            Errors::TooManySigners();
        }

        for signer in signers_to_approve {
            self.approved_signers.entry(signer).write(true);
        };

        self.id_factory.write(id_factory_address);
    }

    #[abi(embed_v0)]
    impl GatewayImpl of super::IGateway<ContractState> {
        fn approve_signer(ref self: ContractState, signer: felt252) {
            self.ownable.assert_only_owner();
            if signer.is_zero() {
                Errors::ZeroAddress();
            };
            let approved_signer_storage_path = self.approved_signers.entry(signer);
            if approved_signer_storage_path.read() {
                Errors::SignerAlreadyApproved(signer);
            }
            approved_signer_storage_path.write(true);
            self.emit(SignerApproved { signer });
        }

        fn revoke_signer(ref self: ContractState, signer: felt252) {
            self.ownable.assert_only_owner();
            if signer.is_zero() {
                Errors::ZeroAddress();
            }
            let approved_signer_storage_path = self.approved_signers.entry(signer);
            if !approved_signer_storage_path.read() {
                Errors::SignerAlreadyNotApproved(signer);
            }
            approved_signer_storage_path.write(false);
            self.emit(SignerApproved { signer });
        }

        fn deploy_identity_with_salt(
            ref self: ContractState,
            identity_owner: ContractAddress,
            salt: felt252,
            signature_expiry: u64,
            signature: Signature
        ) -> ContractAddress {
            if identity_owner.is_zero() {
                Errors::ZeroAddress();
            }

            if signature_expiry != 0 && signature_expiry < starknet::get_block_timestamp() {
                Errors::ExpiredSignature(signature);
            }

            /// TODO: comply with  SNIP12
            let mut serialized_message: Array<felt252> = array![];
            let seperator: ByteArray = "Authorize ONCHAINID deployment";
            seperator.serialize(ref serialized_message);
            identity_owner.serialize(ref serialized_message);
            salt.serialize(ref serialized_message);
            signature_expiry.serialize(ref serialized_message);

            let message_hash: felt252 = poseidon_hash_span(serialized_message.span());
            let signer: felt252 = recover_public_key(
                message_hash, signature.r, signature.s, signature.y_parity
            )
                .unwrap();

            if self.approved_signers.entry(signer).read() {
                Errors::UnapprovedSigner(signer);
            }

            if self.revoked_signatures.entry(signature).read() {
                Errors::SignatureAlreadyRevoked(signature);
            }

            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity(identity_owner, salt)
        }

        fn deploy_identity_with_salt_and_management_keys(
            ref self: ContractState,
            identity_owner: ContractAddress,
            salt: felt252,
            management_keys: Array<felt252>,
            signature_expiry: u64,
            signature: Signature
        ) -> ContractAddress {
            if identity_owner.is_zero() {
                Errors::ZeroAddress();
            }

            if signature_expiry != 0 && signature_expiry < starknet::get_block_timestamp() {
                Errors::ExpiredSignature(signature);
            }
            /// TODO: comply with  SNIP12
            let mut serialized_message: Array<felt252> = array![];
            let seperator: ByteArray = "Authorize ONCHAINID deployment";
            seperator.serialize(ref serialized_message);
            identity_owner.serialize(ref serialized_message);
            salt.serialize(ref serialized_message);
            management_keys.serialize(ref serialized_message);
            signature_expiry.serialize(ref serialized_message);

            /// TODO: comply with  SNIP12
            let message_hash: felt252 = poseidon_hash_span(serialized_message.span());
            let signer: felt252 = recover_public_key(
                message_hash, signature.r, signature.s, signature.y_parity
            )
                .unwrap();

            if self.approved_signers.entry(signer).read() {
                Errors::UnapprovedSigner(signer);
            }

            if self.revoked_signatures.entry(signature).read() {
                Errors::SignatureAlreadyRevoked(signature);
            }

            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity_with_management_keys(identity_owner, salt, management_keys)
        }

        fn deploy_identity_for_wallet(
            ref self: ContractState, identity_owner: ContractAddress
        ) -> ContractAddress {
            if identity_owner.is_zero() {
                Errors::ZeroAddress();
            }

            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity(identity_owner, identity_owner.into())
        }

        fn revoke_signature(ref self: ContractState, signature: Signature) {
            self.ownable.assert_only_owner();
            let revoked_signature_storage_path = self.revoked_signatures.entry(signature);
            if revoked_signature_storage_path.read() {
                Errors::SignatureAlreadyRevoked(signature);
            }
            revoked_signature_storage_path.write(true);
            self.emit(SignatureRevoked { signature });
        }

        fn approve_signature(ref self: ContractState, signature: Signature) {
            self.ownable.assert_only_owner();
            let revoked_signature_storage_path = self.revoked_signatures.entry(signature);
            if !revoked_signature_storage_path.read() {
                Errors::SignatureNotRevoked(signature);
            }
            revoked_signature_storage_path.write(false);
            self.emit(SignatureApproved { signature });
        }

        fn transfer_factory_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self.ownable.assert_only_owner();
            IOwnableDispatcher { contract_address: self.id_factory.read() }
                .transfer_ownership(new_owner);
        }

        fn call_factory(ref self: ContractState, selector: felt252, call_data: Span<felt252>) {
            self.ownable.assert_only_owner();
            starknet::syscalls::call_contract_syscall(self.id_factory.read(), selector, call_data)
                .unwrap();
        }
    }
}
