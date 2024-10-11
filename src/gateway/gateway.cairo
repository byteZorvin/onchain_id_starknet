use onchain_id_starknet::storage::structs::{Signature, SignatureHash};
use starknet::ContractAddress;

#[starknet::interface]
trait IGateway<TContractState> {
    fn approve_signer(ref self: TContractState, signer: ContractAddress);
    fn revoke_signer(ref self: TContractState, signer: ContractAddress);
    fn deploy_identity_with_salt(
        ref self: TContractState,
        identity_owner: ContractAddress,
        salt: ByteArray,
        signature_expiry: u64,
        signature: Signature
    ) -> ContractAddress;
    fn deploy_identity_with_salt_and_management_keys(
        ref self: TContractState,
        identity_owner: ContractAddress,
        salt: ByteArray,
        management_keys: Array<felt252>,
        signature_expiry: u64,
        signature: Signature
    ) -> ContractAddress;
    fn deploy_identity_for_wallet(
        ref self: TContractState, identity_owner: ContractAddress
    ) -> ContractAddress;
    fn revoke_signature(ref self: TContractState, signature: SignatureHash);
    fn approve_signature(ref self: TContractState, signature: SignatureHash);
    fn transfer_factory_ownership(ref self: TContractState, new_owner: ContractAddress);
    fn call_factory(ref self: TContractState, selector: felt252, call_data: Span<felt252>);
}

#[starknet::contract]
mod Gateway {
    use core::byte_array::ByteArrayTrait;
    use core::num::traits::Zero;
    use onchain_id_starknet::factory::iid_factory::{
        IIdFactoryDispatcher, IIdFactoryDispatcherTrait
    };
    use onchain_id_starknet::storage::structs::{Signature, SignatureHash};
    use openzeppelin_access::ownable::{
        ownable::OwnableComponent, interface::{IOwnableDispatcher, IOwnableDispatcherTrait},
    };
    use starknet::ContractAddress;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, StorageMapReadAccess,
        StorageMapWriteAccess, Map
    };

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        id_factory: ContractAddress, //IIdFactoryDispatcher,
        approved_signers: Map<ContractAddress, bool>,
        revoked_signatures: Map<SignatureHash, bool>, //Map<ByteArray, bool>
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
        signer: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct SignerRevoked {
        #[key]
        signer: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct SignatureApproved {
        #[key]
        signature: SignatureHash,
    }

    #[derive(Drop, starknet::Event)]
    struct SignatureRevoked {
        #[key]
        signature: SignatureHash,
    }

    pub mod Errors {
        use super::Signature;
        use super::SignatureHash;
        pub fn ZeroAddress() {
            panic!("A required parameter was set to the Zero address.");
        }
        pub fn TooManySigners() {
            panic!("The maximum number of signers was reached at deployment.");
        }
        pub fn SignerAlreadyApproved(signer: starknet::ContractAddress) {
            panic!("The signed attempted to add was already approved. Signer: {:?}", signer);
        }
        pub fn SignerAlreadyNotApproved(signer: starknet::ContractAddress) {
            panic!("The signed attempted to remove was not approved. Signer {:?}", signer);
        }
        pub fn UnsignedDeployment() {
            panic!(
                "A requested ONCHAINID deployment was requested without a valid signature while the Gateway requires one."
            );
        }
        pub fn UnapprovedSigner(signer: starknet::ContractAddress) {
            panic!(
                "A requested ONCHAINID deployment was requested and signer by a non approved signer."
            );
        }
        pub fn RevokedSignature(signature: SignatureHash) {
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
        pub fn SignatureAlreadyRevoked(signature: SignatureHash) {
            panic!(
                "Attempted to revoke a signature that was already revoked. Signature: {}", signature
            );
        }
        pub fn SignatureNotRevoked(signature: SignatureHash) {
            panic!(
                "Attempted to approve a signature that was not revoked. Signature: {}", signature
            );
        }
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        id_factory_address: ContractAddress,
        signers_to_approve: Array<ContractAddress>
    ) {
        self.ownable.initializer(owner);
        if id_factory_address.is_zero() {
            Errors::ZeroAddress();
        }

        if signers_to_approve.len() > 10 {
            Errors::TooManySigners();
        }

        for signer in signers_to_approve {
            self.approved_signers.write(signer, true);
        };

        self.id_factory.write(id_factory_address);
    }

    #[abi(embed_v0)]
    impl GatewayImpl of super::IGateway<ContractState> {
        fn approve_signer(ref self: ContractState, signer: ContractAddress) {
            self.ownable.assert_only_owner();
            if signer.is_zero() {
                Errors::ZeroAddress();
            };
            if self.approved_signers.read(signer) {
                Errors::SignerAlreadyApproved(signer);
            }
            self.approved_signers.write(signer, true);
            self.emit(SignerApproved { signer });
        }

        fn revoke_signer(ref self: ContractState, signer: ContractAddress) {
            self.ownable.assert_only_owner();
            if signer.is_zero() {
                Errors::ZeroAddress();
            }
            if !self.approved_signers.read(signer) {
                Errors::SignerAlreadyNotApproved(signer);
            }
            self.approved_signers.write(signer, false);
            self.emit(SignerApproved { signer });
        }
        // TODO: Decide on signature to be used
        fn deploy_identity_with_salt(
            ref self: ContractState,
            identity_owner: ContractAddress,
            salt: ByteArray,
            signature_expiry: u64,
            signature: Signature
        ) -> ContractAddress {
            if identity_owner.is_zero() {
                Errors::ZeroAddress();
            }

            if signature_expiry != 0 && signature_expiry < starknet::get_block_timestamp() {
                Errors::ExpiredSignature(signature);
            }

            /// TODO: signature revocer decide on sig type
            ///
            let signer: ContractAddress = Zero::zero();

            if self.approved_signers.read(signer) {
                Errors::UnapprovedSigner(signer);
            }

            let mut signature_serialized: Array<felt252> = array![];
            signature.serialize(ref signature_serialized);
            let signature_hash = core::poseidon::poseidon_hash_span(signature_serialized.span());
            if self.revoked_signatures.read(signature_hash) {
                Errors::SignatureAlreadyRevoked(signature_hash);
            }

            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity(identity_owner, salt)
        }

        fn deploy_identity_with_salt_and_management_keys(
            ref self: ContractState,
            identity_owner: ContractAddress,
            salt: ByteArray,
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

            /// TODO: signature revocer decide on sig type
            ///
            let signer: ContractAddress = Zero::zero();

            if self.approved_signers.read(signer) {
                Errors::UnapprovedSigner(signer);
            }

            let mut signature_serialized: Array<felt252> = array![];
            signature.serialize(ref signature_serialized);
            let signature_hash = core::poseidon::poseidon_hash_span(signature_serialized.span());
            if self.revoked_signatures.read(signature_hash) {
                Errors::SignatureAlreadyRevoked(signature_hash);
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
            let mut salt = "";
            salt.append_word(identity_owner.into(), 32);
            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity(identity_owner, salt)
        }

        fn revoke_signature(ref self: ContractState, signature: SignatureHash) {
            self.ownable.assert_only_owner();
            if self.revoked_signatures.read(signature) {
                Errors::SignatureAlreadyRevoked(signature);
            }

            self.revoked_signatures.write(signature, true);
            self.emit(SignatureRevoked { signature });
        }

        fn approve_signature(ref self: ContractState, signature: SignatureHash) {
            self.ownable.assert_only_owner();
            if !self.revoked_signatures.read(signature) {
                Errors::SignatureNotRevoked(signature);
            }

            self.revoked_signatures.write(signature, false);
            self.emit(SignatureApproved { signature });
        }

        fn transfer_factory_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self.ownable.assert_only_owner();
            IOwnableDispatcher { contract_address: self.id_factory.read() }
                .transfer_ownership(new_owner);
        }

        fn call_factory(ref self: ContractState, selector: felt252, call_data: Span<felt252>) {
            starknet::syscalls::call_contract_syscall(self.id_factory.read(), selector, call_data)
                .unwrap();
        }
    }
}
