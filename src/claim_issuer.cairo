#[starknet::contract]
mod ClaimIssuer {
    use onchain_id_starknet::identity_component::IdentityComponent;
    use onchain_id_starknet::interface::{
        iclaim_issuer::IClaimIssuer, iidentity::{IIdentityDispatcher},
        ierc735::{IERC735Dispatcher, IERC735DispatcherTrait},
    };
    //use starknet::Secp256Trait;
    use onchain_id_starknet::storage::structs::{Signature, SignatureHash};
    use onchain_id_starknet::version::version::VersionComponent;
    use starknet::ContractAddress;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

    component!(path: IdentityComponent, storage: identity, event: IdentityEvent);
    // TODO: abi embed or not depends on how to handle function override
    impl IdentityImpl = IdentityComponent::IdentityImpl<ContractState>;
    impl IdentityInternalImpl = IdentityComponent::InternalImpl<ContractState>;

    component!(path: VersionComponent, storage: version, event: VersionEvent);

    #[abi(embed_v0)]
    impl VersionImpl = VersionComponent::VersionImpl<ContractState>;


    #[storage]
    struct Storage {
        revoked_claims: Map<SignatureHash, bool>,
        #[substorage(v0)]
        identity: IdentityComponent::Storage,
        #[substorage(v0)]
        version: VersionComponent::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        IdentityEvent: IdentityComponent::Event,
        #[flat]
        VersionEvent: VersionComponent::Event,
        ClaimRevoked: ClaimRevoked
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimRevoked {
        #[key]
        signature: SignatureHash, // finalize the signature to be used
    }

    // TODO: ensure initialization pattern matches with solidity one
    #[constructor]
    fn constructor(ref self: ContractState, initial_management_key: ContractAddress) {
        self.identity.initialize(initial_management_key);
    }

    // TODO: Implement interface
    #[abi(embed_v0)]
    impl ClaimIssuerImpl of IClaimIssuer<ContractState> {
        fn revoke_claim_by_signature(ref self: ContractState, signature: SignatureHash) {
            self.identity.delegated_only();
            self.identity.only_manager();
            assert!(!self.revoked_claims.read(signature), "Conflict: Claim already revoked");
            self.revoked_claims.write(signature, true);
            self.emit(ClaimRevoked { signature });
        }

        fn revoke_claim(
            ref self: ContractState, claim_id: felt252, identity: ContractAddress
        ) -> bool {
            self.identity.delegated_only();
            self.identity.only_manager();
            let (_, _, _, signature, _, _) = IERC735Dispatcher { contract_address: identity }
                .get_claim(claim_id);

            let signature_hash = core::poseidon::poseidon_hash_span(
                array![signature.r, signature.s].span()
            );
            assert!(!self.revoked_claims.read(signature_hash), "Conflict: Claim already revoked");
            self.revoked_claims.write(signature_hash, true);
            self.emit(ClaimRevoked { signature: signature_hash });
            true
        }
        // TODO
        // Dev: Overrides Identity.is_claim_valid
        fn is_claim_valid(
            self: @ContractState,
            identity: IIdentityDispatcher,
            claim_topic: felt252,
            signature: Signature,
            data: ByteArray
        ) -> bool {
            true
        }

        fn is_claim_revoked(self: @ContractState, signature: SignatureHash) -> bool {
            self.revoked_claims.read(signature)
        }
    }
}
