#[starknet::contract]
mod ClaimIssuer {
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::identity_component::IdentityComponent;
    use onchain_id_starknet::interface::{
        iclaim_issuer::IClaimIssuer, iidentity::IIdentity,
        ierc735::{IERC735Dispatcher, IERC735DispatcherTrait},
    };
    use onchain_id_starknet::storage::structs::Signature;
    use onchain_id_starknet::version::version::VersionComponent;
    use starknet::ContractAddress;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

    component!(path: IdentityComponent, storage: identity, event: IdentityEvent);

    #[abi(embed_v0)]
    impl ERC734Impl = IdentityComponent::ERC734Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC735Impl = IdentityComponent::ERC735Impl<ContractState>;
    impl IdentityInternalImpl = IdentityComponent::InternalImpl<ContractState>;

    component!(path: VersionComponent, storage: version, event: VersionEvent);

    #[abi(embed_v0)]
    impl VersionImpl = VersionComponent::VersionImpl<ContractState>;

    #[storage]
    struct Storage {
        revoked_claims: Map<Signature, bool>,
        #[substorage(v0)]
        identity: IdentityComponent::Storage,
        #[substorage(v0)]
        version: VersionComponent::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        IdentityEvent: IdentityComponent::Event,
        #[flat]
        VersionEvent: VersionComponent::Event,
        ClaimRevoked: ClaimRevoked
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimRevoked {
        #[key]
        signature: Signature,
    }

    pub mod Errors {
        pub const CLAIM_ALREADY_REVOKED: felt252 = 'Conflict: Claim already revoked';
    }

    // TODO: ensure initialization pattern is correct.
    // NOTE: Depends on central upgreadeability mechanism we come up with
    #[constructor]
    fn constructor(ref self: ContractState, initial_management_key: ContractAddress) {
        self.identity.initialize(initial_management_key);
    }

    #[abi(embed_v0)]
    impl ClaimIssuerImpl of IClaimIssuer<ContractState> {
        fn revoke_claim_by_signature(ref self: ContractState, signature: Signature) {
            self.identity.delegated_only();
            self.identity.only_manager();
            assert(!self.revoked_claims.read(signature), Errors::CLAIM_ALREADY_REVOKED);
            self.revoked_claims.write(signature, true);
            self.emit(ClaimRevoked { signature });
        }
        // NOTE: Deprecated - see
        // {https://docs.onchainid.com/docs/developers/contracts/claim-issuer#revocation-of-a-claim}
        fn revoke_claim(
            ref self: ContractState, claim_id: felt252, identity: ContractAddress
        ) -> bool {
            self.identity.delegated_only();
            self.identity.only_manager();
            let (_, _, _, signature, _, _) = IERC735Dispatcher { contract_address: identity }
                .get_claim(claim_id);

            assert(!self.revoked_claims.read(signature), Errors::CLAIM_ALREADY_REVOKED);
            self.revoked_claims.write(signature, true);
            self.emit(ClaimRevoked { signature });
            true
        }

        fn is_claim_revoked(self: @ContractState, signature: Signature) -> bool {
            self.revoked_claims.read(signature)
        }
    }

    #[abi(embed_v0)]
    impl IdentityImpl of IIdentity<ContractState> {
        fn is_claim_valid(
            self: @ContractState,
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
            let pub_key = self.identity.get_recovered_public_key(signature, data_hash);
            // NOTE: consider using hash required or not? Are we going to support multiple signature
            // type?
            let pub_key_hash = poseidon_hash_span(array![pub_key].span());
            if self.key_has_purpose(pub_key_hash, 3) && !self.is_claim_revoked(signature) {
                true
            } else {
                false
            }
        }
    }
}
