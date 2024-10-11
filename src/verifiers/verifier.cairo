use starknet::ContractAddress;

#[starknet::interface]
pub trait ITrustedIssuersRegistry<TContractState> {
    fn add_trusted_issuer(
        ref self: TContractState, trusted_issuer: ContractAddress, claim_topics: Array<felt252>
    );
    fn remove_trusted_issuer(ref self: TContractState, trusted_issuer: ContractAddress);
    fn update_issuer_claim_topics(
        ref self: TContractState, trusted_issuer: ContractAddress, claim_topics: Array<felt252>
    );
    fn get_trusted_issuers(self: @TContractState) -> Array<ContractAddress>;
    fn get_trusted_issuers_for_claim_topic(
        self: @TContractState, claim_topic: felt252
    ) -> Array<ContractAddress>;
    fn is_trusted_issuer(self: @TContractState, issuer: ContractAddress) -> bool;
    fn get_trusted_issuer_claim_topics(
        self: @TContractState, trusted_issuer: ContractAddress
    ) -> Array<felt252>;
    fn has_claim_topic(
        self: @TContractState, issuer: ContractAddress, claim_topic: felt252
    ) -> bool;
}

#[starknet::interface]
pub trait IClaimTopicsRegistry<TContractState> {
    fn add_claim_topic(ref self: TContractState, claim_topic: felt252);
    fn remove_claim_topic(ref self: TContractState, claim_topic: felt252);
    fn get_claim_topics(self: @TContractState) -> Array<felt252>;
}

#[starknet::interface]
pub trait IVerifier<TContractState> {
    fn verify(self: @TContractState, identity: ContractAddress) -> bool;
    fn is_claim_topic_required(self: @TContractState, claim_topic: felt252) -> bool;
}

#[starknet::contract]
pub mod Verifier {
    use onchain_id_starknet::interface::iclaim_issuer::IClaimIssuerDispatcher;
    use starknet::ContractAddress;
    use starknet::storage::{Vec, Map};
    #[storage]
    struct Storage {
        required_claim_topics: Vec<felt252>,
        trusted_issuers: Vec<IClaimIssuerDispatcher>,
        trusted_issuer_claim_topics: Map<ContractAddress, Vec<felt252>>,
        claim_topics_to_trusted_issuers: Map<felt252, Vec<IClaimIssuerDispatcher>>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ClaimTopicAdded: ClaimTopicAdded,
        ClaimTopicRemoved: ClaimTopicRemoved,
        TrustedIssuerAdded: TrustedIssuerAdded,
        TrustedIssuerRemoved: TrustedIssuerRemoved,
        ClaimTopicsUpdated: ClaimTopicsUpdated
    }

    #[derive(Drop, starknet::Event)]
    struct ClaimTopicAdded {
        #[key]
        claim_topic: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ClaimTopicRemoved {
        #[key]
        claim_topic: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct TrustedIssuerAdded {
        #[key]
        trusted_issuer: ContractAddress,
        claim_topics: Array<felt252>,
    }

    #[derive(Drop, starknet::Event)]
    struct TrustedIssuerRemoved {
        #[key]
        trusted_issuer: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ClaimTopicsUpdated {
        #[key]
        trusted_issuer: ContractAddress,
        claim_topics: Array<felt252>,
    }

    #[abi(embed_v0)]
    impl VerifierImpl of super::IVerifier<ContractState> {
        fn verify(self: @ContractState, identity: ContractAddress) -> bool {
            true
        }

        fn is_claim_topic_required(self: @ContractState, claim_topic: felt252) -> bool {
            true
        }
    }

    #[abi(embed_v0)]
    impl ClaimTopicsRegistryImpl of super::IClaimTopicsRegistry<ContractState> {
        fn add_claim_topic(ref self: ContractState, claim_topic: felt252) {}
        fn remove_claim_topic(ref self: ContractState, claim_topic: felt252) {}
        fn get_claim_topics(self: @ContractState) -> Array<felt252> {
            array![]
        }
    }

    #[abi(embed_v0)]
    impl TrustedIssuerRegistryImpl of super::ITrustedIssuersRegistry<ContractState> {
        fn add_trusted_issuer(
            ref self: ContractState, trusted_issuer: ContractAddress, claim_topics: Array<felt252>
        ) {}
        fn remove_trusted_issuer(ref self: ContractState, trusted_issuer: ContractAddress) {}
        fn update_issuer_claim_topics(
            ref self: ContractState, trusted_issuer: ContractAddress, claim_topics: Array<felt252>
        ) {}
        fn get_trusted_issuers(self: @ContractState) -> Array<ContractAddress> {
            array![]
        }
        fn get_trusted_issuers_for_claim_topic(
            self: @ContractState, claim_topic: felt252
        ) -> Array<ContractAddress> {
            array![]
        }
        fn is_trusted_issuer(self: @ContractState, issuer: ContractAddress) -> bool {
            true
        }
        fn get_trusted_issuer_claim_topics(
            self: @ContractState, trusted_issuer: ContractAddress
        ) -> Array<felt252> {
            array![]
        }
        fn has_claim_topic(
            self: @ContractState, issuer: ContractAddress, claim_topic: felt252
        ) -> bool {
            true
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn only_verified_sender(self: @ContractState) {}
    }
}

