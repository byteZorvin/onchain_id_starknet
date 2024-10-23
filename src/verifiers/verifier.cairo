#[starknet::component]
pub mod VerifierComponent {
    use onchain_id_starknet::interface::iclaim_issuer::IClaimIssuerDispatcher;
    use onchain_id_starknet::interface::iverifier::{
        ITrustedIssuersRegistry, IClaimTopicsRegistry, IVerifier, VerifierABI
    };
    use openzeppelin_access::ownable::OwnableComponent;
    use starknet::ContractAddress;
    use starknet::storage::{Vec, Map};
    
    #[storage]
    pub struct Storage {
        Verifier_required_claim_topics: Vec<felt252>,
        Verifier_trusted_issuers: Vec<IClaimIssuerDispatcher>,
        Verifier_trusted_issuer_claim_topics: Map<ContractAddress, Vec<felt252>>,
        Verifier_claim_topics_to_trusted_issuers: Map<felt252, Vec<IClaimIssuerDispatcher>>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ClaimTopicAdded: ClaimTopicAdded,
        ClaimTopicRemoved: ClaimTopicRemoved,
        TrustedIssuerAdded: TrustedIssuerAdded,
        TrustedIssuerRemoved: TrustedIssuerRemoved,
        ClaimTopicsUpdated: ClaimTopicsUpdated
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimTopicAdded {
        #[key]
        claim_topic: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimTopicRemoved {
        #[key]
        claim_topic: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TrustedIssuerAdded {
        #[key]
        trusted_issuer: ContractAddress,
        claim_topics: Array<felt252>,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TrustedIssuerRemoved {
        #[key]
        trusted_issuer: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimTopicsUpdated {
        #[key]
        trusted_issuer: ContractAddress,
        claim_topics: Array<felt252>,
    }

    #[embeddable_as(VerifierImpl)]
    pub impl Verifier<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of IVerifier<ComponentState<TContractState>> {
        fn verify(self: @ComponentState<TContractState>, identity: ContractAddress) -> bool {
            true
        }

        fn is_claim_topic_required(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> bool {
            true
        }
    }

    #[embeddable_as(ClaimTopicsRegistryImpl)]
    pub impl ClaimTopicsRegistry<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of IClaimTopicsRegistry<ComponentState<TContractState>> {
        fn add_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {}
        fn remove_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {}
        fn get_claim_topics(self: @ComponentState<TContractState>) -> Array<felt252> {
            array![]
        }
    }

    #[embeddable_as(TrustedIssuerRegistryImpl)]
    pub impl TrustedIssuerRegistry<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of ITrustedIssuersRegistry<ComponentState<TContractState>> {
        fn add_trusted_issuer(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {}
        fn remove_trusted_issuer(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) {}
        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {}
        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Array<ContractAddress> {
            array![]
        }
        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> Array<ContractAddress> {
            array![]
        }
        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress
        ) -> bool {
            true
        }
        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) -> Array<felt252> {
            array![]
        }
        fn has_claim_topic(
            self: @ComponentState<TContractState>, issuer: ContractAddress, claim_topic: felt252
        ) -> bool {
            true
        }
    }

    #[embeddable_as(VerifierABIImpl)]
    pub impl VerifierABIImplementation<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of VerifierABI<ComponentState<TContractState>> {
        // IVerify
        fn verify(self: @ComponentState<TContractState>, identity: ContractAddress) -> bool {
            Verifier::verify(self, identity)
        }

        fn is_claim_topic_required(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> bool {
            Verifier::is_claim_topic_required(self, claim_topic)
        }
        // IClaimTopicsRegistry
        fn add_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {
            ClaimTopicsRegistry::add_claim_topic(ref self, claim_topic);
        }

        fn remove_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {
            ClaimTopicsRegistry::remove_claim_topic(ref self, claim_topic);
        }

        fn get_claim_topics(self: @ComponentState<TContractState>) -> Array<felt252> {
            ClaimTopicsRegistry::get_claim_topics(self)
        }
        // ITrustedIssuerRegistry
        fn add_trusted_issuer(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {
            TrustedIssuerRegistry::add_trusted_issuer(ref self, trusted_issuer, claim_topics);
        }

        fn remove_trusted_issuer(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) {
            TrustedIssuerRegistry::remove_trusted_issuer(ref self, trusted_issuer);
        }

        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {
            TrustedIssuerRegistry::update_issuer_claim_topics(
                ref self, trusted_issuer, claim_topics
            );
        }

        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Array<ContractAddress> {
            TrustedIssuerRegistry::get_trusted_issuers(self)
        }

        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> Array<ContractAddress> {
            TrustedIssuerRegistry::get_trusted_issuers_for_claim_topic(self, claim_topic)
        }

        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress
        ) -> bool {
            TrustedIssuerRegistry::is_trusted_issuer(self, issuer)
        }

        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) -> Array<felt252> {
            TrustedIssuerRegistry::get_trusted_issuer_claim_topics(self, trusted_issuer)
        }

        fn has_claim_topic(
            self: @ComponentState<TContractState>, issuer: ContractAddress, claim_topic: felt252
        ) -> bool {
            TrustedIssuerRegistry::has_claim_topic(self, issuer, claim_topic)
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of InternalTrait<TContractState> {
        fn only_verified_sender(self: @ComponentState<TContractState>) {}
    }
}

