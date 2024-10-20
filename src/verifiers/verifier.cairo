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
        self: @TContractState, trusted_issuer: ContractAddress, claim_topic: felt252
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

#[starknet::component]
pub mod Verifier {
    use core::iter::IntoIterator;
    use core::num::traits::Zero;
    use onchain_id_starknet::interface::iclaim_issuer::IClaimIssuerDispatcher;
    use onchain_id_starknet::storage::{
        storage::{
            StorageArrayFelt252, StorageArrayContractAddress, MutableStorageArrayTrait,
            StorageArrayTrait
        }
    };
    use starknet::ContractAddress;
    use starknet::event::EventEmitter;
    use starknet::storage::{
        StoragePath, Mutable, VecTrait, StoragePathEntry, StorageAsPath, Map,
        StoragePointerReadAccess, StoragePointerWriteAccess
    };
    use starknet::{get_contract_address};
    use super::ITrustedIssuersRegistry;
    use super::IVerifier;
    #[storage]
    struct Storage {
        required_claim_topics: StorageArrayFelt252,
        trusted_issuers: StorageArrayContractAddress,
        claim_topics_to_trusted_issuers: Map<felt252, StorageArrayContractAddress>,
        trusted_issuer_claim_topics: Map<ContractAddress, StorageArrayFelt252>,
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
    impl VerifierImpl<TContractState> of super::IVerifier<ComponentState<TContractState>> {
        fn verify(self: @ComponentState<TContractState>, identity: ContractAddress) -> bool {
            true
        }

        fn is_claim_topic_required(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> bool {
            let mut is_required = false;
            let required_claim_topics = self.required_claim_topics.as_path();
            for i in 0
                ..required_claim_topics
                    .len() {
                        if claim_topic == required_claim_topics.at(i).read() {
                            is_required = true;
                            break;
                        };
                    };
            is_required
        }
    }

    #[abi(embed_v0)]
    impl ClaimTopicsRegistryImpl<
        TContractState
    > of super::IClaimTopicsRegistry<ComponentState<TContractState>> {
        fn add_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {}
        fn remove_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {}
        fn get_claim_topics(self: @ComponentState<TContractState>) -> Array<felt252> {
            array![]
        }
    }

    #[abi(embed_v0)]
    impl TrustedIssuerRegistryImpl<
        TContractState, +HasComponent<TContractState>
    > of super::ITrustedIssuersRegistry<ComponentState<TContractState>> {
        fn add_trusted_issuer(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {
            assert(trusted_issuer != get_contract_address(), 'invalid argument - zero address');
            assert(
                self.trusted_issuer_claim_topics.as_path().entry(trusted_issuer).len() == 0,
                'trusted Issuer already exists'
            );
            assert(claim_topics.len() > 0, 'claim_topics should > 0');
            assert(claim_topics.len() <= 15, 'max claim_topics should < 16');
            assert(self.trusted_issuers.as_path().len() < 50, 'max trusted_issuers should < 50');

            self.trusted_issuers.as_path().append().write(trusted_issuer);

            let required_claim_topics = self.required_claim_topics.as_path();
            for claim_topic in claim_topics
                .clone() {
                    required_claim_topics.append().write(claim_topic);
                };

            let trusted_issuer_claim_topics = self.trusted_issuer_claim_topics.as_path();
            for claim_topic in claim_topics
                .clone() {
                    trusted_issuer_claim_topics.entry(trusted_issuer).append().write(claim_topic);
                };
            self.emit(TrustedIssuerAdded { trusted_issuer: trusted_issuer, claim_topics })
        }
        fn remove_trusted_issuer(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) {
            assert(trusted_issuer != get_contract_address(), 'invalid argument - zero address');
            assert(
                self.trusted_issuer_claim_topics.as_path().entry(trusted_issuer).len() != 0,
                'trusted issuer does not exist'
            );
            let total_issuers = self.trusted_issuers.as_path();
            let trusted_issuer_claim_topics = self.trusted_issuer_claim_topics.as_path();
            for i in 0
                ..total_issuers
                    .len() {
                        let m = total_issuers.at(i).read();
                        if m == trusted_issuer {
                            total_issuers.delete(i);
                            for i in 0
                                ..trusted_issuer_claim_topics
                                    .entry(m)
                                    .len() {
                                        trusted_issuer_claim_topics.entry(m).delete(i);
                                    };
                        };
                    };
            self.emit(TrustedIssuerRemoved { trusted_issuer: trusted_issuer });
        }
        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {
            assert(trusted_issuer != get_contract_address(), 'invalid argument - zero address');
            assert(
                self.trusted_issuer_claim_topics.entry(trusted_issuer).len() != 0,
                'there are topics'
            );
            assert(claim_topics.len() > 0, 'claim_topics should > 0');
            assert(claim_topics.len() <= 15, 'max claim_topics should < 16');
            self.trusted_issuers.as_path().append().write(trusted_issuer);
            let required_claim_topics = self.required_claim_topics.as_path();
            for claim_topic in claim_topics
                .clone() {
                    required_claim_topics.append().write(claim_topic);
                };
            let trusted_issuer_claim_topics = self.trusted_issuer_claim_topics.as_path();
            let claim_topics_to_trusted_issuers = self.claim_topics_to_trusted_issuers.as_path();

            for i in 0
                ..trusted_issuer_claim_topics
                    .entry(trusted_issuer)
                    .len() {
                        trusted_issuer_claim_topics.entry(trusted_issuer).delete(i);
                    };

            for claim_topic in claim_topics
                .clone() {
                    trusted_issuer_claim_topics.entry(trusted_issuer).append().write(claim_topic);
                    for i in 0
                        ..claim_topics_to_trusted_issuers
                            .entry(claim_topic)
                            .len() {
                                if trusted_issuer == claim_topics_to_trusted_issuers
                                    .entry(claim_topic)
                                    .at(i)
                                    .read() {
                                    claim_topics_to_trusted_issuers.entry(claim_topic).delete(i);
                                }
                            }
                };
            self.emit(TrustedIssuerAdded { trusted_issuer: trusted_issuer, claim_topics });
        }
        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Array<ContractAddress> {
            let mut issuers_array = ArrayTrait::<ContractAddress>::new();
            let trusted_issuers = self.trusted_issuers.as_path();

            for i in 0
                ..trusted_issuers.len() {
                    issuers_array.append(trusted_issuers.at(i).read());
                };

            issuers_array
        }
        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> Array<ContractAddress> {
            let mut issuers_with_topic = ArrayTrait::<ContractAddress>::new();
            let claim_topics_to_trusted_issuers = self.claim_topics_to_trusted_issuers.as_path();
            for i in 0
                ..claim_topics_to_trusted_issuers
                    .entry(claim_topic)
                    .len() {
                        issuers_with_topic
                            .append(
                                claim_topics_to_trusted_issuers.entry(claim_topic).at(i).read()
                            );
                    };
            issuers_with_topic
        }
        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress
        ) -> bool {
            let trusted_issuers = self.trusted_issuers.as_path();
            let mut is_trusted = false;
            for i in 0
                ..trusted_issuers
                    .len() {
                        if issuer == trusted_issuers.at(i).read() {
                            is_trusted = true;
                            break;
                        };
                    };

            is_trusted
        }
        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) -> Array<felt252> {
            assert(
                self.trusted_issuer_claim_topics.as_path().entry(trusted_issuer).len() != 0,
                'trusted issuer does not exist'
            );
            let mut topics = ArrayTrait::<felt252>::new();
            let trusted_issuer_claim_topics = self.trusted_issuer_claim_topics.as_path();
            for i in 0
                ..trusted_issuer_claim_topics
                    .entry(trusted_issuer)
                    .len() {
                        topics
                            .append(trusted_issuer_claim_topics.entry(trusted_issuer).at(i).read());
                    };
            topics
        }
        fn has_claim_topic(
            self: @ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topic: felt252
        ) -> bool {
            let trusted_issuer_claim_topics = self.trusted_issuer_claim_topics.as_path();
            let mut has_claim = false;
            if trusted_issuer_claim_topics.entry(trusted_issuer).len() > 0 {
                has_claim = true
            }
            has_claim
        }
    }

    #[generate_trait]
    impl InternalImpl<TContractState> of InternalTrait<TContractState> {
        fn only_verified_sender(self: @ComponentState<TContractState>) {}
    }
}

