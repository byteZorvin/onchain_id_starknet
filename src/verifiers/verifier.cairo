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
    use super::IVerifier;
    use starknet::storage::{StoragePath, Mutable,VecTrait,StoragePathEntry,StorageAsPath,Map,  StoragePointerReadAccess, StoragePointerWriteAccess};
    use core::iter::IntoIterator;
    use super::ITrustedIssuersRegistry;
    use starknet::event::EventEmitter;
    use onchain_id_starknet::interface::iclaim_issuer::IClaimIssuerDispatcher;
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use core::num::traits::Zero;
    use onchain_id_starknet::storage::{storage::{StorageArrayFelt252, StorageArrayContractAddress, MutableStorageArrayTrait, StorageArrayTrait} };
    #[storage]
    struct Storage {
        required_claim_topics: StorageArrayFelt252,
        trusted_issuers: StorageArrayContractAddress,
        claim_topics_to_trusted_issuers: Map<ContractAddress, StorageArrayFelt252>,
    }

    #[starknet::storage_node]
    struct RemovableVec{
        len: u8,
        vec: Map<u8,ContractAddress>
    }

    #[starknet::storage_node]
    struct RemovableVecFelt {
        len: u8,
        vec: Map<u8,felt252>,
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

    fn add(self: StoragePath<Mutable<RemovableVec>>, trusted_address: ContractAddress)  {
        let index_to_write = self.len.read();
        self.vec.entry(index_to_write).write(trusted_address);   
    }

    fn remove(self: StoragePath<Mutable<RemovableVec>>, index:u8) {
        let len = self.len.read();
        if index != len -1 {
            let last_element = self.vec.entry(len-1).read();
            self.vec.entry(index).write(last_element);
        }
        self.vec.entry(len-1).write(Zero::zero());
    }

    fn update(self: StoragePath<Mutable<RemovableVec>>, index:u8, trusted_address: ContractAddress){
        self.vec.entry(index).write(trusted_address);
    }
    
    
    #[abi(embed_v0)]
    impl VerifierImpl<TContractState> of super::IVerifier<ComponentState<TContractState>> {
        fn verify(self: @ComponentState<TContractState>, identity: ContractAddress) -> bool {
            true
        }

        fn is_claim_topic_required(self: @ComponentState<TContractState>, claim_topic: felt252) -> bool {
            for i in 0..self.required_claim_topics.as_path().len(){
                if claim_topic == self.required_claim_topics.as_path().at(i).read() {
                    true;
                }
            };
            false
        }
    }

    #[abi(embed_v0)]
    impl ClaimTopicsRegistryImpl<TContractState>  of super::IClaimTopicsRegistry<ComponentState<TContractState>> {
        fn add_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {}
        fn remove_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {}
        fn get_claim_topics(self: @ComponentState<TContractState>) -> Array<felt252> {
            array![]
        }
    }

    #[abi(embed_v0)]
    impl TrustedIssuerRegistryImpl<TContractState,+HasComponent<TContractState>> of super::ITrustedIssuersRegistry<ComponentState<TContractState>> {
        fn add_trusted_issuer(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress, claim_topics: Array<felt252>
        ) {
            assert(trusted_issuer != get_caller_address(), 'invalid argument - zero address');
            assert(self.claim_topics_to_trusted_issuers.entry(trusted_issuer).len() == 0,'trusted Issuer already exists');
            assert(claim_topics.len()>0, 'claim_topics should > 0');
            assert(claim_topics.len()<=15, 'max claim_topics should < 16');
            assert(self.trusted_issuers.as_path().len()<50, 'max trusted_issuers should < 50');
            
            self.trusted_issuers.as_path().append().write(trusted_issuer);
            for claim_topic in claim_topics.clone(){
                self.required_claim_topics.as_path().append().write(claim_topic);
            };
            for claim_topic in claim_topics.clone() {
                self.claim_topics_to_trusted_issuers.entry(trusted_issuer).append().write(claim_topic);
            };
            self.emit(TrustedIssuerAdded { trusted_issuer: trusted_issuer, claim_topics })
        }
        fn remove_trusted_issuer(ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress) {
            assert(trusted_issuer!=get_caller_address(), 'invalid argument - zero address');
            assert(self.claim_topics_to_trusted_issuers.entry(trusted_issuer).len() == 0,'trusted Issuer already exists');
            let total_issuers=self.trusted_issuers.as_path().len();
            for i in 0..total_issuers{
                let m = self.trusted_issuers.as_path().at(i).read();
                if m == trusted_issuer {
                    self.trusted_issuers.as_path().delete(i);
                }

            };
            self.emit(TrustedIssuerRemoved { trusted_issuer: trusted_issuer});
        }
        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress, claim_topics: Array<felt252>
        ) {
            assert(trusted_issuer!=get_caller_address(), 'invalid argument - zero address');
            assert(self.claim_topics_to_trusted_issuers.entry(trusted_issuer).len() == 0,'there are topics');
            assert(claim_topics.len()>0, 'claim_topics should > 0');
            assert(claim_topics.len()<=15, 'max claim_topics should < 16');
            self.trusted_issuers.as_path().append().write(trusted_issuer);
            for claim_topic in claim_topics.clone(){
                self.required_claim_topics.as_path().append().write(claim_topic);
            };
            
            for i in 0..self.claim_topics_to_trusted_issuers.entry(trusted_issuer).len(){
                self.claim_topics_to_trusted_issuers.entry(trusted_issuer).delete(0);
            };

            //TODO remove the claim_topic is used by another trusted_issuer

            for claim_topic in claim_topics.clone() {
                self.claim_topics_to_trusted_issuers.entry(trusted_issuer).append().write(claim_topic);
            };
            self.emit(TrustedIssuerAdded { trusted_issuer: trusted_issuer, claim_topics });
        }
        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Array<ContractAddress> {
            let mut issuers_array = ArrayTrait::<ContractAddress>::new();
            let total_issuers = self.trusted_issuers.as_path().len();

            for i in 0..total_issuers{
                issuers_array.append(self.trusted_issuers.as_path().at(i).read());
            };

            issuers_array
        }
        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> Array<ContractAddress> {
            let mut issuers_with_topic = ArrayTrait::<ContractAddress>::new();

            let issuers_array = self.get_trusted_issuers();
            
            for issuer in issuers_array {
                for i in 0..self.claim_topics_to_trusted_issuers.entry(issuer).len(){
                    if claim_topic == self.claim_topics_to_trusted_issuers.entry(issuer).at(i).read(){
                        issuers_with_topic.append(issuer);
                        break;
                    };
                };  
            };

            issuers_with_topic

        }
        fn is_trusted_issuer(self: @ComponentState<TContractState>, issuer: ContractAddress) -> bool {
            let total_issuers = self.trusted_issuers.as_path().len();

            for i in 0..total_issuers{
                if issuer == self.trusted_issuers.as_path().at(i).read() {
                    true;
                }
            };

            false
        }
        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) -> Array<felt252> {
            assert(self.claim_topics_to_trusted_issuers.entry(trusted_issuer).len() == 0,'trusted Issuer already exists');
            let mut topics = ArrayTrait::<felt252>::new();

            for i in 0..self.claim_topics_to_trusted_issuers.entry(trusted_issuer).len(){
                topics.append(self.claim_topics_to_trusted_issuers.entry(trusted_issuer).at(i).read());
            };  
            topics
        }
        fn has_claim_topic(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress, claim_topic: felt252
        ) -> bool {
            if self.claim_topics_to_trusted_issuers.entry(trusted_issuer).len() > 0 {
                true
            }else{
                false
            }
            
        }
    }

    #[generate_trait]
    impl InternalImpl<TContractState>   of InternalTrait<TContractState> {
        fn only_verified_sender(self: @ComponentState<TContractState>) {}
    }

}

