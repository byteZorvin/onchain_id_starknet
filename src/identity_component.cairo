#[starknet::component]
pub mod IdentityComponent {
    #[allow(unused_imports)]
    use onchain_id_starknet::interface::{
        iclaim_issuer::{IClaimIssuer, IClaimIssuerDispatcher, IClaimIssuerDispatcherTrait},
        iidentity::{IIdentity, IIdentityDispatcher}, ierc734::IERC734, ierc734, ierc735::IERC735,
        ierc735
    };
    #[allow(unused_imports)]
    use onchain_id_starknet::version::version::Version;
    use onchain_id_starknet::storage::{storage::IdentityStorage, structs::Signature};
    use starknet::ContractAddress;
    use starknet::storage::{ //    StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, //    StoragePointerWriteAccess
    };

    #[storage]
    pub struct Storage {
        #[flat]
        IdentityComponent_storage: IdentityStorage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        IERC735Event: ierc735::ERC735Event,
        #[flat]
        IERC734Event: ierc734::ERC734Event,
    }

    // TODO: implement the interface
    #[embeddable_as(IdentityImpl)]
    pub impl Identity<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>
    > of IIdentity<ComponentState<TContractState>> {
        // TODO: this should be partialy overiddeable by claim issuer
        fn is_claim_valid(
            self: @ComponentState<TContractState>,
            identity: IIdentityDispatcher,
            signature: Signature,
            data: ByteArray
        ) -> bool {
            true
        }

        fn get_recovered_public_key(
            self: @ComponentState<TContractState>, signature: Signature, data_hash: u256
        ) -> u256 {
            0
        }
    }
    // TODO: Implement the interface
    #[embeddable_as(ERC734Impl)]
    pub impl ERC734<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>
    > of IERC734<ComponentState<TContractState>> {
        fn add_key(
            ref self: ComponentState<TContractState>, key: felt252, purpose: u256, key_type: u256
        ) -> bool {
            true
        }
        fn approve(ref self: ComponentState<TContractState>, id: u256, approve: bool) -> bool {
            true
        }
        fn remove_key(
            ref self: ComponentState<TContractState>, key: felt252, purpose: u256
        ) -> bool {
            true
        }
        fn execute(
            ref self: ComponentState<TContractState>,
            to: ContractAddress,
            value: u256,
            data: ByteArray
        ) -> u256 {
            0_u256
        }
        fn get_key(
            self: @ComponentState<TContractState>, key: felt252
        ) -> (Array<u256>, u256, felt252) { // TODO: add return type
            (array![], 0, 0)
        }
        fn get_key_purposes(self: @ComponentState<TContractState>, key: felt252) -> Array<u256> {
            array![]
        }
        fn get_keys_by_purpose(
            self: @ComponentState<TContractState>, purpose: u256
        ) -> Array<felt252> {
            array![]
        }
        fn key_has_purpose(
            self: @ComponentState<TContractState>, key: felt252, purpose: u256
        ) -> bool {
            true
        }
    }

    #[embeddable_as(ERC735Impl)]
    pub impl ERC735<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>
    > of IERC735<ComponentState<TContractState>> {
        fn add_claim(
            ref self: ComponentState<TContractState>,
            topic: u256,
            scheme: u256,
            issuer: ContractAddress,
            signature: Signature,
            data: ByteArray,
            uri: ByteArray
        ) -> felt252 {
            0
        }
        fn remove_claim(ref self: ComponentState<TContractState>, claim_id: felt252) -> bool {
            true
        }
        // TODO: turn this into a struct? maybe
        fn get_claim(
            self: @ComponentState<TContractState>, claim_id: felt252
        ) -> (u256, u256, ContractAddress, Signature, ByteArray, ByteArray) {
            (0, 0, starknet::contract_address_const::<0>(), Signature { r: 0, s: 0 }, "", "")
        }

        fn get_claim_ids_by_topics(
            self: @ComponentState<TContractState>, topic: u256
        ) -> Array<felt252> {
            array![]
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>
    > of InternalTrait<TContractState> {
        // TODO: ensure parameters are correct and generak init mechanism satisfies the .sol
        // behavior
        fn initialize(
            ref self: ComponentState<TContractState>, initial_management_key: ContractAddress
        ) {}

        // TODO : decide do we need this
        fn delegated_only(self: @ComponentState<TContractState>) {
            assert!(
                self.IdentityComponent_storage.can_interact.read(),
                "Interacting with the library contract is forbidden."
            );
        }
        // TODO:
        fn only_manager(
            self: @ComponentState<TContractState>
        ) { //assert!((starknet::get_caller_address() == starknet::get_contract_address()) ||
        //key_has_purpose(), "Permissions: Sender does not have management key");
        }
        // TODO:
        fn only_claim_key(self: @ComponentState<TContractState>) {}
    }
}
