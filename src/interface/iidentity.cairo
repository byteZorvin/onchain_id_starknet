use onchain_id_starknet::storage::structs::Signature;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IIdentity<TContractState> {
    fn is_claim_valid(
        self: @TContractState,
        identity: ContractAddress,
        claim_topic: felt252,
        signature: Signature,
        data: ByteArray
    ) -> bool;
}
// is also extends IERC734 and IERC735


