use onchain_id_starknet::storage::structs::Signature;
#[starknet::interface]
pub trait IIdentity<TContractState> {
    fn is_claim_valid(
        self: @TContractState, identity: IIdentityDispatcher, signature: Signature, data: ByteArray
    ) -> bool;
    fn get_recovered_public_key(
        self: @TContractState, signature: Signature, data_hash: u256
    ) -> u256;
}
// is also extends IERC734 and IERC735


