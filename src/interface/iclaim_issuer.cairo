use onchain_id_starknet::interface::iidentity::IIdentityDispatcher;
use onchain_id_starknet::storage::structs::{Signature, SignatureHash};
use starknet::ContractAddress;

#[starknet::interface]
pub trait IClaimIssuer<TContractState> {
    fn revoke_claim(ref self: TContractState, claim_id: felt252, identity: ContractAddress) -> bool;
    fn revoke_claim_by_signature(ref self: TContractState, signature: SignatureHash);
    fn is_claim_revoked(self: @TContractState, signature: SignatureHash) -> bool;
    fn is_claim_valid(
        self: @TContractState,
        identity: IIdentityDispatcher,
        claim_topic: felt252,
        signature: Signature,
        data: ByteArray
    ) -> bool;
}
