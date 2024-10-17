use onchain_id_starknet::storage::structs::Signature;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IClaimIssuer<TContractState> {
    fn revoke_claim(ref self: TContractState, claim_id: felt252, identity: ContractAddress) -> bool;
    fn revoke_claim_by_signature(ref self: TContractState, signature: Signature);
    fn is_claim_revoked(self: @TContractState, signature: Signature) -> bool;
}
