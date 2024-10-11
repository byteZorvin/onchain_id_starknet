use onchain_id_starknet::storage::structs::{Claim, Execution, Key};
use starknet::storage::{Vec, Map};

#[starknet::storage_node]
pub struct IdentityStorage {
    pub execution_nonce: felt252,
    pub keys: Map<u256, Key>,
    pub keys_by_purpose: Map<u256, Vec<u256>>,
    pub executions: Map<u256, Execution>,
    pub claims: Map<u256, Claim>,
    pub claims_by_topic: Map<u256, Vec<u256>>,
    pub initialized: bool,
    pub can_interact: bool,
}
