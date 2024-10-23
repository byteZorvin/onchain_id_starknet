pub mod claim_issuer;
pub mod identity;
pub mod identity_component;
pub mod factory {
    pub mod id_factory;
    pub mod iid_factory;
}
pub mod gateway {
    pub mod gateway;
}
pub mod interface {
    pub mod iclaim_issuer;
    pub mod ierc734;
    pub mod ierc735;
    pub mod iidentity;
    pub mod iimplementation_authority;
}
pub mod proxy {
    pub mod implementation_authority;
    pub mod version_manager;
}
pub mod storage {
    pub mod storage;
    pub mod structs;
}
pub mod verifiers {
    pub mod verifier;
}
pub mod version {
    pub mod version;
}
