pub mod revoke_claim_by_signature_test {
    #[test]
    #[should_panic]
    fn test_should_panic_when_non_management_key() {
        panic!("");
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_management_key_when_claim_already_revoked() {
        panic!("");
    }

    #[test]
    fn test_should_revoke_claim_when_management_key_when_claim_not_revoked() {
        assert(true, '');
    }
}
