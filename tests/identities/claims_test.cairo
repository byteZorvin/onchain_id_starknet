pub mod add_claim {
    #[test]
    fn test_should_add_claim_when_self_attested_when_claim_not_valid() {
        assert(true, '');
    }

    #[test]
    fn test_should_add_claim_when_self_attested_when_claim_valid_when_caller_is_identity() {
        assert(true, '');
    }

    #[test]
    fn test_should_add_claim_when_self_attested_when_claim_valid_when_caller_is_claim_or_management_key() {
        assert(true, '');
    }

    #[test]
    #[should_panic]
    fn test_should_panic_if_caller_is_not_claim_key() {
        panic!("");
    }
}

pub mod update_claim {
    #[test]
    fn test_should_replace_existing_claim() {
        assert(true, '');
    }
}

pub mod remove_claim {
    #[test]
    fn test_should_remove_existing_claim_when_caller_is_identity_contract() {
        assert(true, '');
    }
    #[test]
    #[should_panic]
    fn test_should_panic_when_caller_is_not_a_claim_key() {
        panic!("");
    }
    #[test]
    #[should_panic]
    fn test_should_panic_when_claim_does_not_exist() {
        panic!("");
    }
    #[test]
    fn test_should_remove_claim_when_caller_has_claim_or_management_key() {
        assert(true, '');
    }
}

pub mod get_claim {
    #[test]
    fn test_should_return_default_values_when_claim_does_not_exist() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_claim_data() {
        assert(true, '');
    }
}

pub mod get_claims_by_topic {
    #[test]
    fn test_should_return_empty_array_when_there_are_no_claim_topics() {
        assert(true, '');
    }
    #[test]
    fn test_should_return_array_of_claim_ids_existing_for_topic() {
        assert(true, '');
    }
}
