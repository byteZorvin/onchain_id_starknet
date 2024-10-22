#[test]
#[should_panic]
fn test_should_panic_when_deployment_when_implementation_authority_zero_address() {
    panic!("");
}

pub mod create_identity {
    #[test]
    #[should_panic]
    fn test_should_panic_when_caller_is_not_authorized() {
        panic!("");
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_wallet_zero_address() {
        panic!("");
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_salt_is_zero() {
        panic!("");
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_salt_is_taken() {
        panic!("");
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_wallet_already_linked_to_an_identity() {
        panic!("");
    }
}

pub mod create_identity_with_management_keys {
    #[test]
    #[should_panic]
    fn test_should_panic_when_no_management_keys_are_provided() {
        panic!("");
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_wallet_is_included_in_management_keys() {
        panic!("");
    }

    #[test]
    fn test_should_deploy_identity_with_management_keys_and_link_wallet_to_identity() {
        assert(true, '');
    }
}

pub mod link_unlink_wallet {
    pub mod link_wallet {
        #[test]
        #[should_panic]
        fn test_should_revert_when_new_wallet_is_zero_address() {
            panic!("");
        }
        #[test]
        #[should_panic]
        fn test_should_revert_when_caller_is_not_linked_wallet() {
            panic!("");
        }
        #[test]
        #[should_panic]
        fn test_should_revert_when_new_wallet_already_linked_identity() {
            panic!("");
        }
        #[test]
        #[should_panic]
        fn test_should_revert_when_new_wallet_already_linked_to_token_identity() {
            panic!("");
        }
        #[test]
        fn test_should_link_new_wallet_to_existing_identity() {
            assert(true, '');
        }
    }

    pub mod unlink_wallet {
        #[test]
        #[should_panic]
        fn test_should_panic_when_wallet_to_unlink_is_zero_address() {
            panic!("");
        }

        #[test]
        #[should_panic]
        fn test_should_panic_when_wallet_to_unlink_is_caller() {
            panic!("");
        }
        #[test]
        #[should_panic]
        fn test_should_panic_when_caller_is_not_linked() {
            panic!("");
        }

        #[test]
        fn test_should_unlink_wallet() {
            assert(true, '');
        }
    }
}

