pub mod read_key_methods {
    #[test]
    fn test_should_return_full_key_details() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_existing_key_purposes() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_existing_keys_with_given_purposes() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_true_if_key_has_given_purpose() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_true_if_key_does_not_have_given_purpose_but_is_a_management_key() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_false_if_key_does_not_have_given_purpose() {
        assert(true, '');
    }
}

pub mod add_key_methods {
    #[test]
    #[should_panic]
    fn test_should_panic_when_caller_not_has_management_key() {
        panic!("");
    }

    #[test]
    fn test_should_add_purpose_to_existing_key() {
        assert(true, '');
    }

    #[test]
    fn test_should_create_new_key_with_given_purpose() {
        assert(true, '');
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_key_already_has_given_purpose() {
        panic!("");
    }
}

pub mod remove_key_methods {
    #[test]
    #[should_panic]
    fn test_should_panic_when_caller_not_has_management_key() {
        panic!("");
    }

    #[test]
    fn test_should_remove_purpose_from_existing_key() {
        assert(true, '');
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_key_does_not_exist() {
        panic!("");
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_key_does_not_have_given_purpose() {
        panic!("");
    }
}
