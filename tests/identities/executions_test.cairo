pub mod execute {
    pub mod when_management_key {
        #[test]
        fn test_should_execute_immediately() {
            assert(true, '');
        }

        #[test]
        fn test_should_emit_executed_event_on_successful_call() {
            assert(true, '');
        }

        #[test]
        fn test_should_emit_execution_failed_event_on_failing_call() {
            assert(true, '');
        }
    }

    pub mod when_action_key {
        #[test]
        fn test_should_create_execution_request_when_target_is_identity_contract() {
            assert(true, '');
        }

        #[test]
        fn test_should_execute_immediately_when_target_is_another_contract() {
            assert(true, '');
        }

        #[test]
        fn test_should_emit_execution_failed_on_failed_transaction() {
            assert(true, '');
        }
    }

    pub mod when_non_action_key {
        #[test]
        fn test_should_create_pending_execution_requset() {
            assert(true, '');
        }
    }
}

pub mod approve {
    #[test]
    #[should_panic]
    fn test_should_revert_when_execution_request_not_found() {
        panic!("");
    }

    #[test]
    #[should_panic]
    fn test_should_revert_when_execution_request_is_already_executed() {
        panic!("");
    }

    #[test]
    #[should_panic]
    fn test_should_revert_when_target_is_another_contract_as_non_action_nor_management_key() {
        panic!("");
    }

    #[test]
    #[should_panic]
    fn test_should_revert_when_target_is_identity_contract_as_non_management_key() {
        panic!("");
    }

    #[test]
    fn test_should_approve_the_execution_request_when_management_key() {
        assert(true, '');
    }

    #[test]
    fn test_should_approve_the_execution_request_to_another_contract_when_action_key() {
        assert(true, '');
    }

    #[test]
    fn test_should_leave_approve_false() {
        assert(true, '');
    }
}
