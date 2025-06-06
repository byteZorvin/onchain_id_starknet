pub mod revoke_claim_by_signature_test {
    use onchain_id_starknet::claim_issuer::claim_issuer::ClaimIssuer;
    use onchain_id_starknet::claim_issuer::interface::ClaimIssuerABIDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::setup_identity;

    #[test]
    #[should_panic(expected: 'Sender not have management key')]
    fn test_should_panic_when_non_management_key() {
        let setup = setup_identity();
        setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
    }

    #[test]
    #[should_panic(expected: 'Claim already revoked')]
    fn test_should_panic_when_management_key_when_claim_already_revoked() {
        let setup = setup_identity();
        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
        // Revoking already revoked claim should panic
        setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);
    }

    #[test]
    fn test_should_revoke_claim_when_management_key_when_claim_not_revoked() {
        let setup = setup_identity();

        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);
        let is_valid_claim = setup
            .claim_issuer
            .is_claim_valid(
                setup.alice_claim_666.identity,
                setup.alice_claim_666.topic,
                setup.alice_claim_666.signature,
                setup.alice_claim_666.data,
            );

        assert!(!is_valid_claim, "Claim not revoked");
        spy
            .assert_emitted(
                @array![
                    (
                        setup.claim_issuer.contract_address,
                        ClaimIssuer::Event::ClaimRevoked(
                            ClaimIssuer::ClaimRevoked {
                                signature: setup.alice_claim_666.signature,
                            },
                        ),
                    ),
                ],
            );
    }
}

pub mod revoke_claim {
    use onchain_id_starknet::claim_issuer::claim_issuer::ClaimIssuer;
    use onchain_id_starknet::claim_issuer::interface::ClaimIssuerABIDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::setup_identity;

    #[test]
    #[should_panic(expected: 'Sender not have management key')]
    fn test_should_panic_when_non_management_key() {
        let setup = setup_identity();
        setup
            .claim_issuer
            .revoke_claim(setup.alice_claim_666.claim_id, setup.alice_claim_666.identity);
    }

    #[test]
    #[should_panic(expected: 'Claim already revoked')]
    fn test_should_panic_when_management_key_when_claim_already_revoked() {
        let setup = setup_identity();
        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup
            .claim_issuer
            .revoke_claim(setup.alice_claim_666.claim_id, setup.alice_claim_666.identity);
        // Revoking already revoked claim should panic
        setup
            .claim_issuer
            .revoke_claim(setup.alice_claim_666.claim_id, setup.alice_claim_666.identity);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);
    }

    #[test]
    fn test_should_revoke_claim_when_management_key_when_claim_not_revoked() {
        let setup = setup_identity();

        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup
            .claim_issuer
            .revoke_claim(setup.alice_claim_666.claim_id, setup.alice_claim_666.identity);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);
        let is_valid_claim = setup
            .claim_issuer
            .is_claim_valid(
                setup.alice_claim_666.identity,
                setup.alice_claim_666.topic,
                setup.alice_claim_666.signature,
                setup.alice_claim_666.data,
            );

        assert!(!is_valid_claim, "Claim not revoked");
        spy
            .assert_emitted(
                @array![
                    (
                        setup.claim_issuer.contract_address,
                        ClaimIssuer::Event::ClaimRevoked(
                            ClaimIssuer::ClaimRevoked {
                                signature: setup.alice_claim_666.signature,
                            },
                        ),
                    ),
                ],
            );
    }
}

pub mod is_claim_valid {
    use onchain_id_starknet::claim_issuer::interface::ClaimIssuerABIDispatcherTrait;
    use onchain_id_starknet::identity::identity::Identity::SNIP12MetadataImpl;
    use onchain_id_starknet::libraries::signature::{ClaimMessage, Signature, StarkSignature};
    use openzeppelin_utils::cryptography::snip12::OffchainMessageHash;
    use snforge_std::signature::SignerTrait;
    use snforge_std::signature::stark_curve::{
        StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl,
    };
    use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};
    use crate::common::{get_test_claim, setup_identity};

    #[test]
    fn test_should_return_false_when_key_does_not_have_claim_or_management_purpose() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(
            @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
        );

        let hashed_claim = ClaimMessage {
            identity: test_claim.identity, topic: test_claim.topic, data: test_claim.data,
        }
            .get_message_hash(setup.claim_issuer.contract_address);

        test_claim.issuer = setup.accounts.bob_account.contract_address;
        let (r, s) = setup.accounts.bob_key.sign(hashed_claim).unwrap();
        let signature = Signature::StarkSignature(
            StarkSignature { r, s, public_key: setup.accounts.bob_key.public_key },
        );
        let mut serialized_signature = Default::default();
        signature.serialize(ref serialized_signature);

        test_claim.signature = serialized_signature.span();

        let is_claim_valid = setup
            .claim_issuer
            .is_claim_valid(
                test_claim.identity, test_claim.topic, test_claim.signature, test_claim.data,
            );
        assert!(!is_claim_valid, "Claim should be invalid for non-management, non-claim key");
    }

    #[test]
    fn test_should_return_false_when_key_has_claim_purpose_when_signature_revoked() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(
            @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
        );

        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup.claim_issuer.revoke_claim_by_signature(test_claim.signature);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);

        let is_claim_valid = setup
            .claim_issuer
            .is_claim_valid(
                test_claim.identity, test_claim.topic, test_claim.signature, test_claim.data,
            );
        assert!(!is_claim_valid, "Claim should be invalid when signature is revoked");
    }

    #[test]
    fn test_should_return_false_when_invalid_signature() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(
            @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
        );

        let signature = Signature::StarkSignature(
            StarkSignature {
                r: 'random_r',
                s: 'random_s',
                public_key: setup.accounts.claim_issuer_key.public_key,
            },
        );
        let mut serialized_signature = Default::default();
        signature.serialize(ref serialized_signature);
        test_claim.signature = serialized_signature.span();

        let is_claim_valid = setup
            .claim_issuer
            .is_claim_valid(
                test_claim.identity, test_claim.topic, test_claim.signature, test_claim.data,
            );
        assert!(!is_claim_valid, "Claim should be invalid when signature is invalid");
    }

    #[test]
    fn test_should_return_true_when_valid_signature() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(
            @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
        );

        let is_claim_valid = setup
            .claim_issuer
            .is_claim_valid(
                test_claim.identity, test_claim.topic, test_claim.signature, test_claim.data,
            );
        assert!(
            is_claim_valid,
            "Claim should be valid when signature is valid when key has (claim/management) purpose",
        );
    }
}

