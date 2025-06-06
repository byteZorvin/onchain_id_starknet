use core::poseidon::poseidon_hash_span;
use onchain_id_starknet::claim_issuer::interface::{
    ClaimIssuerABIDispatcher, ClaimIssuerABIDispatcherTrait,
};
use onchain_id_starknet::factory::interface::{IIdFactoryDispatcher, IIdFactoryDispatcherTrait};
use onchain_id_starknet::identity::identity::Identity::SNIP12MetadataImpl;
use onchain_id_starknet::identity::interface::iidentity::{
    IdentityABIDispatcher, IdentityABIDispatcherTrait,
};
use onchain_id_starknet::implementation_authority::interface::IIdentityImplementationAuthorityDispatcher;
use onchain_id_starknet::libraries::signature::{ClaimMessage, Signature, StarkSignature};
use onchain_id_starknet::verifiers::interface::{VerifierABIDispatcher, VerifierABIDispatcherTrait};
use openzeppelin_account::interface::AccountABIDispatcher;
use openzeppelin_utils::cryptography::snip12::OffchainMessageHash;
use snforge_std::signature::stark_curve::{
    StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl,
};
use snforge_std::signature::{KeyPair, KeyPairTrait, SignerTrait};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::ContractAddress;

#[derive(Drop)]
pub struct TestAccounts {
    pub owner_key: KeyPair<felt252, felt252>,
    pub owner_account: AccountABIDispatcher,
    pub alice_key: KeyPair<felt252, felt252>,
    pub alice_account: AccountABIDispatcher,
    pub bob_key: KeyPair<felt252, felt252>,
    pub bob_account: AccountABIDispatcher,
    pub carol_key: KeyPair<felt252, felt252>,
    pub carol_account: AccountABIDispatcher,
    pub david_key: KeyPair<felt252, felt252>,
    pub david_account: AccountABIDispatcher,
    pub claim_issuer_key: KeyPair<felt252, felt252>,
    pub claim_issuer_account: AccountABIDispatcher,
    pub token_owner_key: KeyPair<felt252, felt252>,
    pub token_owner_account: AccountABIDispatcher,
}

#[derive(Drop)]
pub struct FactorySetup {
    pub identity_factory: IIdFactoryDispatcher,
    pub identity_contract: starknet::ClassHash,
    pub implementation_authority: IIdentityImplementationAuthorityDispatcher,
    pub accounts: TestAccounts,
}

#[derive(Drop)]
pub struct IdentitySetup {
    pub identity_factory: IIdFactoryDispatcher,
    pub identity_contract: starknet::ClassHash,
    pub implementation_authority: IIdentityImplementationAuthorityDispatcher,
    pub claim_issuer: ClaimIssuerABIDispatcher,
    pub accounts: TestAccounts,
    pub alice_identity: IdentityABIDispatcher,
    pub bob_identity: IdentityABIDispatcher,
    pub alice_claim_666: TestClaim,
    pub token_address: ContractAddress,
}

#[derive(Drop)]
pub struct TestClaim {
    pub claim_id: felt252,
    pub topic: felt252,
    pub scheme: felt252,
    pub identity: ContractAddress,
    pub issuer: ContractAddress,
    pub signature: Span<felt252>,
    pub data: Span<felt252>,
    pub uri: ByteArray,
}

pub fn setup_accounts() -> TestAccounts {
    let mock_account_contract = declare("MockAccount").unwrap().contract_class();
    // set deployer key and account
    let owner_key = KeyPairTrait::<felt252, felt252>::generate();
    let (owner_account_address, _) = mock_account_contract
        .deploy(@array![owner_key.public_key])
        .unwrap();
    let owner_account = AccountABIDispatcher { contract_address: owner_account_address };
    // set alice key and account
    let alice_key = KeyPairTrait::<felt252, felt252>::generate();
    let (alice_account_address, _) = mock_account_contract
        .deploy(@array![alice_key.public_key])
        .unwrap();
    let alice_account = AccountABIDispatcher { contract_address: alice_account_address };
    // set bob key and account
    let bob_key = KeyPairTrait::<felt252, felt252>::generate();
    let (bob_account_address, _) = mock_account_contract
        .deploy(@array![bob_key.public_key])
        .unwrap();
    let bob_account = AccountABIDispatcher { contract_address: bob_account_address };
    // set carol key and account
    let carol_key = KeyPairTrait::<felt252, felt252>::generate();
    let (carol_account_address, _) = mock_account_contract
        .deploy(@array![carol_key.public_key])
        .unwrap();
    let carol_account = AccountABIDispatcher { contract_address: carol_account_address };
    // set david key and account
    let david_key = KeyPairTrait::<felt252, felt252>::generate();
    let (david_account_address, _) = mock_account_contract
        .deploy(@array![david_key.public_key])
        .unwrap();
    let david_account = AccountABIDispatcher { contract_address: david_account_address };
    // set claim issuer key and account
    let claim_issuer_key = KeyPairTrait::<felt252, felt252>::generate();
    let (claim_issuer_account_address, _) = mock_account_contract
        .deploy(@array![claim_issuer_key.public_key])
        .unwrap();
    let claim_issuer_account = AccountABIDispatcher {
        contract_address: claim_issuer_account_address,
    };
    // set token owner key and account
    let token_owner_key = KeyPairTrait::<felt252, felt252>::generate();
    let (token_owner_account_address, _) = mock_account_contract
        .deploy(@array![token_owner_key.public_key])
        .unwrap();
    let token_owner_account = AccountABIDispatcher {
        contract_address: token_owner_account_address,
    };

    TestAccounts {
        owner_key,
        owner_account,
        alice_key,
        alice_account,
        bob_key,
        bob_account,
        carol_key,
        carol_account,
        david_key,
        david_account,
        claim_issuer_key,
        claim_issuer_account,
        token_owner_key,
        token_owner_account,
    }
}

pub fn setup_factory() -> FactorySetup {
    let test_accounts = setup_accounts();
    // Declare Identity Contract
    let identity_contract = declare("Identity").unwrap().contract_class().class_hash;
    // Declare and Deploy ImplementationAuthority
    let implementation_authority_contract = declare("IdentityImplementationAuthority")
        .unwrap()
        .contract_class();
    let mut implementation_authority_ctor_data: Array<felt252> = array![];
    identity_contract.serialize(ref implementation_authority_ctor_data);
    test_accounts.owner_account.contract_address.serialize(ref implementation_authority_ctor_data);
    let (implementation_authority_address, _) = implementation_authority_contract
        .deploy(@implementation_authority_ctor_data)
        .unwrap();
    let mut implementation_authority_dispatcher = IIdentityImplementationAuthorityDispatcher {
        contract_address: implementation_authority_address,
    };
    // Declare and Deploy IdFactory
    let id_factory_contract = declare("IdFactory").unwrap().contract_class();
    let (id_factory_address, _) = id_factory_contract
        .deploy(
            @array![
                implementation_authority_address.into(),
                test_accounts.owner_account.contract_address.into(),
            ],
        )
        .unwrap();
    let id_factory_dispatcher = IIdFactoryDispatcher { contract_address: id_factory_address };

    FactorySetup {
        identity_factory: id_factory_dispatcher,
        identity_contract: *identity_contract,
        implementation_authority: implementation_authority_dispatcher,
        accounts: test_accounts,
    }
}

pub fn setup_identity() -> IdentitySetup {
    let mut factory_setup = setup_factory();

    let claim_issuer_contract = declare("ClaimIssuer").unwrap().contract_class();
    let (claim_issuer_address, _) = claim_issuer_contract
        .deploy(@array![factory_setup.accounts.claim_issuer_account.contract_address.into()])
        .unwrap();
    let claim_issuer_dispatcher = ClaimIssuerABIDispatcher {
        contract_address: claim_issuer_address,
    };
    start_cheat_caller_address(
        claim_issuer_address, factory_setup.accounts.claim_issuer_account.contract_address,
    );
    // register claim issuer account as claim key
    let claim_issuer_account_address_hash = poseidon_hash_span(
        array![factory_setup.accounts.claim_issuer_account.contract_address.into()].span(),
    );
    claim_issuer_dispatcher.add_key(claim_issuer_account_address_hash, 3, 1);
    // register claim issuer public key as management + claim_key
    let claim_issuer_pub_key_hash = poseidon_hash_span(
        array![factory_setup.accounts.claim_issuer_key.public_key].span(),
    );
    claim_issuer_dispatcher.add_key(claim_issuer_pub_key_hash, 1, 1);
    claim_issuer_dispatcher.add_key(claim_issuer_pub_key_hash, 3, 1);
    stop_cheat_caller_address(claim_issuer_address);

    start_cheat_caller_address(
        factory_setup.identity_factory.contract_address,
        factory_setup.accounts.owner_account.contract_address,
    );
    factory_setup
        .identity_factory
        .create_identity(factory_setup.accounts.alice_account.contract_address, 'alice');
    stop_cheat_caller_address(factory_setup.identity_factory.contract_address);

    let alice_identity = IdentityABIDispatcher {
        contract_address: factory_setup
            .identity_factory
            .get_identity(factory_setup.accounts.alice_account.contract_address),
    };
    start_cheat_caller_address(
        alice_identity.contract_address, factory_setup.accounts.alice_account.contract_address,
    );
    // register alice pub key as management key
    alice_identity
        .add_key(
            poseidon_hash_span(array![factory_setup.accounts.alice_key.public_key].span()), 1, 1,
        );
    // register carol pub key + contract address as claim key
    alice_identity
        .add_key(
            poseidon_hash_span(
                array![factory_setup.accounts.carol_account.contract_address.into()].span(),
            ),
            3,
            1,
        );
    alice_identity
        .add_key(
            poseidon_hash_span(array![factory_setup.accounts.carol_key.public_key].span()), 3, 1,
        );
    // register david pub key + contract address as action key
    alice_identity
        .add_key(
            poseidon_hash_span(
                array![factory_setup.accounts.david_account.contract_address.into()].span(),
            ),
            2,
            1,
        );
    alice_identity
        .add_key(
            poseidon_hash_span(array![factory_setup.accounts.david_key.public_key].span()), 2, 1,
        );

    let claim_topic = 666_felt252;
    let issuer = claim_issuer_address;
    let claim_data = [0x00666].span();
    let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

    let mut claim_message = ClaimMessage {
        identity: alice_identity.contract_address, topic: claim_topic, data: claim_data,
    };
    let hashed_claim = claim_message.get_message_hash(issuer);
    let (r, s) = factory_setup.accounts.claim_issuer_key.sign(hashed_claim).unwrap();

    let alice_claim_666_signature = Signature::StarkSignature(
        StarkSignature { r, s, public_key: factory_setup.accounts.claim_issuer_key.public_key },
    );
    let mut alice_claim_666_signature_serialized = Default::default();
    alice_claim_666_signature.serialize(ref alice_claim_666_signature_serialized);
    let alice_claim_666 = TestClaim {
        claim_id,
        identity: alice_identity.contract_address,
        issuer: claim_issuer_address,
        topic: claim_topic,
        scheme: 1,
        data: claim_data,
        signature: alice_claim_666_signature_serialized.span(),
        uri: "https://example.com",
    };

    alice_identity
        .add_claim(
            alice_claim_666.topic,
            alice_claim_666.scheme,
            alice_claim_666.issuer,
            alice_claim_666.signature,
            alice_claim_666.data,
            alice_claim_666.uri.clone(),
        );
    stop_cheat_caller_address(alice_identity.contract_address);

    start_cheat_caller_address(
        factory_setup.identity_factory.contract_address,
        factory_setup.accounts.owner_account.contract_address,
    );
    factory_setup
        .identity_factory
        .create_identity(factory_setup.accounts.bob_account.contract_address, 'bob');
    let bob_identity = IdentityABIDispatcher {
        contract_address: factory_setup
            .identity_factory
            .get_identity(factory_setup.accounts.bob_account.contract_address),
    };

    let token_address = 'token_address'.try_into().unwrap();
    factory_setup
        .identity_factory
        .create_token_identity(
            token_address,
            factory_setup.accounts.token_owner_account.contract_address,
            'token_owner',
        );
    stop_cheat_caller_address(factory_setup.identity_factory.contract_address);

    IdentitySetup {
        identity_factory: factory_setup.identity_factory,
        identity_contract: factory_setup.identity_contract,
        implementation_authority: factory_setup.implementation_authority,
        claim_issuer: claim_issuer_dispatcher,
        accounts: factory_setup.accounts,
        alice_identity,
        bob_identity,
        alice_claim_666,
        token_address,
    }
}

pub fn setup_verifier(
    setup: @IdentitySetup,
    claims_to_add: Span<felt252>,
    add_issuer_entries: Span<(ContractAddress, Array<felt252>)>,
) -> VerifierABIDispatcher {
    let mock_verifier_contract = declare("MockVerifier").unwrap().contract_class();
    let (mock_verifier_address, _) = mock_verifier_contract
        .deploy(@array![(*setup.accounts.owner_account.contract_address).into()])
        .unwrap();
    let mut verifier_dispatcher = VerifierABIDispatcher { contract_address: mock_verifier_address };

    start_cheat_caller_address(
        mock_verifier_address, *setup.accounts.owner_account.contract_address,
    );
    for claim in claims_to_add {
        verifier_dispatcher.add_claim_topic(*claim);
    }

    for (issuer, claim_topics) in add_issuer_entries {
        verifier_dispatcher.add_trusted_issuer(*issuer, claim_topics.span());
    }
    stop_cheat_caller_address(mock_verifier_address);

    verifier_dispatcher
}

pub fn get_test_claim(
    setup: @IdentitySetup,
    identity: ContractAddress,
    claim_topic: felt252,
    claim_data: Span<felt252>,
) -> TestClaim {
    let issuer = *setup.claim_issuer.contract_address;
    let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

    let mut claim_message = ClaimMessage { identity, topic: claim_topic, data: claim_data };
    let hashed_claim = claim_message.get_message_hash(issuer);

    let (r, s) = (*setup.accounts.claim_issuer_key).sign(hashed_claim).unwrap();
    let signature = Signature::StarkSignature(
        StarkSignature { r, s, public_key: *setup.accounts.claim_issuer_key.public_key },
    );
    let mut serialized_signature = Default::default();
    signature.serialize(ref serialized_signature);
    TestClaim {
        claim_id,
        identity,
        issuer,
        topic: claim_topic,
        scheme: 1,
        data: claim_data,
        signature: serialized_signature.span(),
        uri: "https://example.com",
    }
}
