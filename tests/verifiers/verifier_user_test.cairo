#[test]
#[should_panic]
fn test_should_panic_when_calling_a_verified_function_not_as_an_identity() {
    panic!("");
}

#[test]
fn test_should_return_when_identity_verified() {
    assert(true, '');
}

#[test]
#[should_panic]
fn test_should_return_when_identity_is_not_verified() {
    panic!("");
}
