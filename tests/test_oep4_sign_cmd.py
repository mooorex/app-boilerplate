
import pytest

from application_client.boilerplate_transaction import Transaction
from application_client.boilerplate_command_sender import BoilerplateCommandSender, Errors
from application_client.boilerplate_response_unpacker import unpack_get_public_key_response, unpack_sign_tx_response
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID
from utils import check_signature_validity
import hashlib
# In this tests we check the behavior of the device when asked to sign a oep4 transaction


# In this test we send to the device a oep4 transaction to sign and validate it on screen
# The oep4 transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_oep4_tx_short_tx(backend, scenario_navigator):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # The path used for this entire test
    path: str = "m/44'/1024'/0'/0/0"

    # First we need to get the public key of the device in order to build the oep4 transaction
    rapdu = client.get_public_key(path=path)
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    # Create the oep4 transaction that will be sent to the device for signing
    ope4_transaction = Transaction(
        rawtx = "00d2cf678c5dc409000000000000409c000000000000f65049e55b9d17bb039d02de7bb9a630a3196cfb5677f1ffe3ada5dd7862f9601f5a0a058a6bd8274341087472616e73666572f65049e55b9d17bb039d02de7bb9a630a3196cfb165d30185b2940ace08ee685c5e6bc1af11dd860a386973d718d0300000000000000000000"
        #rawtx = "00d2d64f9355c409000000000000409c0000000000001451108489337c8055a9c1ed9158c947d22070d7561c6c98c223f4285df248d2cf81fb54b7fbc314c841087472616e736665721451108489337c8055a9c1ed9158c947d22070d7ec9441bf328b6cd6607b3847c30b7eaed756dabe40420f000000000000000000000000000000"
    ).serialize()

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_tx(path=path, transaction=ope4_transaction):
        # Validate the on-screen request by performing the navigation appropriate for this device
        scenario_navigator.review_approve()

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data
    _, der_sig, _ = unpack_sign_tx_response(response)
    first_hash = hashlib.sha256(ope4_transaction).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    assert check_signature_validity(public_key, der_sig, second_hash)


# Oep4 Transaction signature refused test
# The test will ask for a oep4 transaction signature that will be refused on screen
def test_sign_oep4_tx_refused(backend, scenario_navigator):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    path: str = "m/44'/1024'/0'/0/0"

    rapdu = client.get_public_key(path=path)
    _, pub_key, _, _ = unpack_get_public_key_response(rapdu.data)

    oep4_transaction = Transaction(
        rawtx = "00d24adab893c409000000000000409c000000000000ae6393b337e4a8d856ec00d75af134fdcd6bfe295677f1ffe3ada5dd7862f9601f5a0a058a6bd8274341087472616e73666572ae6393b337e4a8d856ec00d75af134fdcd6bfe298eee645323897c3344cfc1d1bd0110407e457d923042470000000000000000000000000000"
        #rawtx = "00d2d64f9355c409000000000000409c0000000000001451108489337c8055a9c1ed9158c947d22070d7561c6c98c223f4285df248d2cf81fb54b7fbc314c841087472616e736665721451108489337c8055a9c1ed9158c947d22070d7ec9441bf328b6cd6607b3847c30b7eaed756dabe40420f000000000000000000000000000000"
    ).serialize()

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(path=path, transaction=oep4_transaction):
            scenario_navigator.review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0
    