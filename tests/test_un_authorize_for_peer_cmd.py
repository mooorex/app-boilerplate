
import pytest

from application_client.boilerplate_transaction import Transaction
from application_client.boilerplate_command_sender import BoilerplateCommandSender, Errors
from application_client.boilerplate_response_unpacker import unpack_get_public_key_response, unpack_sign_tx_response
from ragger.error import ExceptionRAPDU
from utils import check_signature_validity
import hashlib

# In this tests we check the behavior of the device when asked to sign a transaction
import logging

# Configure logger
logger = logging.getLogger("test_logger")
logger.setLevel(logging.DEBUG)


# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_un_authorize_for_peer_tx_short_tx(backend, scenario_navigator):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # The path used for this entire test
    path: str = "m/44'/1024'/0'/0/0"

    # First we need to get the public key of the device in order to build the transaction
    rapdu = client.get_public_key(path=path)
    logger.debug("rapu.data.hex:%s", rapdu.data.hex())

    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)
    logger.debug("pubkey:%s", public_key.hex())

    # Create the transaction that will be sent to the device for signing
    transaction = Transaction(
        rawtx="00d19171c702c409000000000000204e000000000000825995774fc9f599e6f5270176b37495d8579826b700c66b14825995774fc9f599e6f5270176b37495d85798266a7cc8516a7cc8423032626463346334616630373065636364356230633037326265326635303336626662663065356537636561323339383064636562373837643138303161346531316a7cc8516a7cc808f4010000000000006a7cc86c12756e417574686f72697a65466f72506565721400000000000000000000000000000000000000070068164f6e746f6c6f67792e4e61746976652e496e766f6b6500"
    ).serialize()

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    logger.debug("tx:%s", transaction.hex())
    with client.sign_tx(path=path, transaction=transaction):
        # Validate the on-screen request by performing the navigation appropriate for this device
        scenario_navigator.review_approve()

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data
    _, der_sig, _ = unpack_sign_tx_response(response)
    first_hash = hashlib.sha256(transaction).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    logger.debug("pubkey:%s,der_sig:%s,transaction:%s,first_hash:%s", public_key.hex(), der_sig.hex(),
                 transaction.hex(), first_hash.hex())
    assert check_signature_validity(public_key, der_sig, second_hash)


# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen

def test_sign_un_authorize_for_peer_tx_refused(backend, scenario_navigator):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    path: str = "m/44'/1024'/0'/0/0"

    rapdu = client.get_public_key(path=path)
    _, pub_key, _, _ = unpack_get_public_key_response(rapdu.data)

    transaction = Transaction(
        rawtx="00d19171c702c409000000000000204e000000000000825995774fc9f599e6f5270176b37495d8579826b700c66b14825995774fc9f599e6f5270176b37495d85798266a7cc8516a7cc8423032626463346334616630373065636364356230633037326265326635303336626662663065356537636561323339383064636562373837643138303161346531316a7cc8516a7cc808f4010000000000006a7cc86c12756e417574686f72697a65466f72506565721400000000000000000000000000000000000000070068164f6e746f6c6f67792e4e61746976652e496e766f6b6500"
    ).serialize()

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(path=path, transaction=transaction):
            scenario_navigator.review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0
