# Ontology Application APDU Interface

## About

This document outlines the APDU messages interface for interacting with the Ontology application. The application supports communication over HID or BLE interfaces

### Supported Functionalities

The Ontology application provides the following features:

- Get Public Address: Retrieve an Ontology public address given a BIP-32 derivation path.
- Sign Transaction: Sign an Ontology transaction using a BIP-32 derivation path and a raw transaction.
- Get App Version: Retrieve the version of the Ontology application.
- Get App Name: Retrieve the name of the Ontology application.

The application interface can be accessed over HID or BLE

## APDUs

### Get Ont Public Address

#### Description

This command retrieves the public key corresponding to a specified BIP-32 derivation path. Optionally, the associated address can be displayed on the device for user verification before being returned.

#### Coding

##### `Command`

| CLA | INS   | P1                                                 | P2    | Lc       | Le       |
| --- | ---   | ---                                                | ---   | ---      | ---      |
| 80  |  05   |  00 : return address                               | 00    | variable | variable |
|     |       |  01 : display address and confirm before returning |       |          |          |

##### `Input data`

| Description                                                      | Length |
| ---                                                              | ---    |
| Number of BIP 32 derivations to perform (max 10)                 | 1      |
| First derivation index (big endian)                              | 4      |
| ...                                                              | 4      |
| Last derivation index (big endian)                               | 4      |

##### `Output data`

| Description                                                      | Length |
| ---                                                              | ---    |
| Public Key length                                                | 1      |
| Public Key                                                       | var    |
| Chain code length                                                | 1      |
| Chain code                                                       | var    |

### Sign Ontology Transaction

#### Description

This command signs an Ontology (ONT), ONG, or OEP-4 transaction after user validation of the transaction parameters on the device. The input is an RLP-encoded transaction, streamed to the device in chunks of up to 255 bytes.

#### Coding

##### `Command`

| CLA | INS  | P1                   | P2                               | Lc       | Le       |
| --- | ---  | ---                  | ---                              | ---      | ---      |
| 80  | 02   |  00-FF : chunk index | 00 : last transaction data block | variable | variable |
|     |      |                      | 80 : subsequent transaction data block |    |          |

##### `Input data (first transaction data block)`

| Description                                          | Length   |
| ---                                                  | ---      |
| Number of BIP 32 derivations to perform (max 10)     | 1        |
| First derivation index (little endian)               | 4        |
| ...                                                  | 4        |
| Last derivation index (little endian)                | 4        |
  
##### `Input data (other transaction data block)`

| Description                                          | Length   |
| ---                                                  | ---      |
| Transaction chunk                                    | variable |

##### `Output data`

| Description                                          | Length   |
| ---                                                  | ---      |
| Signature length                                     | 1        |
| Signature                                            | variable |
| v                                                    | 1        |

### Sign Personal Message

#### Description

This command signs a personal message using a specified BIP-32 derivation path after user validation of the message on the device. The input is the message data, streamed to the device in chunks of up to 255 bytes.

#### Coding

##### `Command`

| CLA | INS  | P1                   | P2                               | Lc       | Le       |
| --- | ---  | ---                  | ---                              | ---      | ---      |
| 80  | 07   |  00-FF : chunk index | 00 : last personal msg data block  | variable | variable |
|     |      |                      | 80 : subsequent personal msg data block |    |          |

##### `Input data (first personal message data block)`

| Description                                          | Length   |
| ---                                                  | ---      |
| Number of BIP 32 derivations to perform (max 10)     | 1        |
| First derivation index (little endian)               | 4        |
| ...                                                  | 4        |
| Last derivation index (little endian)                | 4        |

##### `Input data (other personal msg data block)`

| Description                                          | Length   |
| ---                                                  | ---      |
| message chunk                                        | variable |

##### `Output data`

| Description                                          | Length   |
| ---                                                  | ---      |
| Signature length                                     | 1        |
| Signature                                            | variable |
| v                                                    | 1        |

### Sign OEP-4 Transaction

#### Description

This command signs an OEP-4 transaction using a specified BIP-32 derivation path after user validation of the transaction parameters on the device. The input is an RLP-encoded transaction, streamed to the device in chunks of up to 255 bytes.

#### Coding

##### `Command`

| CLA | INS  | P1                   | P2                                    | Lc       | Le       |
| --- | ---  | ---                  | ---                                   | ---      | ---      |
| 80  | 08   |  00-FF : chunk index | 00 : last OEP-4 transaction data block | variable | variable |
|     |      |                      | 80 : subsequent OEP-4 transaction data block |    |          |

##### `Input data (first OEP-4 transaction data block)`

| Description                                          | Length   |
| ---                                                  | ---      |
| Number of BIP 32 derivations to perform (max 10)     | 1        |
| First derivation index (little endian)               | 4        |
| ...                                                  | 4        |
| Last derivation index (little endian)                | 4        |

##### `Input data (other transaction data block)`

| Description                                          | Length   |
| ---                                                  | ---      |
| Transaction chunk                                    | variable |

##### `Output data`

| Description                                          | Length   |
| ---                                                  | ---      |
| Signature length                                     | 1        |
| Signature                                            | variable |
| v                                                    | 1        |

### Get Application Version

#### Description

This command retrieves the version of the Ontology application installed on the device.

#### Coding

##### `Command`

| CLA | INS | P1  | P2  | Lc   | Le |
| --- | --- | --- | --- | ---  | ---|
| 80  | 03  | 00  | 00  | 00   | 04 |

##### `Input data`

None

##### `Output data`

| Description                       | Length |
| ---                               | ---    |
| Application major version         | 01 |
| Application minor version         | 01 |
| Application patch version         | 01 |

### Get Application Name

#### Description

This command retrieves the name of the Ontology application installed on the device.

#### Coding

##### `Command`

| CLA | INS | P1  | P2  | Lc   | Le |
| --- | --- | --- | --- | ---  | ---|
| 80  | 04  | 00  | 00  | 00   | 04 |

##### `Input data`

None

##### `Output data`

| Description           | Length   |
| ---                   | ---      |
| Application name      | variable |

## Status Words

The following standard Status Words are returned for all APDUs.

##### `Status Words`

| SW       | SW name                     | Description                                           |
| ---      | ---                         | ---                                                   |
|   6985   | SW_DENY                  | Rejected by user                                      |
|   6A86   | SW_WRONG_P1P2               | Either P1 or P2 is incorrect                          |
|   6A87   | SW_WRONG_DATA_LENGTH        | Lc or minimum APDU length is incorrect                |
|   6D00   | SW_INS_NOT_SUPPORTED      | No command exists with INS                            |
|   6E00   | SW_CLA_NOT_SUPPORTED        | Bad CLA used for this application                     |
|   B000   | SW_WRONG_RESPONSE_LENGTH    | Wrong response length (buffer size problem)           |
|   B001   | SW_DISPLAY_BIP32_PATH_FAIL  | BIP32 path conversion to string failed                |
|   B002   | SW_DISPLAY_ADDRESS_FAIL     | Address conversion to string failed                   |
|   B003   | SW_DISPLAY_AMOUNT_FAIL      | Amount conversion to string failed                    |
|   B004   | SW_WRONG_TX_LENGTH          | Wrong raw transaction length                          |
|   B005   | SW_TX_PARSING_FAIL          | Failed to parse raw transaction                       |
|   B006   | SW_TX_HASH_FAIL          | Failed to compute hash digest of raw transaction      |
|   B007   | SW_BAD_STATE                | Security issue with bad state                         |
|   B008   | SW_SIGNATURE_FAIL           | Signature of data(tx or personal msg) failed            |
|   B009   | SW_PERSONAL_MSG_PARSING_FAIL  | Failed to parse personal msg                            |
|   B00A   | SW_PERSONAL_MSG_HASH_FAIL     | Failed to compute hash digest of personal msg           |
|   B00B   | SW_INVALID_TRANSACTION  | Invalid transaction                              |
