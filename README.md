
# Luna Key Management Utility (KMU)

This project provides a tool to generate and manage cryptographic keys using [Luna General Purpose HSMs](https://cpl.thalesgroup.com/encryption/hardware-security-modules/general-purpose-hsms), and more specifically [Luna Network HSMs](https://cpl.thalesgroup.com/encryption/hardware-security-modules/network-hsms). 

## Introduction
KMU is based on the [PKCS#11 specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html), with some [Luna specific extensions](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/pkcs11/pkcs11_standard.htm).

It has been tested with both Luna Network HSMs and the [Luna Cloud HSM service](https://cpl.thalesgroup.com/encryption/data-protection-on-demand/services/luna-cloud-hsm).

The purpose of KMU is to offer handful key management functions to import/export/derive cryptographic keys using transport keys (or "wrap keys", which can be private or secret keys) to address typical IOT and automotive use cases.

KMU allows to:
- Create data objects.
- List objects in partitions.
- Display and modify object attributes.
- Create keys (including DES, AES, RSA, DSA, DH, ECDSA, EdDSA, Montgomery, ML-DSA, ML-KEM, SM2, SM4, HMAC or generic ones).
- Create AES or DES keys as multiple clear key compoments and KCV (XOR method)
- Export and wrap private/secret keys (currently limited to RSA OAEP, AES variant wrap algorithms) in a file.
- Export private keys protected with password based encryption (PBKDF2) in a PEM-PKCS#8 file. 
- Export public keys in a PEM-PKCS#8 file.
- Export public keys in a binary file or a text file encoded in ASN1 DER.
- Import wrapped private/secret keys from a file (currently limited to RSA OAEP, AES variant wrap algorithms).
- Import wrapped AES keys from a file encoded in TR31 format(partial support with AES key only as ZMK).
- Import private keys protected with password based encryption (PBKDF2) from a PEM-PKCS#8 file.
- Import public keys from a PEM-PKCS#8 file.
- Import public keys from a binary file and a text file encoded in ASN1 DER.
- Import DES or AES keys as multiple clear key compoments and KCV (XOR method)
- Encrypt/decrypt from/to a file (currently limited to RSA OAEP and AES encryption algorithms).
- Derive key (currently limited to SHAxxx derivation mechanisms and proprietary Thales Luna key derivation functions such as CKM_NIST_PRF_KDF).
- Generate a digest for symetric keys.
- Convert a file format to other file formats.
- Compute KCV on a symetric key (currently limited to 4 KCV methods: PCI DSS, PKCS#11, Global Platform and HMAC-SHA256).
- Perform a remote MZMK setup with Thales TMD 
- Get the HSM capabilities (limited rigth now to key generation mecanism)

These operations require to create partitions, register clients, initialize user roles... These tasks can be performed using:
- The [Luna Universal Client](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/Utilities/Preface.htm), and esp.
  - The [Luna Shell (Lush)](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/lunash/Preface.htm)
  - The [Luna client management tool (LunaCM)](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/lunacm/Preface.htm)
- The [Luna REST API](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/REST_API/REST_API_References.htm)

KMU supports the Luna HSM "Crypto User" role, with both password and PED authentication (if the CKF_PROTECTED_AUTHENTICATION_PATH "TokenInfo" flag is set to 1).

KMU is available as a console and might be scriptable from a command line. The console supports auto completion for command and parameters.

## Requirements
- Base OS:
  - Windows-10 or later.
  - Windows Server 2019 or later.
- Redistribuable package:
  - 2015 -2022 (refer to https://learn.microsoft.com/fr-fr/cpp/windows/latest-supported-vc-redist?view=msvc-170#visual-studio-2015-2017-2019-and-2022).
- Thales Luna Universal Client:
  - 10.5.x or later.
    - Note. Client 10.9.1 or later is recommanded to use PQC features. 
- Environment variable “ChrystokiConfigurationPath” must refer to the folder that contains the Luna Universal Client PKCS#11 library ('cryptoki.dll').
  - This environment variable is set when you install luna client.
  - KMU searches for a "cryptoki.dll" in the path pointed at by this environment variable.
  - If this environment variable is already pointing at a PKCS#11 DLL, KMU will use this library.

## Build
- Requirements:
  - Base OS:
    - Windows 10 or later.
    - Windows Server 2019 or later.
  - Development environment:
    - Visual Studio 2015 or later with a C/C++ build chain.
    - Thales Luna Universal Client:
      - 10.9.1 or later.
    - Environment variable “ChrystokiConfigurationPath” must refer to the folder that contains the Luna Universal Client PKCS#11 library ('cryptoki.dll').
- Using Visual Studio:
  - Open the "kmu.sln" solution file.
  - Select the "release" configuration and build the solution.
    - Note. An error may happen during compilation in cryptoki_v2.h. If happens replace #include "RSA/pkcs11.h" by #include "pkcs11.h".
- Once built, "kmu.exe" can be used immediately.

Note:
- A precompiled version is provided for Windows x64 platforms in the "x64/release" directory. 

## Run
Refer to the usage documentation provided by the tool (running it without any parameter or using help command).

```
help                            Display this help
listslot                        This command lists all PKCS#11 slot
login                           Login to selected slot
logout                          Logout the current slot
list                            This command lists all the keys in the selected slot
getcapabilities                 This command returns the PKCS11 capabilities (limited to key generation)
generatekey                     This command generates a symmetric or asymmetric key
createdo                        This command creates a data object
getattribute                    This command displays object attributes
setattribute                    This command set attributes to an object
readattribute                   This command read an attribute of a object and write in a file
writeattribute                  This command write an attribute of a object read from a file
export                          This command exports a key to a file
import                          This command imports a key from a file or from key components
encrypt                         This command encrypts a file
decrypt                         This command decrypts a file
derive                          This command derives a key
convert                         This command converts a file to a different format
delete                          This command deletes an object
digestkey                       This command return a message digest of secret key
computekcv                      This command calculate the KCV of a symetric key
remotemzmk                      This command generate and store a payshield TMD remote MZMK
exit                            Exit console
```

All command parameters are optional. 

To display help for a specific command, use: 

```
"command" help
```

Two argument formats are supported for each command:
- Command -arg1 value1 -arg2 -value2
- Command -arg=value1 -arg2=value2

Typical examples:
| Command | -argument=value or -argument value |
| ------- | ---------------------------------- | 
| List all objects in a PKCS#11 | slot list -slot=0 -password=00000000 |
| List all objects in a PKCS#11 as crypto user | slot list -slot=0 -password=00000000 - cu=true|
| Generate a AES key | generatekey -slot=0 -password=00000000 -keytype=aes -keysize 32 -label=key-aes-256 -extractable=1 -modifiable=true -wrap=0 -encrypt false -token=true -private=true -sensitive=true |
| Generate a RSA key | generatekey -slot=0 -password=00000000 -keytype=rsa -keysize 4096 -labelpublic=key-rsa-public -labelprivate=key-rsa-private -publicexponent=65537 -extractable=1 -modifiable=true -mech=prime |
| Generate a ECDSA key | generatekey -slot=0 -password=00000000 -keytype=ecdsa -labelpublic=key-ecdsa-public -labelprivate=key-ecdsa-private -curve=secp256r1  |
| Generate a EDDSA key | generatekey -slot=0 -password=00000000 -keytype=eddsa -labelpublic=key-eddsa-public -labelprivate=key-eddsa-private -curve=ed25519 |
| Generate a SM2 key | generatekey -slot=0 -password=00000000 -keytype=sm2 -labelpublic=key-sm2-public -labelprivate=key-sm2-private -curve=sm2 |
| Export a private RSA key with a symetric AES wrap key (1) | export -slot=0 -password=00000000 -handle=377 -outputfile=private_rsa.bin -format=bin -key=426 -algo=aes_cbc_pad |
| Export a private RSA key with a symetric AES wrap key (2) | export -slot=0 -password=00000000 -handle=377 -outputfile=private_rsa.txt -format=text -key=426 -algo=aes_cbc_pad |
| Export a AES key with a asymetric public RSA wrap key | export -slot=0 -password=00000000 -handle=535 -outputfile=secret_aes.bin -format=bin -key=602 -algo=rsa_oaep_sha256 |
| Export a public key | export -slot=0 -password=00000000 -handle=717 -outputfile=public_ecdsa_sect571k1.pem -format=PKCS8 |
| Import a private RSA key with a symetric AES wrap key | import -slot=0 -password=00000000 -keyclass=private -keytype=rsa -inputfile=private_rsa.bin -format=bin -key=426 -algo=aes_cbc_pad -label=importrsakey -modifiable=false -extractable=false |
| Import a AES key with a asymetric private RSA wrap key | import -slot=0 -password=00000000 -keyclass=secret -keytype=aes -inputfile=secret_aes.bin -format=bin -key=603 -algo=rsa_oaep_sha256 -label=importaeskey -modifiable=true -extractable=true |
| Import a public key | import -slot=0 -password=00000000 -keyclass=public -keytype=ecdsa -inputfile=public_ecdsa_sect571k1.pem -format=PKCS8 -label=imported-ecdsa-sect571k1 -modifiable=true -extractable=true |
| Derive a key from a master key using SHA derivation | derive -slot=0 -password=00000000 -key=751 -keytype=aes -keysize=32 -mech=sha256 -label=derived-key-sha256 -extractable=true |
| Derive a key from a master key using luna KDF method with SCP03 | derive -slot=0 -password=00000000 -key=426 -keytype=aes -keysize=32 -mech=luna-nist-kdf  |-label=derived-key-kdf-scp03 -extractable=true -kdf-type=aes-cmac -kdf-scheme=scp03 -kdf-counter=9 -kdf-label=0102 -kdf-context=FFFF |
| Generate a AES key with 3 compoments and follow prompt| generatekey -slot=0 -password=00000000 -keytype=aes -keysize=32 -clearcomponents=3 -label=zmk-key-aes-256 |
| Import a AES key with 3 compoments and follow prompt | import -slot=0 -password=00000000 -keytype=aes -keysize=32 -clearcomponents=3 -label=zmk-key-aes-256 |

## Test

The folder test contains some templates of keys that can be imported into a HSM (using a preconfigued HSM slot) and a file "list-command.txt" that contains a list of test command.

The best approach is to generate/derive different kinds of keys (AES, RSA, ECDSA...) on the HSM using the "generatekey" command.

Then keys can be exported and imported to/from different parties. 

Once a key has been generated, its PKCS#11 attributes can be shown using the "getattribute" command. 

The PKCS#11 attributes may be updated using the "setattribute" command.

## Contributing

If you are interested in contributing to this project, please read the [Contributing guide](CONTRIBUTING.md).

## License

This software is provided under a [permissive license](LICENSE).
