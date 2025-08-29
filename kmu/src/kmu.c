/****************************************************************************\
*
* This file is part of the "Luna KMU" tool.
*
* The "KMU" tool is provided under the MIT license (see the
* following Web site for further details: https://mit-license.org/ ).
*
* Author: Sebastien Chapellier
*
* Copyright © 2023-2024 Thales Group
*
\****************************************************************************/

#define _KMU_C

#ifdef OS_WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p11.h"
#include "kmu.h"
#include "parser.h"
#include "cmdarg.h"
#include "cmd.h"
#include "console.h"
#include "file.h"
#include "str.h"


/** commands **/
const STRING_ARRAY CMD_HELP = "help";
const STRING_ARRAY CMD_HELP_HELP = "Display this help";

const STRING_ARRAY CMD_LOGIN = "login";
const STRING_ARRAY CMD_LOGIN_HELP = "Login to selected slot";

const STRING_ARRAY CMD_LOGOUT = "logout";
const STRING_ARRAY CMD_LOGOUT_HELP = "Logout the current slot";

const STRING_ARRAY CMD_EXIT = "exit";
const STRING_ARRAY CMD_EXIT_HELP = "Exit console";

const STRING_ARRAY CMD_LIST = "list";
const STRING_ARRAY CMD_LIST_HELP = "This command lists all the keys in the selected slot";

const STRING_ARRAY CMD_LIST_SLOT = "listslot";
const STRING_ARRAY CMD_LIST_SLOT_HELP = "This command lists all PKCS11 slot";

const STRING_ARRAY CMD_GENERATE_KEY = "generatekey";
const STRING_ARRAY CMD_GENERATE_KEY_HELP = "This command generates a symmetric or asymmetric key";

const STRING_ARRAY CMD_CREATE_DO = "createdo";
const STRING_ARRAY CMD_CREATE_DO_HELP = "This command creates a data object";

const STRING_ARRAY CMD_GET_ATTRIBUTE = "getattribute";
const STRING_ARRAY CMD_GET_ATTRIBUTE_HELP = "This command displays object attributes";

const STRING_ARRAY CMD_SET_ATTRIBUTE = "setattribute";
const STRING_ARRAY CMD_SET_ATTRIBUTE_HELP = "This command set attributes to an object";

const STRING_ARRAY CMD_WRITE_ATTRIBUTE = "writeattribute";
const STRING_ARRAY CMD_WRITE_ATTRIBUTE_HELP = "This command write an attribute of a object read from a file";

const STRING_ARRAY CMD_READ_ATTRIBUTE = "readattribute";
const STRING_ARRAY CMD_READ_ATTRIBUTE_HELP = "This command read an attribute of a object and write in a file";

const STRING_ARRAY CMD_EXPORT = "export";
const STRING_ARRAY CMD_EXPORT_HELP = "This command exports a key to a file";

const STRING_ARRAY CMD_IMPORT = "import";
const STRING_ARRAY CMD_IMPORT_HELP = "This command imports a key from a file or from key components";

const STRING_ARRAY CMD_ENCRYPT = "encrypt";
const STRING_ARRAY CMD_ENCRYPT_HELP = "This command encrypts a file";

const STRING_ARRAY CMD_DECRYPT = "decrypt";
const STRING_ARRAY CMD_DECRYPT_HELP = "This command decrypts a file";

const STRING_ARRAY CMD_DERIVE = "derive";
const STRING_ARRAY CMD_DERIVE_HELP = "This command derives a key";

const STRING_ARRAY CMD_CONVERT = "convert";
const STRING_ARRAY CMD_CONVERT_HELP = "This command converts a file to a different format";

const STRING_ARRAY CMD_DELETE = "delete";
const STRING_ARRAY CMD_DELETE_HELP = "This command deletes an object";

const STRING_ARRAY CMD_DIGEST_KEY = "digestkey";
const STRING_ARRAY CMD_DIGEST_KEY_HELP = "This command return a message digest of secret key";

const STRING_ARRAY CMD_COMPUTE_KCV = "computekcv";
const STRING_ARRAY CMD_COMPUTE_KCV_HELP = "This command calculate the KCV of a symetric key";


/** parameters **/
const STRING_ARRAY ARG_SLOT_ID = "-slot";
const STRING_ARRAY ARG_SLOT_ID_HELP = "pkcs11 slot ID \n\t\t\t\t\t-For example 0, 1 \n\t\t\t\t\t-Use argument slot list to get available slot";

const STRING_ARRAY ARG_PASSWORD = "-password";
const STRING_ARRAY ARG_PASSWORD_HELP = "pkcs11 slot password \n\t\t\t\t\t-If the TokenInfo flag CKF_PROTECTED_AUTHENTICATION_PATH is set, the password will not be prompted if absent\n\t\t\t\t\t-If password is given, authentication with password is forced ";

const STRING_ARRAY ARG_CU = "-cu";
const STRING_ARRAY ARG_CU_HELP = "Specifies that you wish to perform the command as the partition's Crypto User. \n\t\t\t\t\t-Supported value: true, 1 \n\t\t\t\t\t-Optional Default value is absent. Crypto Officer role is used by default";

const STRING_ARRAY ARG_LABEL = "-label";
const STRING_ARRAY ARG_LABEL_HELP = "Key label value";
const STRING_ARRAY ARG_LABEL_GENERATEKEY_HELP = "Key label value\n\t\t\t\t\t-Mandatory for symmetric keys\n\t\t\t\t\t-Optionnal for asymmetric keys";
const STRING_ARRAY ARG_LABEL_DERIVEKEY_HELP = "derived Key label value";

const STRING_ARRAY ARG_HANDLE = "-handle";
const STRING_ARRAY ARG_HANDLE_HELP = "Object handle value";

const STRING_ARRAY ARG_KEY = "-key";
const STRING_ARRAY ARG_KEY_HELP = "Object handle value of encryption or decryption key";

const STRING_ARRAY ARG_DERIVE_KEY = "-key";
const STRING_ARRAY ARG_DERIVE_KEY_HELP = "Object handle value of master derivation key";

const STRING_ARRAY ARG_WRAPKEY = "-key";
const STRING_ARRAY ARG_WRAPKEY_HELP = "Object handle value for wrap key";

const STRING_ARRAY ARG_UNWRAPKEY = "-key";
const STRING_ARRAY ARG_UNWRAPKEY_HELP = "Object handle value for unwrap key";

const STRING_ARRAY ARG_LABEL_PRIVATE = "-labelprivate";
const STRING_ARRAY ARG_LABEL_PRIVATE_HELP = "Key label value for private key object\n\t\t\t\t\t-Optionnal, if absent the label is taken in -label";

const STRING_ARRAY ARG_LABEL_PUBLIC = "-labelpublic";
const STRING_ARRAY ARG_LABEL_PUBLIC_HELP = "Key label value for public key object\n\t\t\t\t\t-Optionnal, if absent the label is taken in -label";

const STRING_ARRAY ARG_KEYTYPE = "-keytype";
const STRING_ARRAY ARG_KEYTYPE_HELP = "Key type value\n\t\t\t\t\t-Supported value: des, aes, rsa, dsa, dh, ecdsa, eddsa, montgomery sm2, sm4";
const STRING_ARRAY ARG_DERIVEKEY_TYPE_HELP = "dervive Key type value\n\t\t\t\t\t-Supported value for SHAx-xxx key derivation: des, aes, generic, hmac";
const STRING_ARRAY ARG_IMPORTKEYTYPE_HELP = "Key type value\n\t\t\t\t\t-Supported value: des, des2, des3, aes, rsa, dsa, dh, dh-x9.42, ecdsa, eddsa, montgomery sm2, sm4";

const STRING_ARRAY ARG_KEYSIZE = "-keysize";
const STRING_ARRAY ARG_KEYSIZE_HELP = "key size\n\t\t\t\t\t-Value in byte for DES(8, 16 or 24 bytes), \n\t\t\t\t\t-Value in byte for AES(16, 24 or 32 bytes)\n\t\t\t\t\t-Value in byte for HMAC(1 to 512 bytes) keys\n\t\t\t\t\t-Modulus size in bits for RSA keys\n\t\t\t\t\t-Not required for other key types";
const STRING_ARRAY ARG_DERIVEKEY_SIZE_HELP = "derived key size\n\t\t\t\t\t-Value in byte for DES key(8, 16 or 24 bytes), \n\t\t\t\t\t-Value in byte for AES key(16, 24 or 32 bytes)\n\t\t\t\t\t-Value in byte for HMAC or generic key(1 to 512 bytes)";
const STRING_ARRAY ARG_IMPORTKEY_SIZE_HELP = "Optional. Key size when importing key in compoments\n\t\t\t\t\t-Value in byte for AES key(16, 24 or 32 bytes)\n\t\t\t\t\t-no required when importing wrapped key or other type of keys";

const STRING_ARRAY ARG_KEYCLASS = "-keyclass";
const STRING_ARRAY ARG_KEYCLASS_HELP = "Key class\n\t\t\t\t\t-Supported value: private, public or secret";

const STRING_ARRAY ARG_PUBLIC_EXP = "-publicexponent";
const STRING_ARRAY ARG_PUBLIC_EXP_HELP = "Public exponent value to be used for generation of RSA key pairs\n\t\t\t\t\t-Supported value: 3, 17, 10001, 65537 ";

const STRING_ARRAY ARG_ALGO = "-algo";
const STRING_ARRAY ARG_ALGO_HELP = "Encryption algorithm. Supported algorithm: \n\t\t\t\t\t-aes_cbc_pad (PKCS padding), aes_cbc, aes_ecb, aes_gcm, aes_kw, aes_kwp, aes_cbc_pad_ipsec, aes_cfb8, aes_cfb128, aes_ofb \n\t\t\t\t\t-rsa_oaep_sha256, rsa_oaep_sha384, rsa_oaep_sha512, rsa_oaep \n\t\t\t\t\t-pbfkd2_aes128_cbc, pbfkd2_aes192_cbc, pbfkd2_aes256_cbc (password base encryption requires pkcs8 format)";

const STRING_ARRAY ARG_IV = "-iv";
const STRING_ARRAY ARG_IV_HELP = "Symmetric encryption algorithm IV as hexadecimal string\n\t\t\t\t\t-Optional. A default IV is used if absent\n\t\t\t\t\t-AES CBC, CFB, OFB : 16 bytes, default IV: '31323334353637383132333435363738'\n\t\t\t\t\t-AES GCM : 12 bytes or more, default IV: '00310000000000000000000000000000'\n\t\t\t\t\t-PBKDF2 with AES CBC : 16 bytes, default IV is random";

const STRING_ARRAY ARG_ADDITONAL_AUTH_DATA = "-aad";
const STRING_ARRAY ARG_ADDITONAL_AUTH_DATA_HELP = "Additional Authentication Data as hexadecimal string\n\t\t\t\t\t-Optional. Empty as default\n\t\t\t\t\t-AES GCM : minimum 1 byte";

const STRING_ARRAY ARG_AUTH_TAG_LEN = "-atl";
const STRING_ARRAY ARG_AUTH_TAG_LEN_HELP = "Authentication Tag length in bits\n\t\t\t\t\t-Optional. 96 bits as default\n\t\t\t\t\t-AES GCM : 32, 64, 96, 104, 112, 120 or 128 bits";

const STRING_ARRAY ARG_HASH = "-hash";
const STRING_ARRAY ARG_OEAP_HASH_HELP = "hash value\n\t\t\t\t\t-Mandatory if rsa encryption algorythm rsa_oaep is set\n\t\t\t\t\t-RSA OAEP: sha256, sha384, sha512";
const STRING_ARRAY ARG_HASH_HELP = "hash value\n\t\t\t\t\tsha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512";

const STRING_ARRAY ARG_KEYGEN_MECH = "-mech";
const STRING_ARRAY ARG_KEY_GEN_MECH_HELP = "key generation mechanism to be used\n\t\t\t\t\t-Supported value: pkcs, prime, aux if RSA key generation\n\t\t\t\t\t-Supported value: pkcs, x942 if DH key generation";

const STRING_ARRAY ARG_DERIVE_MECH = "-mech";
const STRING_ARRAY ARG_DERIVE_MECH_HELP = "key derivation mechanism to be used\n\t\t\t\t\t-Supported value: sha1, sha224, sha256, sha384, sha512 key derivation\n\t\t\t\t\t-Supported value: sha3-224, sha3-256, sha3-384, sha3-512 key derivation\n\t\t\t\t\t-Supported value: luna-kdf or luna-nist-kdf";

const STRING_ARRAY ARG_ECCCURVE = "-curve";
const STRING_ARRAY ARG_ECCCURVE_HELP = "Curve for ECC based keys\n\t\t\t\t\t-Mandatory if ecc key generation\n\t\t\t\t\t-Example of value: secp256r1, brainpoolp266r1, ed25519, sm2 ... ";

const STRING_ARRAY ARG_DH_BASE = "-base";
const STRING_ARRAY ARG_DH_BASE_HELP = "DH or DSA domain base g value\n\t\t\t\t\t-Mandatory if dh or dsa key generation\n\t\t\t\t\t-Must be a hexadecimal string";

const STRING_ARRAY ARG_DH_PRIME = "-prime";
const STRING_ARRAY ARG_DH_PRIME_HELP = "DH or DSA domain prime p value\n\t\t\t\t\t-Mandatory if dh or dsa key generation\n\t\t\t\t\t-Must be a hexadecimal string of the size of the key in bytes";

const STRING_ARRAY ARG_DH_SUBPRIME = "-subprime";
const STRING_ARRAY ARG_DH_SUBPRIME_HELP = "DH or DSA domain sub-prime q value\n\t\t\t\t\t-Mandatory if dh key generation with x9.42 mecanism\n\t\t\t\t\t-Mandatory if dsa key generation\n\t\t\t\t\t-Must be a hexadecimal string";

const STRING_ARRAY ARG_OUTPUT_FILE = "-outputfile";
const STRING_ARRAY ARG_INPUT_FILE = "-inputfile";
const STRING_ARRAY ARG_FILE_HELP = "Input file path\n\t\t\t\t\t-It can be relative in current path (file.txt) or full path (c:\\file.txt)";

const STRING_ARRAY ARG_FORMAT = "-format";
const STRING_ARRAY ARG_INFORMAT = "-inform";
const STRING_ARRAY ARG_OUTFORMAT = "-outform";
const STRING_ARRAY ARG_FORMAT_HELP = "File format \n\t\t\t\t\t-Supported value for secret key: bin, txt or text\n\t\t\t\t\t-Supported value for public key: bin, text, txt or pkcs8, \n\t\t\t\t\t-Supported value for private key: bin, txt, text or pkcs8(requires pkfkd2 encryption)";
const STRING_ARRAY ARG_FORMAT_ENCRYPT_HELP = "File format as binary or hexadecimal text \n\t\t\t\t\t-Supported value: bin, text, txt";

const STRING_ARRAY ARG_ATTR_NAME = "-attribute";
const STRING_ARRAY ARG_ATTR_NAME_HELP = "pkcs11 attribute name \n\t\t\t\t\t- 'id' as CKA_ID PKCS11 attribute \n\t\t\t\t\t- 'value' as CKA_VALUE PKCS11 attribute \n\t\t\t\t\t- 'application' as CKA_APPLICATION PKCS11 attribute (File must be a ASCCI file)";

const STRING_ARRAY ARG_ATTR_TOKEN = "-token";
const STRING_ARRAY ARG_ATTR_TOKEN_HELP = "pkcs11 attribute CKA_TOKEN \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_PRIVATE = "-private";
const STRING_ARRAY ARG_ATTR_PRIVATE_HELP = "pkcs11 attribute CKA_PRIVATE \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_SENSITIVE = "-sensitive";
const STRING_ARRAY ARG_ATTR_SENSITIVE_HELP = "pkcs11 attribute CKA_SENSITIVE \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_ENCRYPT = "-encrypt";
const STRING_ARRAY ARG_ATTR_ENCRYPT_HELP = "pkcs11 attribute CKA_ENCRYPT \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_DECRYPT = "-decrypt";
const STRING_ARRAY ARG_ATTR_DECRYPT_HELP = "pkcs11 attribute CKA_DECRYPT \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_SIGN = "-sign";
const STRING_ARRAY ARG_ATTR_SIGN_HELP = "pkcs11 attribute CKA_SIGN \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_VERIFY = "-verify";
const STRING_ARRAY ARG_ATTR_VERIFY_HELP = "pkcs11 attribute CKA_VERIFY \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_DERIVE = "-derive";
const STRING_ARRAY ARG_ATTR_DERIVE_HELP = "pkcs11 attribute CKA_DERIVE \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_WRAP = "-wrap";
const STRING_ARRAY ARG_ATTR_WRAP_HELP = "pkcs11 attribute CKA_WRAP \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional, default value is true";

const STRING_ARRAY ARG_ATTR_UNWRAP = "-unwrap";
const STRING_ARRAY ARG_ATTR_UNWRAP_HELP = "pkcs11 attribute CKA_UNWRAP \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_EXTRACTABLE = "-extractable";
const STRING_ARRAY ARG_ATTR_EXTRACTABLE_HELP = "pkcs11 attribute CKA_EXTRACTABLE \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_MODIFIABLE = "-modifiable";
const STRING_ARRAY ARG_ATTR_MODIFIABLE_HELP = "pkcs11 attribute CKA_MODIFIABLE \n\t\t\t\t\t-Supported value: true, false, 0, 1 \n\t\t\t\t\t-Optional Default value is true";

const STRING_ARRAY ARG_ATTR_ID = "-id";
const STRING_ARRAY ARG_ATTR_ID_HELP = "pkcs11 attribute CKA_ID as hexadecimal string\n\t\t\t\t\t-Optional Default value empty";

const STRING_ARRAY ARG_ATTR_APPLICATION = "-application";
const STRING_ARRAY ARG_ATTR_APPLICATION_HELP = "pkcs11 attribute CKA_APPLICATION as string\n\t\t\t\t\t-Optional Default value empty";

const STRING_ARRAY ARG_ATTR_VALUE = "-value";
const STRING_ARRAY ARG_ATTR_VALUE_HELP = "pkcs11 attribute CKA_VALUE as hexadecimal string\n\t\t\t\t\t-Optional Default value empty";

const STRING_ARRAY ARG_KDF_TYPE = "-kdf-type";
const STRING_ARRAY ARG_KDF_TYPE_HELP = "Luna Key Derivation Function type\n\t\t\t\t\t-Mandatory if mecasnim is luna-kdf or luna-nist-kdf. Supported value:\n\t\t\t\t\t-aes-cmac\n\t\t\t\t\t-tdes-cmac\n\t\t\t\t\t-hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512";

const STRING_ARRAY ARG_KDF_SCHEME = "-kdf-scheme";
const STRING_ARRAY ARG_KDF_SCHEME_HELP = "Luna Key Derivation Function scheme\n\t\t\t\t\t-Mandatory if mecasnim is luna-kdf or luna-nist-kdf. Supported value:\n\t\t\t\t\tscheme1 : Counter(4 bytes), Context, Separator byte, Label, and Length(4 bytes)\n\t\t\t\t\tscheme2 : Counter(4 bytes), Context and Label\n\t\t\t\t\tscheme3 : Counter(4 bytes), Label, Separator byte, Context, and Length(4 bytes)\n\t\t\t\t\tscheme4 : Counter(4 bytes), Label and Context\n\t\t\t\t\tscp03 : Label, Separator byte, Length(2 bytes), Counter(1 byte), and Context\n\t\t\t\t\thid : Counter, Label, Separator byte, Context, and Length(2 bytes) ";

const STRING_ARRAY ARG_KDF_COUNTER = "-kdf-counter";
const STRING_ARRAY ARG_KDF_COUNTER_HELP = "Luna Key Derivation Function Counter as hex string";

const STRING_ARRAY ARG_KDF_LABEL = "-kdf-label";
const STRING_ARRAY ARG_KDF_LABEL_HELP = "Luna Key Derivation Function label as hex string. \n\t\t\t\t\t-Optional. If empty, label is set as empty string";

const STRING_ARRAY ARG_KDF_CONTEXT = "-kdf-context";
const STRING_ARRAY ARG_KDF_CONTEXT_HELP = "Luna Key Derivation Function context as hex string. \n\t\t\t\t\t-Optional. If empty, context is set as empty string";

const STRING_ARRAY ARG_KCV_METHOD = "-method";
const STRING_ARRAY ARG_KCV_METHOD_HELP = "KCV computation method \n\t\t\t\t\t-Supported value: pkcs11, pci(banking), gp (global platform)";

const STRING_ARRAY ARG_KCV_COMP = "-clearcomponents";
const STRING_ARRAY ARG_KCV_COMP_HELP = "generate a key with clear components and calculate KCV for each component with PCI method \n\t\t\t\t\t-Number of compoments for symetric keys between 2 to 16";

const STRING_ARRAY ARG_KEYPASSWORD_COMP = "-keypassword";
const STRING_ARRAY ARG_KEYPASSWORD_COMP_HELP = "password of the key for PBKDF2 key generation. \n\t\t\t\t\t-Mandatory if using pbfkd2.";

const STRING_ARRAY ARG_SALT_COMP = "-salt";
const STRING_ARRAY ARG_SALT_COMP_HELP = "salt value for PBKDF2 key generation. \n\t\t\t\t\t-Optional. If empty, the salt is randomly generated with 16 bytes length ";

const STRING_ARRAY ARG_ITERATION_COMP = "-iteration";
const STRING_ARRAY ARG_ITERATION_COMP_HELP = "number if iteration value for PBKDF2 key generation. \n\t\t\t\t\t-Optional. If empty, the number of iteration is 10000 ";

const STRING_ARRAY ARG_PRF_COMP = "-prf";
const STRING_ARRAY ARG_PRF_COMP_HELP = "pseudo random function for password based encryption function. \n\t\t\t\t\t-Optional. hmac-sha1, If empty, the default prf algo is hmac-sha1 ";


#define CMD_HELP_VALUE              (const CK_CHAR_PTR)CMD_HELP, (const P_fCMD)&parser_CommandHelp, (const CK_CHAR_PTR)CMD_HELP_HELP, \
                                    {(const CK_CHAR_PTR)NULL, 0, (const CK_CHAR_PTR)NULL}

#define CMD_LOGIN_VALUE             (const CK_CHAR_PTR)CMD_LOGIN, (const P_fCMD)&cmd_kmu_login, (const CK_CHAR_PTR)CMD_LOGIN_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP }

#define CMD_LOGOUT_VALUE            (const CK_CHAR_PTR)CMD_LOGOUT, (const P_fCMD)&cmd_kmu_logout, (const CK_CHAR_PTR)CMD_LOGOUT_HELP, \
                                    {(const CK_CHAR_PTR)NULL, 0, (const CK_CHAR_PTR)NULL}

#define CMD_EXIT_VALUE              (const CK_CHAR_PTR)CMD_EXIT, (const P_fCMD)&kmu_exitConsole, (const CK_CHAR_PTR)CMD_EXIT_HELP, \
                                    {(const CK_CHAR_PTR)NULL, 0, (const CK_CHAR_PTR)NULL}

#define CMD_LIST_SLOT_VALUE         (const CK_CHAR_PTR)CMD_LIST_SLOT, (const P_fCMD)&cmd_kmu_list_SLot, (const CK_CHAR_PTR)CMD_LIST_SLOT_HELP, \
                                    {(const CK_CHAR_PTR)NULL, 0, (const CK_CHAR_PTR)NULL}


#define CMD_LIST_VALUE              (const CK_CHAR_PTR)CMD_LIST, (const P_fCMD)&cmd_kmu_list, (const CK_CHAR_PTR)CMD_LIST_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP }


#define CMD_GENERATEKEY_VALUE       (const CK_CHAR_PTR)CMD_GENERATE_KEY, (const P_fCMD)&cmd_kmu_generateKey, (const CK_CHAR_PTR)CMD_GENERATE_KEY_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_KEYTYPE, ARG_TYPE_KEYTYPE, (const CK_CHAR_PTR)ARG_KEYTYPE_HELP,\
                                    (const CK_CHAR_PTR)ARG_KEYSIZE, ARG_TYPE_KEYSIZE, (const CK_CHAR_PTR)ARG_KEYSIZE_HELP,\
                                    (const CK_CHAR_PTR)ARG_LABEL,	ARG_TYPE_CKA_LABEL, (const CK_CHAR_PTR)ARG_LABEL_GENERATEKEY_HELP,\
                                    (const CK_CHAR_PTR)ARG_LABEL_PRIVATE, ARG_TYPE_LABEL_PRIV, (const CK_CHAR_PTR)ARG_LABEL_PRIVATE_HELP,\
                                    (const CK_CHAR_PTR)ARG_LABEL_PUBLIC, ARG_TYPE_LABEL_PUB, (const CK_CHAR_PTR)ARG_LABEL_PUBLIC_HELP,\
                                    (const CK_CHAR_PTR)ARG_PUBLIC_EXP, ARG_TYPE_PUBLIC_EXP, (const CK_CHAR_PTR)ARG_PUBLIC_EXP_HELP,\
                                    (const CK_CHAR_PTR)ARG_KEYGEN_MECH, ARG_TYPE_KEYGEN_MECH, (const CK_CHAR_PTR)ARG_KEY_GEN_MECH_HELP,\
                                    (const CK_CHAR_PTR)ARG_ECCCURVE, ARG_TYPE_ECC_CURVE, (const CK_CHAR_PTR)ARG_ECCCURVE_HELP,\
                                    (const CK_CHAR_PTR)ARG_DH_BASE, ARG_TYPE_DH_BASE, (const CK_CHAR_PTR)ARG_DH_BASE_HELP,\
                                    (const CK_CHAR_PTR)ARG_DH_PRIME, ARG_TYPE_DH_PRIME, (const CK_CHAR_PTR)ARG_DH_PRIME_HELP,\
                                    (const CK_CHAR_PTR)ARG_DH_SUBPRIME, ARG_TYPE_DH_SUBPRIME, (const CK_CHAR_PTR)ARG_DH_SUBPRIME_HELP,\
                                    (const CK_CHAR_PTR)ARG_KCV_COMP, ARG_TYPE_KEY_COMP, (const CK_CHAR_PTR)ARG_KCV_COMP_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_ENCRYPT, ARG_TYPE_CKA_ENCRYPT, (const CK_CHAR_PTR)ARG_ATTR_ENCRYPT_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_DECRYPT, ARG_TYPE_CKA_DECRYPT, (const CK_CHAR_PTR)ARG_ATTR_DECRYPT_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_SIGN, ARG_TYPE_CKA_SIGN, (const CK_CHAR_PTR)ARG_ATTR_SIGN_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_VERIFY, ARG_TYPE_CKA_VERIFY, (const CK_CHAR_PTR)ARG_ATTR_VERIFY_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_DERIVE, ARG_TYPE_CKA_DERIVE, (const CK_CHAR_PTR)ARG_ATTR_DERIVE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_WRAP, ARG_TYPE_CKA_WRAP, (const CK_CHAR_PTR)ARG_ATTR_WRAP_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_UNWRAP, ARG_TYPE_CKA_UNWRAP, (const CK_CHAR_PTR)ARG_ATTR_UNWRAP_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_EXTRACTABLE, ARG_TYPE_CKA_EXTRACTABLE, (const CK_CHAR_PTR)ARG_ATTR_EXTRACTABLE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_MODIFIABLE, ARG_TYPE_CKA_MODIFIABLE, (const CK_CHAR_PTR)ARG_ATTR_MODIFIABLE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_TOKEN, ARG_TYPE_CKA_TOKEN, (const CK_CHAR_PTR)ARG_ATTR_TOKEN_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_PRIVATE, ARG_TYPE_CKA_PRIVATE, (const CK_CHAR_PTR)ARG_ATTR_PRIVATE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_SENSITIVE, ARG_TYPE_CKA_SENSITIVE, (const CK_CHAR_PTR)ARG_ATTR_SENSITIVE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_ID, ARG_TYPE_CKA_ID, (const CK_CHAR_PTR)ARG_ATTR_ID_HELP,\
                                    }


#define CMD_CREATE_DO_VALUE     (const CK_CHAR_PTR)CMD_CREATE_DO, (const P_fCMD)&cmd_kmu_createDO, (const CK_CHAR_PTR)CMD_CREATE_DO_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_LABEL,	ARG_TYPE_CKA_LABEL, (const CK_CHAR_PTR)ARG_LABEL_GENERATEKEY_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_MODIFIABLE, ARG_TYPE_CKA_MODIFIABLE, (const CK_CHAR_PTR)ARG_ATTR_MODIFIABLE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_TOKEN, ARG_TYPE_CKA_TOKEN, (const CK_CHAR_PTR)ARG_ATTR_TOKEN_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_PRIVATE, ARG_TYPE_CKA_PRIVATE, (const CK_CHAR_PTR)ARG_ATTR_PRIVATE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_APPLICATION, ARG_TYPE_CKA_APPLICATION, (const CK_CHAR_PTR)ARG_ATTR_APPLICATION_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_VALUE, ARG_TYPE_CKA_VALUE, (const CK_CHAR_PTR)ARG_ATTR_VALUE_HELP,\
                                    }

#define CMD_GET_ATTRIBUTE_VALUE     (const CK_CHAR_PTR)CMD_GET_ATTRIBUTE, (const P_fCMD)&cmd_kmu_getattribute, (const CK_CHAR_PTR)CMD_GET_ATTRIBUTE_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_HANDLE, ARG_TYPE_HANDLE, (const CK_CHAR_PTR)ARG_HANDLE_HELP ,\
                                    }

#define CMD_SET_ATTRIBUTE_VALUE     (const CK_CHAR_PTR)CMD_SET_ATTRIBUTE, (const P_fCMD)&cmd_kmu_setattribute, (const CK_CHAR_PTR)CMD_SET_ATTRIBUTE_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_HANDLE, ARG_TYPE_HANDLE, (const CK_CHAR_PTR)ARG_HANDLE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_LABEL,	ARG_TYPE_CKA_LABEL, (const CK_CHAR_PTR)ARG_LABEL_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_ENCRYPT, ARG_TYPE_CKA_ENCRYPT, (const CK_CHAR_PTR)ARG_ATTR_ENCRYPT_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_DECRYPT, ARG_TYPE_CKA_DECRYPT, (const CK_CHAR_PTR)ARG_ATTR_DECRYPT_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_SIGN, ARG_TYPE_CKA_SIGN, (const CK_CHAR_PTR)ARG_ATTR_SIGN_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_VERIFY, ARG_TYPE_CKA_VERIFY, (const CK_CHAR_PTR)ARG_ATTR_VERIFY_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_DERIVE, ARG_TYPE_CKA_DERIVE, (const CK_CHAR_PTR)ARG_ATTR_DERIVE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_WRAP, ARG_TYPE_CKA_WRAP, (const CK_CHAR_PTR)ARG_ATTR_WRAP_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_UNWRAP, ARG_TYPE_CKA_UNWRAP, (const CK_CHAR_PTR)ARG_ATTR_UNWRAP_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_EXTRACTABLE, ARG_TYPE_CKA_EXTRACTABLE, (const CK_CHAR_PTR)ARG_ATTR_EXTRACTABLE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_MODIFIABLE, ARG_TYPE_CKA_MODIFIABLE, (const CK_CHAR_PTR)ARG_ATTR_MODIFIABLE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_PRIVATE, ARG_TYPE_CKA_PRIVATE, (const CK_CHAR_PTR)ARG_ATTR_PRIVATE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_ID, ARG_TYPE_CKA_ID, (const CK_CHAR_PTR)ARG_ATTR_ID_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_APPLICATION, ARG_TYPE_CKA_APPLICATION, (const CK_CHAR_PTR)ARG_ATTR_APPLICATION_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_VALUE, ARG_TYPE_CKA_VALUE, (const CK_CHAR_PTR)ARG_ATTR_VALUE_HELP,\
                                    }


#define CMD_READ_ATTRIBUTE_VALUE    (const CK_CHAR_PTR)CMD_READ_ATTRIBUTE, (const P_fCMD)&cmd_kmu_readattribute, (const CK_CHAR_PTR)CMD_READ_ATTRIBUTE_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_HANDLE, ARG_TYPE_HANDLE, (const CK_CHAR_PTR)ARG_HANDLE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_OUTPUT_FILE, ARG_TYPE_FILE_OUTPUT, (const CK_CHAR_PTR)ARG_FILE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_ATTR_NAME, ARG_TYPE_ATTR_NAME, (const CK_CHAR_PTR)ARG_ATTR_NAME_HELP, \
                                    }

#define CMD_WRITE_ATTRIBUTE_VALUE    (const CK_CHAR_PTR)CMD_WRITE_ATTRIBUTE, (const P_fCMD)&cmd_kmu_writeattribute, (const CK_CHAR_PTR)CMD_WRITE_ATTRIBUTE_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_HANDLE, ARG_TYPE_HANDLE, (const CK_CHAR_PTR)ARG_HANDLE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_INPUT_FILE, ARG_TYPE_FILE_INPUT, (const CK_CHAR_PTR)ARG_FILE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_ATTR_NAME, ARG_TYPE_ATTR_NAME, (const CK_CHAR_PTR)ARG_ATTR_NAME_HELP, \
                                    }

#define CMD_EXPORT_KEY_VALUE        (const CK_CHAR_PTR)CMD_EXPORT, (const P_fCMD)&cmd_kmu_export, (const CK_CHAR_PTR)CMD_EXPORT_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_HANDLE, ARG_TYPE_HANDLE_EXPORT, (const CK_CHAR_PTR)ARG_HANDLE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_WRAPKEY, ARG_TYPE_HANDLE_WRAPKEY, (const CK_CHAR_PTR)ARG_WRAPKEY_HELP ,\
                                    (const CK_CHAR_PTR)ARG_OUTPUT_FILE, ARG_TYPE_FILE_OUTPUT, (const CK_CHAR_PTR)ARG_FILE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_FORMAT, ARG_TYPE_FORMAT_FILE, (const CK_CHAR_PTR)ARG_FORMAT_HELP, \
                                    (const CK_CHAR_PTR)ARG_ALGO, ARG_TYPE_WRAP_ALGO, (const CK_CHAR_PTR)ARG_ALGO_HELP ,\
                                    (const CK_CHAR_PTR)ARG_IV, ARG_TYPE_IV, (const CK_CHAR_PTR)ARG_IV_HELP, \
                                    (const CK_CHAR_PTR)ARG_ADDITONAL_AUTH_DATA, ARG_TYPE_GCM_AUTH_DATA, (const CK_CHAR_PTR)ARG_ADDITONAL_AUTH_DATA_HELP, \
                                    (const CK_CHAR_PTR)ARG_AUTH_TAG_LEN, ARG_TYPE_GCM_TAG_LEN, (const CK_CHAR_PTR)ARG_AUTH_TAG_LEN_HELP, \
                                    (const CK_CHAR_PTR)ARG_HASH, ARG_TYPE_RSA_OAEP_HASH, (const CK_CHAR_PTR)ARG_OEAP_HASH_HELP, \
                                    (const CK_CHAR_PTR)ARG_KEYPASSWORD_COMP, ARG_TYPE_KEY_PASSWORD, (const CK_CHAR_PTR)ARG_KEYPASSWORD_COMP_HELP, \
                                    (const CK_CHAR_PTR)ARG_SALT_COMP, ARG_TYPE_SALT, (const CK_CHAR_PTR)ARG_SALT_COMP_HELP, \
                                    (const CK_CHAR_PTR)ARG_ITERATION_COMP, ARG_TYPE_ITERATION, (const CK_CHAR_PTR)ARG_ITERATION_COMP_HELP, \
                                    (const CK_CHAR_PTR)ARG_PRF_COMP, ARG_TYPE_PRF, (const CK_CHAR_PTR)ARG_PRF_COMP_HELP, \
}


#define CMD_IMPORT_KEY_VALUE        (const CK_CHAR_PTR)CMD_IMPORT, (const P_fCMD)&cmd_kmu_import, (const CK_CHAR_PTR)CMD_IMPORT_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_LABEL,	ARG_TYPE_CKA_LABEL, (const CK_CHAR_PTR)ARG_LABEL_HELP,\
                                    (const CK_CHAR_PTR)ARG_KEYTYPE, ARG_TYPE_KEYTYPE, (const CK_CHAR_PTR)ARG_IMPORTKEYTYPE_HELP,\
                                    (const CK_CHAR_PTR)ARG_KEYSIZE, ARG_TYPE_KEYSIZE, (const CK_CHAR_PTR)ARG_IMPORTKEY_SIZE_HELP,\
                                    (const CK_CHAR_PTR)ARG_KEYCLASS, ARG_TYPE_KEYCLASS, (const CK_CHAR_PTR)ARG_KEYCLASS_HELP,\
                                    (const CK_CHAR_PTR)ARG_UNWRAPKEY, ARG_TYPE_HANDLE_UNWRAPKEY, (const CK_CHAR_PTR)ARG_UNWRAPKEY_HELP ,\
                                    (const CK_CHAR_PTR)ARG_INPUT_FILE, ARG_TYPE_FILE_INPUT, (const CK_CHAR_PTR)ARG_FILE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_FORMAT, ARG_TYPE_FORMAT_FILE, (const CK_CHAR_PTR)ARG_FORMAT_HELP, \
                                    (const CK_CHAR_PTR)ARG_ALGO, ARG_TYPE_UNWRAP_ALGO, (const CK_CHAR_PTR)ARG_ALGO_HELP ,\
                                    (const CK_CHAR_PTR)ARG_IV, ARG_TYPE_IV, (const CK_CHAR_PTR)ARG_IV_HELP, \
                                    (const CK_CHAR_PTR)ARG_ADDITONAL_AUTH_DATA, ARG_TYPE_GCM_AUTH_DATA, (const CK_CHAR_PTR)ARG_ADDITONAL_AUTH_DATA_HELP, \
                                    (const CK_CHAR_PTR)ARG_AUTH_TAG_LEN, ARG_TYPE_GCM_TAG_LEN, (const CK_CHAR_PTR)ARG_AUTH_TAG_LEN_HELP, \
                                    (const CK_CHAR_PTR)ARG_HASH, ARG_TYPE_RSA_OAEP_HASH, (const CK_CHAR_PTR)ARG_OEAP_HASH_HELP, \
                                    (const CK_CHAR_PTR)ARG_KCV_COMP, ARG_TYPE_KEY_COMP, (const CK_CHAR_PTR)ARG_KCV_COMP_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_ENCRYPT, ARG_TYPE_CKA_ENCRYPT, (const CK_CHAR_PTR)ARG_ATTR_ENCRYPT_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_DECRYPT, ARG_TYPE_CKA_DECRYPT, (const CK_CHAR_PTR)ARG_ATTR_DECRYPT_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_SIGN, ARG_TYPE_CKA_SIGN, (const CK_CHAR_PTR)ARG_ATTR_SIGN_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_VERIFY, ARG_TYPE_CKA_VERIFY, (const CK_CHAR_PTR)ARG_ATTR_VERIFY_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_DERIVE, ARG_TYPE_CKA_DERIVE, (const CK_CHAR_PTR)ARG_ATTR_DERIVE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_WRAP, ARG_TYPE_CKA_WRAP, (const CK_CHAR_PTR)ARG_ATTR_WRAP_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_UNWRAP, ARG_TYPE_CKA_UNWRAP, (const CK_CHAR_PTR)ARG_ATTR_UNWRAP_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_EXTRACTABLE, ARG_TYPE_CKA_EXTRACTABLE, (const CK_CHAR_PTR)ARG_ATTR_EXTRACTABLE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_MODIFIABLE, ARG_TYPE_CKA_MODIFIABLE, (const CK_CHAR_PTR)ARG_ATTR_MODIFIABLE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_TOKEN, ARG_TYPE_CKA_TOKEN, (const CK_CHAR_PTR)ARG_ATTR_TOKEN_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_PRIVATE, ARG_TYPE_CKA_PRIVATE, (const CK_CHAR_PTR)ARG_ATTR_PRIVATE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_SENSITIVE, ARG_TYPE_CKA_SENSITIVE, (const CK_CHAR_PTR)ARG_ATTR_SENSITIVE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_ID, ARG_TYPE_CKA_ID, (const CK_CHAR_PTR)ARG_ATTR_ID_HELP,\
}


#define CMD_ENCRYPT_VALUE           (const CK_CHAR_PTR)CMD_ENCRYPT, (const P_fCMD)&cmd_kmu_encrypt, (const CK_CHAR_PTR)CMD_ENCRYPT_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_KEY, ARG_TYPE_HANDLE_ENCRYPT, (const CK_CHAR_PTR)ARG_KEY_HELP ,\
                                    (const CK_CHAR_PTR)ARG_ALGO, ARG_TYPE_ALGO, (const CK_CHAR_PTR)ARG_ALGO_HELP ,\
                                    (const CK_CHAR_PTR)ARG_IV, ARG_TYPE_IV, (const CK_CHAR_PTR)ARG_IV_HELP, \
                                    (const CK_CHAR_PTR)ARG_ADDITONAL_AUTH_DATA, ARG_TYPE_GCM_AUTH_DATA, (const CK_CHAR_PTR)ARG_ADDITONAL_AUTH_DATA_HELP, \
                                    (const CK_CHAR_PTR)ARG_AUTH_TAG_LEN, ARG_TYPE_GCM_TAG_LEN, (const CK_CHAR_PTR)ARG_AUTH_TAG_LEN_HELP, \
                                    (const CK_CHAR_PTR)ARG_HASH, ARG_TYPE_RSA_OAEP_HASH, (const CK_CHAR_PTR)ARG_OEAP_HASH_HELP, \
                                    (const CK_CHAR_PTR)ARG_OUTPUT_FILE, ARG_TYPE_FILE_OUTPUT, (const CK_CHAR_PTR)ARG_FILE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_INPUT_FILE, ARG_TYPE_FILE_INPUT, (const CK_CHAR_PTR)ARG_FILE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_FORMAT, ARG_TYPE_FORMAT_FILE, (const CK_CHAR_PTR)ARG_FORMAT_ENCRYPT_HELP, \
                                    }


#define CMD_DECRYPT_VALUE           (const CK_CHAR_PTR)CMD_DECRYPT, (const P_fCMD)&cmd_kmu_decrypt, (const CK_CHAR_PTR)CMD_DECRYPT_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_KEY, ARG_TYPE_HANDLE_DECRYPT, (const CK_CHAR_PTR)ARG_KEY_HELP ,\
                                    (const CK_CHAR_PTR)ARG_ALGO, ARG_TYPE_ALGO, (const CK_CHAR_PTR)ARG_ALGO_HELP ,\
                                    (const CK_CHAR_PTR)ARG_IV, ARG_TYPE_IV, (const CK_CHAR_PTR)ARG_IV_HELP, \
                                    (const CK_CHAR_PTR)ARG_ADDITONAL_AUTH_DATA, ARG_TYPE_GCM_AUTH_DATA, (const CK_CHAR_PTR)ARG_ADDITONAL_AUTH_DATA_HELP, \
                                    (const CK_CHAR_PTR)ARG_AUTH_TAG_LEN, ARG_TYPE_GCM_TAG_LEN, (const CK_CHAR_PTR)ARG_AUTH_TAG_LEN_HELP, \
                                    (const CK_CHAR_PTR)ARG_HASH, ARG_TYPE_RSA_OAEP_HASH, (const CK_CHAR_PTR)ARG_OEAP_HASH_HELP, \
                                    (const CK_CHAR_PTR)ARG_OUTPUT_FILE, ARG_TYPE_FILE_OUTPUT, (const CK_CHAR_PTR)ARG_FILE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_INPUT_FILE, ARG_TYPE_FILE_INPUT, (const CK_CHAR_PTR)ARG_FILE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_FORMAT, ARG_TYPE_FORMAT_FILE, (const CK_CHAR_PTR)ARG_FORMAT_ENCRYPT_HELP, \
                                    }

#define CMD_DERIVE_VALUE            (const CK_CHAR_PTR)CMD_DERIVE, (const P_fCMD)&cmd_kmu_derive, (const CK_CHAR_PTR)CMD_DERIVE_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_DERIVE_KEY, ARG_TYPE_HANDLE_DERIVE, (const CK_CHAR_PTR)ARG_DERIVE_KEY_HELP ,\
                                    (const CK_CHAR_PTR)ARG_DERIVE_MECH, ARG_TYPE_DERIVE_MECH, (const CK_CHAR_PTR)ARG_DERIVE_MECH_HELP ,\
                                    (const CK_CHAR_PTR)ARG_LABEL,	ARG_TYPE_CKA_LABEL, (const CK_CHAR_PTR)ARG_LABEL_DERIVEKEY_HELP,\
                                    (const CK_CHAR_PTR)ARG_KEYTYPE, ARG_TYPE_KEYTYPE, (const CK_CHAR_PTR)ARG_DERIVEKEY_TYPE_HELP,\
                                    (const CK_CHAR_PTR)ARG_KEYSIZE, ARG_TYPE_KEYSIZE, (const CK_CHAR_PTR)ARG_DERIVEKEY_SIZE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_ENCRYPT, ARG_TYPE_CKA_ENCRYPT, (const CK_CHAR_PTR)ARG_ATTR_ENCRYPT_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_DECRYPT, ARG_TYPE_CKA_DECRYPT, (const CK_CHAR_PTR)ARG_ATTR_DECRYPT_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_SIGN, ARG_TYPE_CKA_SIGN, (const CK_CHAR_PTR)ARG_ATTR_SIGN_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_VERIFY, ARG_TYPE_CKA_VERIFY, (const CK_CHAR_PTR)ARG_ATTR_VERIFY_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_DERIVE, ARG_TYPE_CKA_DERIVE, (const CK_CHAR_PTR)ARG_ATTR_DERIVE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_WRAP, ARG_TYPE_CKA_WRAP, (const CK_CHAR_PTR)ARG_ATTR_WRAP_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_UNWRAP, ARG_TYPE_CKA_UNWRAP, (const CK_CHAR_PTR)ARG_ATTR_UNWRAP_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_EXTRACTABLE, ARG_TYPE_CKA_EXTRACTABLE, (const CK_CHAR_PTR)ARG_ATTR_EXTRACTABLE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_MODIFIABLE, ARG_TYPE_CKA_MODIFIABLE, (const CK_CHAR_PTR)ARG_ATTR_MODIFIABLE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_TOKEN, ARG_TYPE_CKA_TOKEN, (const CK_CHAR_PTR)ARG_ATTR_TOKEN_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_PRIVATE, ARG_TYPE_CKA_PRIVATE, (const CK_CHAR_PTR)ARG_ATTR_PRIVATE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_SENSITIVE, ARG_TYPE_CKA_SENSITIVE, (const CK_CHAR_PTR)ARG_ATTR_SENSITIVE_HELP,\
                                    (const CK_CHAR_PTR)ARG_ATTR_ID, ARG_TYPE_CKA_ID, (const CK_CHAR_PTR)ARG_ATTR_ID_HELP,\
                                    (const CK_CHAR_PTR)ARG_KDF_TYPE, ARG_TYPE_KDF_TYPE, (const CK_CHAR_PTR)ARG_KDF_TYPE_HELP,\
                                    (const CK_CHAR_PTR)ARG_KDF_SCHEME, ARG_TYPE_KDF_SCHEME, (const CK_CHAR_PTR)ARG_KDF_SCHEME_HELP,\
                                    (const CK_CHAR_PTR)ARG_KDF_COUNTER, ARG_TYPE_KDF_COUNTER, (const CK_CHAR_PTR)ARG_KDF_COUNTER_HELP,\
                                    (const CK_CHAR_PTR)ARG_KDF_LABEL, ARG_TYPE_KDF_LABEL, (const CK_CHAR_PTR)ARG_KDF_LABEL_HELP,\
                                    (const CK_CHAR_PTR)ARG_KDF_CONTEXT, ARG_TYPE_KDF_CONTEXT, (const CK_CHAR_PTR)ARG_KDF_CONTEXT_HELP,\
                                    }

#define CMD_CONVERT_VALUE           (const CK_CHAR_PTR)CMD_CONVERT, (const P_fCMD)&cmd_kmu_convert, (const CK_CHAR_PTR)CMD_CONVERT_HELP, \
                                    {(const CK_CHAR_PTR)ARG_INPUT_FILE, ARG_TYPE_FILE_INPUT, (const CK_CHAR_PTR)ARG_FILE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_OUTPUT_FILE, ARG_TYPE_FILE_OUTPUT, (const CK_CHAR_PTR)ARG_FILE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_INFORMAT, ARG_TYPE_INFORM_FILE, (const CK_CHAR_PTR)ARG_FORMAT_HELP,\
                                    (const CK_CHAR_PTR)ARG_OUTFORMAT, ARG_TYPE_OUTFORM_FILE, (const CK_CHAR_PTR)ARG_FORMAT_HELP,\
                                    }

#define CMD_DELETE_VALUE            (const CK_CHAR_PTR)CMD_DELETE, (const P_fCMD)&cmd_kmu_delete, (const CK_CHAR_PTR)CMD_DELETE_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_HANDLE, ARG_TYPE_HANDLE_DELETE, (const CK_CHAR_PTR)ARG_HANDLE_HELP ,\
                                    }

#define CMD_DIGEST_KEY_VALUE        (const CK_CHAR_PTR)CMD_DIGEST_KEY, (const P_fCMD)&cmd_kmu_digestKey, (const CK_CHAR_PTR)CMD_DIGEST_KEY_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_HANDLE, ARG_TYPE_HANDLE_DIG_KEY, (const CK_CHAR_PTR)ARG_HANDLE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_HASH, ARG_TYPE_HASH_KEY, (const CK_CHAR_PTR)ARG_HASH_HELP ,\
                                    }

#define CMD_COMPUTE_KCV_VALUE       (const CK_CHAR_PTR)CMD_COMPUTE_KCV, (const P_fCMD)&cmd_kmu_compute_KCV, (const CK_CHAR_PTR)CMD_COMPUTE_KCV_HELP, \
                                    {(const CK_CHAR_PTR)ARG_SLOT_ID, ARG_TYPE_SLOT, (const CK_CHAR_PTR)ARG_SLOT_ID_HELP ,\
                                    (const CK_CHAR_PTR)ARG_PASSWORD, ARG_TYPE_PASSWORD, (const CK_CHAR_PTR)ARG_PASSWORD_HELP ,\
                                    (const CK_CHAR_PTR)ARG_CU, ARG_TYPE_CRYPTO_USER, (const CK_CHAR_PTR)ARG_CU_HELP ,\
                                    (const CK_CHAR_PTR)ARG_HANDLE, ARG_TYPE_HANDLE_KCV, (const CK_CHAR_PTR)ARG_HANDLE_HELP ,\
                                    (const CK_CHAR_PTR)ARG_KCV_METHOD, ARG_TYPE_METHOD_KCV, (const CK_CHAR_PTR)ARG_KCV_METHOD_HELP ,\
                                    }

#define MAX_COMMAND_NUMBER		DIM(kmu_batchcmd_list)
const PARSER_COMMAND kmu_batchcmd_list[] =
{
   CMD_HELP_VALUE,
   CMD_LIST_VALUE,
   CMD_GENERATEKEY_VALUE,
   CMD_CREATE_DO_VALUE,
   CMD_GET_ATTRIBUTE_VALUE,
   CMD_SET_ATTRIBUTE_VALUE,
   CMD_READ_ATTRIBUTE_VALUE,
   CMD_WRITE_ATTRIBUTE_VALUE,
   CMD_EXPORT_KEY_VALUE,
   CMD_IMPORT_KEY_VALUE,
   CMD_ENCRYPT_VALUE,
   CMD_DECRYPT_VALUE,
   CMD_DERIVE_VALUE,
   CMD_CONVERT_VALUE,
   CMD_DELETE_VALUE,
   CMD_DIGEST_KEY_VALUE,
   CMD_COMPUTE_KCV_VALUE,
};

#define MAX_CONSOLE_COMMAND_NUMBER		DIM(kmu_console_list)
const PARSER_COMMAND kmu_console_list[] =
{
   CMD_HELP_VALUE,
   CMD_LIST_SLOT_VALUE,
   CMD_LOGIN_VALUE,
   CMD_LOGOUT_VALUE,
   CMD_LIST_VALUE,
   CMD_GENERATEKEY_VALUE,
   CMD_CREATE_DO_VALUE,
   CMD_GET_ATTRIBUTE_VALUE,
   CMD_SET_ATTRIBUTE_VALUE,
   CMD_READ_ATTRIBUTE_VALUE,
   CMD_WRITE_ATTRIBUTE_VALUE,
   CMD_EXPORT_KEY_VALUE,
   CMD_IMPORT_KEY_VALUE,
   CMD_ENCRYPT_VALUE,
   CMD_DECRYPT_VALUE,
   CMD_DERIVE_VALUE,
   CMD_CONVERT_VALUE,
   CMD_DELETE_VALUE,
   CMD_DIGEST_KEY_VALUE,
   CMD_COMPUTE_KCV_VALUE,
   CMD_EXIT_VALUE,
};

const CK_CHAR_PTR  sAutocompletion[] =
{
   (CK_CHAR_PTR)CMD_HELP,
   (CK_CHAR_PTR)CMD_LOGIN,
   (CK_CHAR_PTR)CMD_LOGOUT,
   (CK_CHAR_PTR)CMD_LIST,
   (CK_CHAR_PTR)CMD_LIST_SLOT,
   (CK_CHAR_PTR)CMD_GENERATE_KEY,
   (CK_CHAR_PTR)CMD_CREATE_DO,
   (CK_CHAR_PTR)CMD_GET_ATTRIBUTE,
   (CK_CHAR_PTR)CMD_SET_ATTRIBUTE,
   (CK_CHAR_PTR)CMD_READ_ATTRIBUTE,
   (CK_CHAR_PTR)CMD_WRITE_ATTRIBUTE,
   (CK_CHAR_PTR)CMD_EXPORT,
   (CK_CHAR_PTR)CMD_IMPORT,
   (CK_CHAR_PTR)CMD_ENCRYPT,
   (CK_CHAR_PTR)CMD_DECRYPT,
   (CK_CHAR_PTR)CMD_DERIVE,
   (CK_CHAR_PTR)CMD_CONVERT,
   (CK_CHAR_PTR)CMD_DELETE,
   (CK_CHAR_PTR)CMD_DIGEST_KEY,
   (CK_CHAR_PTR)CMD_COMPUTE_KCV,
   (CK_CHAR_PTR)CMD_EXIT,
   (CK_CHAR_PTR)ARG_SLOT_ID,
   (CK_CHAR_PTR)ARG_PASSWORD,
   (CK_CHAR_PTR)ARG_LABEL,
   (CK_CHAR_PTR)ARG_HANDLE,
   (CK_CHAR_PTR)ARG_KEY,
   (CK_CHAR_PTR)ARG_WRAPKEY,
   (CK_CHAR_PTR)ARG_UNWRAPKEY,
   (CK_CHAR_PTR)ARG_LABEL_PRIVATE,
   (CK_CHAR_PTR)ARG_LABEL_PUBLIC,
   (CK_CHAR_PTR)ARG_KEYTYPE,
   (CK_CHAR_PTR)ARG_KEYSIZE,
   (CK_CHAR_PTR)ARG_KEYCLASS,
   (CK_CHAR_PTR)ARG_PUBLIC_EXP,
   (CK_CHAR_PTR)ARG_ALGO,
   (CK_CHAR_PTR)ARG_IV,
   (CK_CHAR_PTR)ARG_ADDITONAL_AUTH_DATA,
   (CK_CHAR_PTR)ARG_AUTH_TAG_LEN,
   (CK_CHAR_PTR)ARG_HASH,
   (CK_CHAR_PTR)ARG_KEYGEN_MECH,
   (CK_CHAR_PTR)ARG_ECCCURVE,
   (CK_CHAR_PTR)ARG_OUTPUT_FILE,
   (CK_CHAR_PTR)ARG_INPUT_FILE,
   (CK_CHAR_PTR)ARG_FORMAT,
   (CK_CHAR_PTR)ARG_OUTFORMAT,
   (CK_CHAR_PTR)ARG_INFORMAT,
   (CK_CHAR_PTR)ARG_ATTR_TOKEN,
   (CK_CHAR_PTR)ARG_ATTR_PRIVATE,
   (CK_CHAR_PTR)ARG_ATTR_SENSITIVE,
   (CK_CHAR_PTR)ARG_ATTR_ENCRYPT,
   (CK_CHAR_PTR)ARG_ATTR_DECRYPT,
   (CK_CHAR_PTR)ARG_ATTR_SIGN,
   (CK_CHAR_PTR)ARG_ATTR_VERIFY,
   (CK_CHAR_PTR)ARG_ATTR_DERIVE,
   (CK_CHAR_PTR)ARG_ATTR_WRAP,
   (CK_CHAR_PTR)ARG_ATTR_UNWRAP,
   (CK_CHAR_PTR)ARG_ATTR_EXTRACTABLE,
   (CK_CHAR_PTR)ARG_ATTR_MODIFIABLE,
   (CK_CHAR_PTR)ARG_ATTR_ID,
   (CK_CHAR_PTR)ARG_ATTR_APPLICATION,
   (CK_CHAR_PTR)ARG_ATTR_VALUE,
   (CK_CHAR_PTR)ARG_DH_PRIME,
   (CK_CHAR_PTR)ARG_DH_BASE,
   (CK_CHAR_PTR)ARG_DH_SUBPRIME,
   (CK_CHAR_PTR)ARG_KDF_TYPE,
   (CK_CHAR_PTR)ARG_KDF_SCHEME,
   (CK_CHAR_PTR)ARG_KDF_COUNTER,
   (CK_CHAR_PTR)ARG_KDF_LABEL,
   (CK_CHAR_PTR)ARG_KDF_CONTEXT,
   (CK_CHAR_PTR)ARG_KCV_METHOD,
   (CK_CHAR_PTR)ARG_CU,
   (CK_CHAR_PTR)ARG_KCV_COMP,
};

#define MAX_CONSOLE_ARG_LIST      (1+ (MAX_ARGUMENT *2))

char* pConsoleArgList[MAX_CONSOLE_ARG_LIST];
CK_BBOOL bExitFlag;

CK_BBOOL kmu_Batch(int argc, char* argv[]);
CK_BBOOL kmu_Console();
CK_LONG kmu_CheckConsoleCommand(CK_CHAR_PTR sCommand);



#ifdef OS_WIN32

BOOL WINAPI HandlerRoutine(_In_ DWORD dwCtrlType) {
   switch (dwCtrlType)
   {
   case CTRL_C_EVENT:
      printf("Ctrl+C\n");
      // Signal is handled - don'sTime pass it on to the next handler

      // release console
      Console_Terminate();

      // free P11 library
      P11_Terminate();

      printf("Thanks for using KMU\n");

      exit(0);
      return TRUE;
   default:
      // Pass signal on to the next handler
      return FALSE;
   }
}

#endif

/*
    FUNCTION:        int main(int argc, char* argv[], char** envp)
*/
int main(int argc, // Number of strings in array argv
   char* argv[],      // Array of command-line argument strings
   char** envp)
{
   printf("Key Management Utility (64-bit). Copyright ©(c) 2025 Thales Group. All rights reserved.\n");
   printf("This tool is a cryptography key utility compatible with PKCS#11 device such as luna hsm and is only for test purposes and shall not be distributed.\n\n");

   // Init console
   Console_Init();

#ifdef OS_WIN32
   SetConsoleCtrlHandler(HandlerRoutine, TRUE);
#endif
   // init p11 global variables
   P11_Init();

   // if not arg, run the console 
   if (argc == 1)
   {
      kmu_Console();
   }
   // run the batch
   else
   {
      kmu_Batch(argc, argv);
   }

   // free P11 library
   P11_Terminate();

   // release console
   Console_Terminate();

   return FALSE;
}

/*
    FUNCTION:        CK_BBOOL kmu_Batch(int argc, char* argv[])
*/
CK_BBOOL kmu_Batch(int argc, char* argv[])
{
   do
   {

      // Init command parser with batch list of command
      parser_Init((PARSER_COMMAND*)kmu_batchcmd_list, MAX_COMMAND_NUMBER);

      argc--;

      if (parser_CommandParser(argc, &argv[1]) == CK_FALSE)
      {
         return FALSE;
      }

      // Check if command Help. 
      if (parser_IsCommand((CK_CHAR_PTR)CMD_HELP) == CK_FALSE)
      {
         // Login for all command except help
         // init p11 library
         if (P11_LoadLibrary() != CK_TRUE)
         {
            break;
         }

         // Login to slot
         if (cmd_kmu_login(CK_FALSE) == CK_FALSE)
         {
            break;
         }
      }

      // execute command
      if (parser_ExecuteCommand(CK_FALSE) != CK_TRUE)
      {
         break;
      }

      return CK_TRUE;
      // successfull execution
   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL kmu_Console()
*/
CK_BBOOL kmu_Console()
{
   CK_LONG sCommandArgNumber;
   CK_BBOOL bAutoCompletion = CK_TRUE;
#ifdef OS_WIN32
   P_ConsoleFunction pConsole_RequestString = &Console_RequestStringWithAutoComplete;

   // required fow windows with the console with auto complete. Requires virtual terminal
   // https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences
   DWORD dwMode;
   HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
   GetConsoleMode(hOutput, &dwMode);
   //printf("%i", dwMode);
   dwMode |= ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
   //printf("%i", dwMode);
   // if fonction return false, disable autocompletion
   bAutoCompletion = SetConsoleMode(hOutput, dwMode);
   if (bAutoCompletion == CK_FALSE)
   {
      printf("Cannot set virtual terminal processing. Auto complete disabled\n");
      P_ConsoleFunction pConsole_RequestString = &Console_RequestString;
   }
#else
   // disable auto completion with linux
   P_ConsoleFunction pConsole_RequestString = &Console_RequestString;
#endif

   // Set the list of command for auto completion
   Console_SetAutocompleteList((CK_CHAR_PTR*)&sAutocompletion, DIM(sAutocompletion));

   // Init command parser with console list of command
   parser_Init((PARSER_COMMAND*)kmu_console_list, MAX_CONSOLE_COMMAND_NUMBER);

   // init p11 library
   if (P11_LoadLibrary() == CK_FALSE)
   {
      return CK_FALSE;
   }

   // display help
   parser_CommandHelp();

   // Set the exit flag to false
   bExitFlag = CK_FALSE;

   // loop while the exit flag is not set
   do
   {
      printf("\nEnter command:\n");
      printf("kmu:> ");

      // wait for command in the console
      if (pConsole_RequestString() < 0)
      {
         // stop
         break;
      }

      // check command from the console
      sCommandArgNumber = kmu_CheckConsoleCommand(Console_GetBuffer());
      if (sCommandArgNumber > 0)
      {
         // Check the command
         if (parser_CommandParser(sCommandArgNumber, pConsoleArgList) == CK_TRUE)
         {
            printf("\n");
            // if command valid, execute the command
            parser_ExecuteCommand(CK_TRUE);
         }
      }

   } while (bExitFlag == CK_FALSE);

   // Set exit message
   printf("Thanks for using KMU\n");

   return bExitFlag;
}

/*
    FUNCTION:        CK_CHAR_PTR kmu_CheckArgAndGetNext(CK_CHAR_PTR sCurrentArg)
*/
CK_CHAR_PTR kmu_CheckArgAndGetNext(CK_CHAR_PTR sCurrentArg)
{
   CK_CHAR_PTR sNextSpace = NULL;
   CK_CHAR_PTR sFirstNextQuote;
   CK_CHAR_PTR sSecondNextQuote;
   CK_BBOOL    bIsFoundSpace = CK_FALSE;

   do
   {
      // Get the next space in the string
      sNextSpace = strchr(sCurrentArg, strSpace);

#ifdef OS_WIN32 // only for windows ? what is the behavior with linux ?
      // Search for first next quote
      sFirstNextQuote = strchr(sCurrentArg, strQuote);

      // If found it, search for a second next quote
      if (sFirstNextQuote != NULL)
      {
         // if the space is after the quote, search for a second quote
         // example defore : -slot="c:\Temp\file name.txt"
         // example after  : -slot=c:\Temp\file name.txt
         // and return the arg after for next space
         // if sNextSpace == null, means last argument potentially with a quote
         if ((sNextSpace == NULL) || (sNextSpace >= sFirstNextQuote))
         {
            // search second next quote
            sSecondNextQuote = strchr(&sFirstNextQuote[1], strQuote);

            // if the second quote is not null remove the quote
            if (sSecondNextQuote != NULL)
            {
               str_RemoveQuotes(sCurrentArg, (CK_ULONG)(sSecondNextQuote - sCurrentArg));

               if (sNextSpace != NULL)
               {
                  // return the address after the second quote
                  sNextSpace = &sSecondNextQuote[1];
               }
            }
         }
      }

#endif
      // if next is null, return
      if (sNextSpace == NULL)
      {
         break;
      }

      // remove leading space of the next argument
      sNextSpace = str_RemoveLeadingSpace(sNextSpace);

   } while (FALSE);

   // no quote, return next space by default
   return sNextSpace;
}

/*
    FUNCTION:        CK_LONG kmu_CheckConsoleCommand(CK_CHAR_PTR sCommand)
*/
CK_LONG kmu_CheckConsoleCommand(CK_CHAR_PTR sCommand)
{
   CK_LONG        uCommandStringLength;
   CK_LONG        uCommandCurrentLength = 0;
   CK_LONG        uCommandArgNumber = 0;
   CK_CHAR_PTR    sNextArg;
   CK_CHAR_PTR    sCurrentArg = sCommand;

   // check if command not null
   if (sCommand == NULL)
   {
      return -1;
   }

#ifdef _DEBUG
   // clear pConsoleArgList array
   memset(pConsoleArgList, 0, sizeof(pConsoleArgList));
#endif

   // removre leading space if any
   sCommand = str_RemoveLeadingSpace(sCommand);

   // get the length of the string
   uCommandStringLength = (CK_LONG)strlen(sCommand);

   if (uCommandStringLength > 0)
   {
      sNextArg = sCommand;

      do
      {
         // if next arg is not empty string, Should not happen normally
         if (sNextArg[0] != 0)
         {
            // add the string in the table
            pConsoleArgList[uCommandArgNumber] = sNextArg;
            uCommandArgNumber++;

            // check no overflow in the table
            if (uCommandArgNumber > MAX_CONSOLE_ARG_LIST)
            {
               return -2;
            }
         }

         // Set current arg as existing string
         sCurrentArg = sNextArg;

         // Check current argument, remove quote and space, and get next
         sNextArg = kmu_CheckArgAndGetNext(sNextArg);

         // if not space, stop the loop
         if (sNextArg == NULL)
         {
            break;
         }

         // increment size of string, approximative length here if there are space or quote in argument
         uCommandCurrentLength += (CK_LONG)strlen(sCurrentArg) + 1;

      } while (uCommandCurrentLength < uCommandStringLength);
   }
   return uCommandArgNumber;
}


/*
    FUNCTION:        CK_BBOOL kmu_exitConsole()
*/
CK_BBOOL kmu_exitConsole()
{
   // Set exit flag to true
   bExitFlag = CK_TRUE;
   return CK_TRUE;
}

