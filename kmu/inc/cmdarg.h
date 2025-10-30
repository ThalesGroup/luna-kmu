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

#ifndef _CMDARG_H_
#define _CMDARG_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _CMD_ARG_C
#define _EXT
#else
#define _EXT extern
#endif

#define ARG_TYPE_SLOT               0
#define ARG_TYPE_PASSWORD           1
#define ARG_TYPE_CKA_LABEL          2
#define ARG_TYPE_LABEL_PRIV         3
#define ARG_TYPE_LABEL_PUB          4
#define ARG_TYPE_KEYTYPE            5
#define ARG_TYPE_KEYSIZE            6
#define ARG_TYPE_PUBLIC_EXP         7
#define ARG_TYPE_KEYGEN_MECH        8
#define ARG_TYPE_CKA_ENCRYPT        9
#define ARG_TYPE_CKA_DECRYPT        10
#define ARG_TYPE_CKA_SIGN           11
#define ARG_TYPE_CKA_VERIFY         12
#define ARG_TYPE_CKA_DERIVE         13
#define ARG_TYPE_CKA_WRAP           14
#define ARG_TYPE_CKA_UNWRAP         15
#define ARG_TYPE_CKA_EXTRACTABLE    16
#define ARG_TYPE_CKA_MODIFIABLE     17
#define ARG_TYPE_CKA_TOKEN          18
#define ARG_TYPE_CKA_PRIVATE        19
#define ARG_TYPE_CKA_SENSITIVE      20
#define ARG_TYPE_CKA_ID             21
#define ARG_TYPE_ECC_CURVE          22
#define ARG_TYPE_HANDLE             23
#define ARG_TYPE_HANDLE_WRAPKEY     24
#define ARG_TYPE_HANDLE_UNWRAPKEY   25
#define ARG_TYPE_FILE_OUTPUT        26
#define ARG_TYPE_FILE_INPUT         27
#define ARG_TYPE_WRAP_ALGO          28
#define ARG_TYPE_UNWRAP_ALGO        29
#define ARG_TYPE_FORMAT_FILE        30
#define ARG_TYPE_KEYCLASS           31
#define ARG_TYPE_ALGO               32
#define ARG_TYPE_IV                 33
#define ARG_TYPE_RSA_OAEP_HASH      34
#define ARG_TYPE_GCM_AUTH_DATA      35
#define ARG_TYPE_GCM_TAG_LEN        36
#define ARG_TYPE_DH_PRIME           37
#define ARG_TYPE_DH_BASE            38
#define ARG_TYPE_DH_SUBPRIME        39
#define ARG_TYPE_DERIVE_MECH        40
#define ARG_TYPE_INFORM_FILE        41
#define ARG_TYPE_OUTFORM_FILE       42
#define ARG_TYPE_HANDLE_DERIVE      43
#define ARG_TYPE_HANDLE_DELETE      44
#define ARG_TYPE_HANDLE_EXPORT      45
#define ARG_TYPE_HANDLE_ENCRYPT     46
#define ARG_TYPE_HANDLE_DECRYPT     47
#define ARG_TYPE_HASH_KEY           48
#define ARG_TYPE_HANDLE_DIG_KEY     49
#define ARG_TYPE_CKA_VALUE          50
#define ARG_TYPE_CKA_APPLICATION    51
#define ARG_TYPE_KDF_TYPE           52
#define ARG_TYPE_KDF_SCHEME         53
#define ARG_TYPE_KDF_COUNTER        54
#define ARG_TYPE_KDF_LABEL          55
#define ARG_TYPE_KDF_CONTEXT        56
#define ARG_TYPE_HANDLE_KCV         57
#define ARG_TYPE_METHOD_KCV         58
#define ARG_TYPE_CRYPTO_USER        59
#define ARG_TYPE_KEY_COMP           60
#define ARG_TYPE_ATTR_NAME          61
#define ARG_TYPE_KEY_PASSWORD       62
#define ARG_TYPE_SALT               63
#define ARG_TYPE_ITERATION          64
#define ARG_TYPE_PRF                65
#define ARG_TYPE_LIMIT              66
#define ARG_TYPE_PBE                67

#define MASK_BINARY                 CK_TRUE
#define FILE_FORMAT_BINARY          (0x10 | MASK_BINARY)
#define FILE_FORMAT_TEXT            0x10
#define FILE_FORMAT_PKCS8           0x20
#define FILE_FORMAT_PKCS12          0x40
#define FILE_FORMAT_TR31            0x80

#define TYPE_KEY_SIZE_AES           0x01
#define TYPE_KEY_SIZE_DES           0x02
#define TYPE_KEY_SIZE_HMAC_GEN      0x03
#define TYPE_KEY_SIZE_RSA           0x04
#define TYPE_KEY_SIZE_MLDSA         0x05
#define TYPE_KEY_SIZE_MLKEM         0x06
#define TYPE_KEY_SIZE_MZMK          0x07


#define cmdarg_GetLabel(buffer, size)        cmdarg_SearchTypeString(ARG_TYPE_CKA_LABEL, buffer, size)
#define cmdarg_GetLabelPrivate(buffer, size) cmdarg_SearchTypeString(ARG_TYPE_LABEL_PRIV, buffer, size)
#define cmdarg_GetLabelPublic(buffer, size)  cmdarg_SearchTypeString(ARG_TYPE_LABEL_PUB, buffer, size)
#define cmdarg_GetValue(buffer)              cmdarg_SearchTypeHexString(ARG_TYPE_CKA_VALUE, buffer)
#define cmdarg_GetApp(buffer, size)          cmdarg_SearchTypeString(ARG_TYPE_CKA_APPLICATION, buffer, size)
#define cmdarg_GetCKAPrivate(p)              cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_PRIVATE, p, CK_TRUE)
#define cmdarg_GetCKASensitive(p)            cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_SENSITIVE, p, CK_TRUE)
#define cmdarg_GetCKAToken(p)                cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_TOKEN, p, CK_TRUE)
#define cmdarg_GetCKAEncrypt(p)              cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_ENCRYPT, p, CK_TRUE)
#define cmdarg_GetCKADecrypt(p)              cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_DECRYPT, p, CK_TRUE)
#define cmdarg_GetCKASign(p)                 cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_SIGN, p, CK_TRUE)
#define cmdarg_GetCKAVerify(p)               cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_VERIFY, p, CK_TRUE)
#define cmdarg_GetCKADerive(p)               cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_DERIVE, p, CK_TRUE)
#define cmdarg_GetCKAWrap(p)                 cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_WRAP, p, CK_TRUE)
#define cmdarg_GetCKAUnwrap(p)               cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_UNWRAP, p, CK_TRUE)
#define cmdarg_GetCKAModifiable(p)           cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_MODIFIABLE, p, CK_TRUE)
#define cmdarg_GetCKAExtractable(p)          cmdarg_SearchTypeBoolean(ARG_TYPE_CKA_EXTRACTABLE, p, CK_TRUE)
#define cmdarg_GetOutputFilePath(buf, size)  cmdarg_SearchTypeString(ARG_TYPE_FILE_OUTPUT, buf, size)
#define cmdarg_GetInputFilePath(buf, size)   cmdarg_SearchTypeString(ARG_TYPE_FILE_INPUT, buf, size)
#define cmdarg_ArgGetIV()                    cmdarg_SearchTypeString(ARG_TYPE_IV, NULL, 0)
#define cmdarg_GetGCMAuthData()              cmdarg_SearchTypeString(ARG_TYPE_GCM_AUTH_DATA, NULL, 0)
#define cmdarg_ArgGetSalt()                  cmdarg_SearchTypeString(ARG_TYPE_SALT, NULL, 0)
#define cmdarg_GetGCMAuthTagLen()            cmdarg_SearchTypeInteger(ARG_TYPE_GCM_TAG_LEN)
#define cmdarg_GetHash()                     cmdarg_SearchHash(ARG_TYPE_HASH_KEY)
#define cmdarg_Limit()                       cmdarg_SearchTypeInteger(ARG_TYPE_LIMIT)
#define cmdarg_GetIteration()                cmdarg_SearchTypeInteger(ARG_TYPE_ITERATION)

   _EXT  CK_CHAR_PTR             cmdarg_GetPassword();
   _EXT  CK_SLOT_ID              cmdarg_GetSlotID();
   _EXT  CK_BBOOL                cmdarg_SearchTypeBoolean(BYTE bArgType, CK_BBOOL* bOutValue, CK_BBOOL bdefaultValue);
   _EXT  CK_BYTE                 cmdarg_SearchFileFormat(BYTE bArgType);
   _EXT  CK_OBJECT_CLASS         cmdarg_GetKeyClass();
   _EXT  CK_KEY_TYPE             cmdarg_GetKeytype(CK_BBOOL bForceRequest, CK_ULONG uFlag);
   _EXT  CK_OBJECT_CLASS         cmdarg_GetClassFromkeyType(CK_ULONG uFlag);
   _EXT  CK_OBJECT_HANDLE        cmdarg_GetHandleValue(CK_BYTE bArgType);
   _EXT  CK_CHAR_PTR             cmdarg_SearchTypeString(CK_BYTE bLabelType, CK_CHAR_PTR sBuffer, CK_ULONG sBufferSize);
   _EXT  CK_LONG                 cmdarg_SearchTypeHexString(BYTE bArgType, CK_CHAR_PTR* sHexString);
   _EXT  CK_LONG                 cmdarg_GetKeySize(CK_ULONG uKeyType);
   _EXT  P11_RSA_EXP*            cmdarg_GetPublicExponant();
   _EXT  CK_MECHANISM_TYPE       cmdarg_GetRSAGenMechParam();
   _EXT  CK_MECHANISM_TYPE       cmdarg_GetDHGenMechParam();
   _EXT  P11_ECC_OID*            cmdarg_ArgGetEcCurveOIDParam(CK_KEY_TYPE sKeyType);
   _EXT  P11_EXP_DOMAIN*         cmdarg_GetExpDomain(CK_BBOOL bIsSubPrime);
   _EXT  P11_ENCRYPTION_MECH*    cmdarg_SearchEncryptionAlgoValue(BYTE bArgType);
   _EXT  P11_HASH_MECH*          cmdarg_SearchHash(BYTE bArgType);
   _EXT  P11_DERIVE_MECH*        cmdarg_SearchDerivationAlgoValue(BYTE bArgType);
   _EXT  P11_DERIVE_MECH*        cmdarg_GetDerivationMecansim(BYTE bArgType);
   _EXT  P11_ENCRYPTION_MECH*    cmdarg_GetEncryptionMecansim(BYTE bArgType);
   _EXT  P11_ENCRYPTION_MECH*    cmdarg_GetPBEMecansim();
   _EXT  CK_KDF_PRF_TYPE         cmdarg_GetKdfType();
   _EXT  CK_KDF_PRF_ENCODING_SCHEME cmdarg_GetKdfScheme();
   _EXT  CK_LONG_64              cmdarg_GetKdfCounter();
   _EXT  CK_LONG                 cmdarg_SearchTypeInteger(CK_BYTE bArgType);
   _EXT  CK_LONG                 cmdarg_SearchTypeUnsignedInteger(CK_BYTE bArgType);
   _EXT  CK_LONG                 cmdarg_GetCKA_ID(CK_CHAR_PTR sCkaId, CK_ULONG sBufferSize);
   _EXT  BYTE                    cmdarg_GetKCVMethod();
   _EXT  CK_ATTRIBUTE_TYPE       cmdarg_AttributeType();
   _EXT  CK_BBOOL                cmdarg_isCryptoUserLoginRequested();
   _EXT  CK_LONG                 cmdarg_GetCompomentsNumber();
   _EXT  CK_CHAR_PTR             cmdarg_GetKeyPassword();

#undef _EXT

#endif // _CMDARG_H_