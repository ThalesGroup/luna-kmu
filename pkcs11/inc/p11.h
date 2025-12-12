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

#ifndef _PKCS_11_H_
#define _PKCS_11_H_

#ifdef _PKCS_11_C
#define _EXT
#else
#define _EXT extern
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define DIM(a) (sizeof(a)/sizeof(a[0]))
#define MAX(x,y) ((x>y)?x:y)

#include "cryptoki_v2.h"

   typedef CK_CHAR  STRING_ARRAY[];

   typedef CK_BBOOL(*P_fCMD)(CK_BYTE);
   /* an unsigned value, at least 32 bits long */
   typedef long long CK_LONG_64;


   // wrap/unwrap param

#define DES_BLOCK_LENGTH            8
#define AES_BLOCK_LENGTH            16
#define DES_IV_LENGTH               8
#define AES_IV_LENGTH               16
#define AES_GCM_AUTH_TAG_LENGTH_96  96
#define AES_GCM_IV_MIN_LENGTH       12

#define DES_CMAC_LENGTH             8
#define AES_CMAC_LENGTH             16

#define AES_128_KEY_LENGTH          16
#define AES_192_KEY_LENGTH          24
#define AES_256_KEY_LENGTH          32

#define DES_KEY_LENGTH              8
#define DES2_KEY_LENGTH             16
#define DES3_KEY_LENGTH             24

#define SM4_KEY_LENGTH              16

#define GENERIC_KEY_MINIMUM_LENGTH     1
#define GENERIC_KEY__MAXIMUM_LENGTH     512

#define SLOT_MODE_LIST              -1

#define KEY_TYPE_DISPLAY            0x00000001
#define KEY_TYPE_GENKEY             0x00000002
#define KEY_TYPE_IMPORT_EXPORTKEY   0x00000004
#define KEY_TYPE_PBE                0x00000008
#define KEY_TYPE_DERIVEKEY          0x00000010
#define KEY_TYPE_ENCRYPT            0x00000020
#define KEY_TYPE_HASH               0x00000040
#define KEY_TYPE_MZMK               0x00000080
#define KEY_TYPE_DISPLAY_MEC        0x00000100

#define KCV_PKCS11                  0x01
#define KCV_PCI                     0x02
#define KCV_GP                      0x03
#define KCV_HMAC_256                0x04

#define PBFKD2_DEFAULT_ITERATION    10000       // 
#define PBFKD2_SALT_LENGTH          16          // recommanded by NIST

#define ML_DSA_44_PUBLIC_KEY_SIZE            1312
#define ML_DSA_65_PUBLIC_KEY_SIZE            1952
#define ML_DSA_87_PUBLIC_KEY_SIZE            2592

#define ML_DSA_44_PRIVATE_KEY_SIZE           2420
#define ML_DSA_65_PRIVATE_KEY_SIZE           3309
#define ML_DSA_87_PRIVATE_KEY_SIZE           4627

#define ML_KEM_512_PUBLIC_KEY_SIZE           800
#define ML_KEM_768_PUBLIC_KEY_SIZE           1184
#define ML_KEM_1024_PUBLIC_KEY_SIZE          1568

#define ML_KEM_512_PRIVATE_KEY_SIZE          2420
#define ML_KEM_768_PRIVATE_KEY_SIZE          3309
#define ML_KEM_1024_PRIVATE_KEY_SIZE         4627


#define CKK_LMS                              (CKK_HSS | CKK_VENDOR_DEFINED)
#define DEFAULT_LMS_LEVEL                    1
#define MAX_HSS_LEVEL                        8

#define CK_KEY_NOT_FOUND                     (-2)


   typedef struct ck_des_param
   {
      CK_CHAR_PTR             pIv;           /* must be first position*/
      CK_ULONG                ulIvLen;
   }P11_DES_PARAM;


   typedef struct ck_aes_param
   {
      CK_CHAR_PTR             pIv;           /* must be first position*/
      CK_ULONG                ulIvLen;
   }P11_AES_PARAM;


   typedef struct P11_PBFKD2_ENC_PARAMS
   {
      CK_CHAR                 sIV[AES_IV_LENGTH];
      CK_CHAR                 sSalt[PBFKD2_SALT_LENGTH];
      CK_PKCS5_PBKD2_PARAMS2  pbfkd2_param;
   } P11_PKCS5_PBKD2_ENC_PARAMS2;

   typedef P11_PKCS5_PBKD2_ENC_PARAMS2 CK_PTR CK_PKCS5_PBKD2_ENC_PARAMS2_PTR;

   typedef struct p11_pbe_enc_algo
   {
      CK_CHAR_PTR             pIv;           /* must be first position*/
      CK_ULONG                ulIvLen;
      CK_MECHANISM_TYPE       ckPbeMechType;
      CK_OBJECT_CLASS         sEncClass;
      CK_KEY_TYPE             sEnckeyType;
      CK_MECHANISM_TYPE       ckEncMechType;
      CK_LONG                 sEnckeySize;
      CK_CHAR_PTR             pWrappedKey;
      CK_ULONG                ulWrappedKeyLen;
      union
      {
         P11_PKCS5_PBKD2_ENC_PARAMS2  pbkdf2;
      };
   }P11_PBE_ENC_PARAMS;

   typedef P11_PBE_ENC_PARAMS CK_PTR P11_PBE_ENC_PARAMS_PTR;

   typedef struct p11_EncryptAlgo
   {
      CK_ULONG          uFlag;
      CK_CHAR_PTR       sMechName;
      CK_MECHANISM_TYPE ckMechType;
      union
      {
         P11_DES_PARAM              des_param;
         P11_AES_PARAM              aes_param;
         CK_GCM_PARAMS              aes_gcm_param;
         P11_PBE_ENC_PARAMS         pbe_param;
         CK_RSA_PKCS_OAEP_PARAMS    rsa_oeap_param;
         CK_RSA_AES_KEY_WRAP_PARAMS rsa_aes_wrap; // not supported by luna
      };
   }P11_ENCRYPTION_MECH;

   typedef struct p11_SignAlgo
   {
      CK_ULONG          uFlag;
      CK_CHAR_PTR       sMechName;
      CK_MECHANISM_TYPE ckMechType;
      union
      {
         P11_DES_PARAM   des_param;
         P11_AES_PARAM   aes_param;
         CK_MAC_GENERAL_PARAMS  macGeneralParams;
      };
   }P11_SIGN_MECH;

   typedef struct p11_derivemech
   {
      CK_CHAR_PTR sMechName;
      CK_MECHANISM_TYPE ckMechType;
      union
      {
         CK_ECDH1_DERIVE_PARAMS       sEcdh1DeriveParams;
         CK_ECDH2_DERIVE_PARAMS       sEcdh2DeriveParams;
         CK_X9_42_DH1_DERIVE_PARAMS   sx942DhDeriveParams;
         CK_PRF_KDF_PARAMS            sPrfKdfParams;

      };
   }P11_DERIVE_MECH;

   typedef struct p11_kdf_type
   {
      CK_CHAR_PTR       sKdfMechType;
      CK_KDF_PRF_TYPE   cKdfMechType;
   }P11_KDF_TYPE;

   typedef struct p11_kcv_type
   {
      CK_CHAR_PTR       sKCVMechType;
      CK_BYTE           cKCVMethod;
   }P11_KCV_TYPE;

   typedef struct p11_attr_type
   {
      CK_CHAR_PTR          sAttributeType;
      CK_ATTRIBUTE_TYPE    cAttributeType;
   }P11_ATTR_TYPE;

   typedef struct p11_kdf_scheme
   {
      CK_CHAR_PTR                   sKdfScheme;
      CK_KDF_PRF_ENCODING_SCHEME    cKdfScheme;
   }P11_KDF_SCHEME;

   typedef struct p11_HashAlgo
   {
      CK_CHAR_PTR       sHashName;
      CK_MECHANISM_TYPE ckMechType;
      CK_MECHANISM_TYPE ckMechOaepMgfType;
      CK_ULONG          uFlag;
   }P11_HASH_MECH;


   typedef struct P11_eddsa_oid_convert {
      const CK_LONG uOidStdLength;
      const CK_CHAR_PTR sOidStd;
      const CK_LONG uOidLengthHSM;
      const CK_CHAR_PTR sOidHSM;
   }P11_EDDSA_OID_CONVERT;

   typedef struct P11_ecc_oid {
      const CK_KEY_TYPE cktype;
      const CK_CHAR_PTR sCurveName;
      const CK_LONG oidLen;
      const CK_CHAR_PTR oid;
   }P11_ECC_OID;

   typedef struct P11_rsa_exp {
      const CK_CHAR_PTR sExpName;
      const CK_LONG expLen;
      const CK_CHAR_PTR exp;
   }P11_RSA_EXP;
   
   typedef struct P11_exp_domain {
      CK_CHAR_PTR sPrime;
      CK_LONG uPrimeLength;
      CK_CHAR_PTR sBase;
      CK_LONG uBaseLength;
      CK_CHAR_PTR sSubPrime;
      CK_LONG uSubPrimeLength;
      CK_BBOOL bIsSubPrime;
   }P11_EXP_DOMAIN;

   typedef struct rsapublickey
   {
      CK_CHAR_PTR sModulus;
      CK_ULONG    uModulusLength;
      CK_CHAR_PTR sExponent;
      CK_ULONG    uExponentLength;
   }RSA_PUBLIC_KEY;

   typedef struct dsapublickey
   {
      CK_CHAR_PTR sPublicKey;
      CK_ULONG    uPublicKeyLength;
      P11_EXP_DOMAIN sDomain;
   }DSA_PUBLIC_KEY;

   typedef struct dhpublickey
   {
      CK_CHAR_PTR sPublicKey;
      CK_ULONG    uPublicKeyLength;
      P11_EXP_DOMAIN sDomain;
   }DH_PUBLIC_KEY;

   typedef struct eccpublickey
   {
      CK_CHAR_PTR sPublicPoint;
      CK_ULONG    uPublicPointLength;
      CK_CHAR_PTR sOid;
      CK_ULONG    uOidSize;
   }EC_PUBLIC_KEY;

   typedef struct mldsapublickey
   {
      CK_CHAR_PTR                   sPublicKey;
      CK_ULONG                      uPublicKeyLength;
      CK_ML_DSA_PARAMETER_SET_TYPE  uML_DSA_Parameter_Set;
   }ML_DSA_PUBLIC_KEY;

   typedef struct mlkempublickey
   {
      CK_CHAR_PTR                   sPublicKey;
      CK_ULONG                      uPublicKeyLength;
      CK_ML_KEM_PARAMETER_SET_TYPE  uML_KEM_Parameter_Set;
   }ML_KEM_PUBLIC_KEY;

   typedef struct lms_publickey
   {
      CK_CHAR_PTR                            sPublicKey;
      CK_ULONG                               uPublicKeyLength;
      CK_HSS_LEVELS                          uHSS_Levels;
      CK_LMS_TYPE                            uLmsType;
      CK_LMOTS_TYPE                          uLmotsType;
   }LMS_PUBLIC_KEY;

   typedef union publickey
   {
      RSA_PUBLIC_KEY       sRsaPublicKey;
      DSA_PUBLIC_KEY       sDsaPublicKey;
      DH_PUBLIC_KEY        sDhPublicKey;
      EC_PUBLIC_KEY        sEcPublicKey;
      ML_DSA_PUBLIC_KEY    sMlDsaPublicKey;
      ML_KEM_PUBLIC_KEY    sMlKemPublicKey;
      LMS_PUBLIC_KEY       sLmsPublicKey;
   }PUBLIC_KEY;

   typedef struct p11_ml_dsa_key_size
   {
      CK_ULONG                               sPublicKeySize;
      CK_ULONG                               sPrivateKeySize;
      CK_ML_DSA_PARAMETER_SET_TYPE           uML_DSA_Parameter_Set;
      CK_CHAR_PTR                            sName;
   }P11_ML_DSA_KEY;

   typedef struct p11_ml_kem_key
   {
      CK_ULONG                               sPublicKeySize;
      CK_ULONG                               sPrivateKeySize;
      CK_ML_DSA_PARAMETER_SET_TYPE           uML_KEM_Parameter_Set;
      CK_CHAR_PTR                            sName;
   }P11_ML_KEM_KEY;



   typedef struct p11_hss_key
   {
      CK_HSS_LEVELS                          uHSS_Levels;
      CK_LMS_TYPE                            uLmsType[MAX_HSS_LEVEL];
      CK_LMOTS_TYPE                          uLmotsType[MAX_HSS_LEVEL];
   }P11_HSS_KEY;
   

   // key atributes template
   typedef struct P11_keyattributes
   {
      CK_BBOOL             bCKA_Token;
      CK_BBOOL             bCKA_Private;
      CK_BBOOL             bCKA_Sensitive;
      CK_BBOOL             bCKA_Encrypt;
      CK_BBOOL             bCKA_Decrypt;
      CK_BBOOL             bCKA_Sign;
      CK_BBOOL             bCKA_Verify;
      CK_BBOOL             bCKA_Derive;
      CK_BBOOL             bCKA_Wrap;
      CK_BBOOL             bCKA_Unwrap;
      CK_BBOOL             bCKA_Extractable;
      CK_BBOOL             bCKA_Modifiable;
      CK_CHAR_PTR          pLabel;
      CK_CHAR_PTR          pCKA_ID;
      CK_LONG              uCKA_ID_Length;
   }P11_KEYATTRIBUTES;

   // derive template
   typedef struct P11_derivetemplate
   {
      CK_OBJECT_HANDLE     hMasterKey;
      CK_OBJECT_CLASS      sDerivedClass;
      CK_KEY_TYPE          sderivedKeyType;
      CK_LONG              sderivedKeyLength;
      CK_CHAR_PTR          pDerivedKeyLabel;
      CK_BBOOL             bCKA_Token;
      CK_BBOOL             bCKA_Private;
      CK_BBOOL             bCKA_Sensitive;
      CK_BBOOL             bCKA_Encrypt;
      CK_BBOOL             bCKA_Decrypt;
      CK_BBOOL             bCKA_Sign;
      CK_BBOOL             bCKA_Verify;
      CK_BBOOL             bCKA_Derive;
      CK_BBOOL             bCKA_Wrap;
      CK_BBOOL             bCKA_Unwrap;
      CK_BBOOL             bCKA_Extractable;
      CK_BBOOL             bCKA_Modifiable;
      CK_CHAR_PTR          pCKA_ID;
      CK_ULONG             uCKA_ID_Length;
      P11_DERIVE_MECH*     sDeriveMech;
   }P11_DERIVETEMPLATE;

   // unwrap template
   typedef struct P11_unwraptemplate
   {
      CK_OBJECT_CLASS      sClass;
      CK_KEY_TYPE          skeyType;
      CK_LONG              skeySize;
      CK_CHAR_PTR          pKeyLabel;
      CK_BBOOL             bCKA_Token;
      CK_BBOOL             bCKA_Private;
      CK_BBOOL             bCKA_Sensitive;
      CK_BBOOL             bCKA_Encrypt;
      CK_BBOOL             bCKA_Decrypt;
      CK_BBOOL             bCKA_Sign;
      CK_BBOOL             bCKA_Verify;
      CK_BBOOL             bCKA_Derive;
      CK_BBOOL             bCKA_Wrap;
      CK_BBOOL             bCKA_Unwrap;
      CK_BBOOL             bCKA_Encapsulate;
      CK_BBOOL             bCKA_Decapsulate;
      CK_BBOOL             bCKA_Extractable;
      CK_BBOOL             bCKA_Modifiable;
      CK_CHAR_PTR          pCKA_ID;
      CK_ULONG             uCKA_ID_Length;
      CK_OBJECT_HANDLE     hWrappingKey;
      CK_BBOOL             bPbe;
      P11_ENCRYPTION_MECH* wrapmech;
   }P11_UNWRAPTEMPLATE;

   // wrap template
   typedef struct P11_wraptemplate
   {
      CK_OBJECT_CLASS      sClass;
      CK_KEY_TYPE          skeyType;
      CK_OBJECT_HANDLE     hKeyToExport;
      CK_OBJECT_HANDLE     hWrappingKey;
      CK_CHAR_PTR          pKeyLabel;
      CK_BBOOL             bPbe;
      P11_ENCRYPTION_MECH* wrap_key_mech;
   }P11_WRAPTEMPLATE;

   // encrypt template
   typedef struct P11_encryptemplate
   {
      CK_OBJECT_CLASS      sClass;
      CK_KEY_TYPE          skeyType;
      CK_OBJECT_HANDLE     hEncyptiontKey;
      P11_ENCRYPTION_MECH* encryption_mech;
      CK_CHAR_PTR          sInputData;
      CK_ULONG             sInputDataLength;

   }P11_ENCRYPT_TEMPLATE;

   // encrypt template
   typedef struct P11_signaturetemplate
   {
      CK_OBJECT_CLASS      sClass;
      CK_KEY_TYPE          skeyType;
      CK_OBJECT_HANDLE     hSignatureKey;
      P11_SIGN_MECH*       sign_mech;
      CK_CHAR_PTR          sInputData;
      CK_ULONG             sInputDataLength;

   }P11_SIGNATURE_TEMPLATE;

   // keygen template
   typedef struct P11_keygentemplate 
   {
      CK_OBJECT_CLASS      sClass;
      CK_OBJECT_CLASS      sClassPublic;
      CK_KEY_TYPE          skeyType;
      CK_LONG              skeySize;
      CK_CHAR_PTR          pKeyLabel;
      CK_CHAR_PTR          pKeyLabelPrivate;
      CK_CHAR_PTR          pKeyLabelPublic;
      CK_LONG              sKeyGenMech;
      union {
         P11_RSA_EXP*      pKeyPublicExp;
         P11_ECC_OID*      pECCurveOID;
         P11_EXP_DOMAIN*   pDHDomain;
         P11_EXP_DOMAIN*   pDSADomain;
         P11_ML_DSA_KEY*   pML_DSA;
         P11_ML_KEM_KEY*   pML_KEM;
         P11_HSS_KEY       pHSS;
      };
      CK_BBOOL             bCKA_Token;
      CK_BBOOL             bCKA_Private;
      CK_BBOOL             bCKA_Sensitive;
      CK_BBOOL             bCKA_Encrypt;
      CK_BBOOL             bCKA_Decrypt;
      CK_BBOOL             bCKA_Sign;
      CK_BBOOL             bCKA_Verify;
      CK_BBOOL             bCKA_Derive;
      CK_BBOOL             bCKA_Wrap;
      CK_BBOOL             bCKA_Unwrap;
      CK_BBOOL             bCKA_Encapsulate;
      CK_BBOOL             bCKA_Decapsulate;
      CK_BBOOL             bCKA_Extractable;
      CK_BBOOL             bCKA_Modifiable;
      CK_CHAR_PTR          pCKA_ID;
      CK_LONG              uCKA_ID_Length;
   }P11_KEYGENTEMPLATE;

   // unwrap template
   typedef struct P11_dotemplate
   {
      CK_BBOOL             bCKA_Token;
      CK_BBOOL             bCKA_Private;
      CK_BBOOL             bCKA_Modifiable;
      CK_CHAR_PTR          pLabel;
      CK_CHAR_PTR          pApplication;
      CK_LONG              uApplicationLength;
      CK_CHAR_PTR          pValue;
      CK_LONG              upValueLength;

   }P11_DOTEMPLATE;

   // key atributes template
   typedef struct P11_upddatekeyattributes
   {
      CK_BBOOL             bCKA_Token;
      CK_BBOOL             bCKA_Private;
      CK_BBOOL             bCKA_Sensitive;
      CK_BBOOL             bCKA_Encrypt;
      CK_BBOOL             bCKA_Decrypt;
      CK_BBOOL             bCKA_Sign;
      CK_BBOOL             bCKA_Verify;
      CK_BBOOL             bCKA_Derive;
      CK_BBOOL             bCKA_Wrap;
      CK_BBOOL             bCKA_Unwrap;
      CK_BBOOL             bCKA_Extractable;
      CK_BBOOL             bCKA_Modifiable;
      CK_BBOOL             bLabel;
      CK_BBOOL             bCKA_ID;
   }P11_UPDATEKEYATTRIBUTES;


   _EXT  CK_RV                P11_Login(CK_SLOT_ID ckSlot, CK_CHAR_PTR sPassword, CK_BBOOL bISCryptoUser);
   _EXT  CK_RV                P11_Logout();
   _EXT  CK_BBOOL             P11_IsLoggedIn();
   _EXT  CK_LONG              P11_ListStot();
   _EXT  CK_BBOOL             p11_GetSlotInfo(CK_SLOT_ID u32_SlotID, CK_SLOT_INFO* slotInfo);
   _EXT  CK_BBOOL             p11_GetMecanismInfo(CK_SLOT_ID u32_SlotID, CK_MECHANISM_TYPE sMech, CK_MECHANISM_INFO* info);
   _EXT  CK_BBOOL             P11_IsLoginPasswordRequired(void);
   _EXT  CK_BBOOL             P11_FindAllObjects(CK_LONG uLimit);
   _EXT  CK_BBOOL             P11_DeleteObject(CK_OBJECT_HANDLE Handle);
   _EXT  CK_BBOOL             P11_GetAttributes(CK_OBJECT_HANDLE Handle);
   _EXT  CK_BBOOL             P11_GetAttributesArray(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute, CK_CHAR_PTR * pArray, CK_ULONG_PTR pArrayLength);
   _EXT  CK_BBOOL             P11_SetAttributeString(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE ctype, CK_CHAR_PTR sStringValue);
   _EXT  CK_BBOOL             P11_SetAttributeArray(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute, CK_CHAR_PTR sStringValue, CK_ULONG uStringLength);
   _EXT  CK_BBOOL             P11_SetAttributeBoolean(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute, CK_BBOOL bValue);
   _EXT  CK_BBOOL             P11_GenerateKey(P11_KEYGENTEMPLATE* sKeyGenTemplate, CK_OBJECT_HANDLE_PTR hKey, CK_BBOOL bDisplay);
   _EXT  CK_OBJECT_HANDLE     P11_ImportClearSymetricKey(P11_UNWRAPTEMPLATE* sKeyGenTemplate, CK_CHAR_PTR pbClearKey, CK_ULONG lKeyLength);
   _EXT  CK_OBJECT_HANDLE     P11_GenerateAESWrapKey(CK_BBOOL bTokenKey, CK_LONG sSymkeySize, CK_CHAR_PTR pLabel);
   _EXT  CK_BBOOL             P11_GenerateKeyPair(P11_KEYGENTEMPLATE* sKeyGenTemplate, CK_OBJECT_HANDLE_PTR hPrivateKey, CK_OBJECT_HANDLE_PTR hPublicKey, CK_BBOOL bDisplay);
   _EXT  CK_BBOOL             P11_GenerateKeyPbe(P11_KEYGENTEMPLATE* sKeyGenTemplate, CK_OBJECT_HANDLE_PTR hKey, P11_PBE_ENC_PARAMS* pbkdf2, CK_BBOOL bDisplay);
   _EXT  CK_BBOOL             P11_CreateDO(P11_DOTEMPLATE* sDOTemplate);
   _EXT  CK_BBOOL             P11_WrapPrivateSecretKey(P11_WRAPTEMPLATE* sWrapTemplate, CK_BYTE_PTR   pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
   _EXT  CK_BBOOL             P11_UnwrapPrivateSecretKey(P11_UNWRAPTEMPLATE* sUnWrapTemplate, CK_CHAR_PTR pWrappedKey, CK_LONG pulWrappedKeyLen, CK_OBJECT_HANDLE* hKey);
   _EXT  CK_BBOOL             P11_DeriveKey(P11_DERIVETEMPLATE* sDeriveTemplate, CK_OBJECT_HANDLE_PTR hKey, CK_BBOOL bDisplay);
   _EXT  CK_BBOOL             P11_DeriveKeyAndWrap(P11_DERIVETEMPLATE* sDeriveTemplate, P11_WRAPTEMPLATE* sWrapTemplate, CK_BYTE_PTR * pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
   _EXT  CK_BBOOL             P11_KeyAgreement(CK_OBJECT_HANDLE hPrivateKey, CK_BYTE_PTR sPublicData, CK_ULONG sPublicDataSize, CK_BYTE_PTR* sSharedSecret, CK_ULONG_PTR sSharedSecretLength);
   _EXT  CK_BBOOL             P11_CreatePublicKey(P11_UNWRAPTEMPLATE* sImportPublicKeyTemplate, PUBLIC_KEY* sPublicKey);
   _EXT  CK_BBOOL             P11_GetRsaPublicKey(CK_OBJECT_HANDLE Handle, RSA_PUBLIC_KEY* sRsaPublicKey);
   _EXT  CK_BBOOL             P11_GetEccPublicKey(CK_OBJECT_HANDLE Handle, EC_PUBLIC_KEY* eccpublickey, CK_KEY_TYPE ckTypeEc);
   _EXT  CK_BBOOL             P11_GetDsaPublicKey(CK_OBJECT_HANDLE Handle, DSA_PUBLIC_KEY* dsapublickey);
   _EXT  CK_BBOOL             P11_GetDHPublicKey(CK_OBJECT_HANDLE Handle, DH_PUBLIC_KEY* dhpublickey, CK_KEY_TYPE skeyType);
   _EXT  CK_BBOOL             P11_GetMLDSAPublicKey(CK_OBJECT_HANDLE Handle, ML_DSA_PUBLIC_KEY* smldsapublickey);
   _EXT  CK_BBOOL             P11_GetMLKEMPublicKey(CK_OBJECT_HANDLE Handle, ML_KEM_PUBLIC_KEY* smlkempublickey);
   _EXT  CK_BBOOL             P11_GetLMSPublicKey(CK_OBJECT_HANDLE Handle, LMS_PUBLIC_KEY* sLmspublickey);
   _EXT  CK_BBOOL             P11_EncryptData(P11_ENCRYPT_TEMPLATE* sEncryptTemplate, CK_CHAR_PTR* pEncryptedData, CK_ULONG_PTR pEncryptedDataLength);
   _EXT  CK_BBOOL             P11_DecryptData(P11_ENCRYPT_TEMPLATE* sEncryptTemplate, CK_CHAR_PTR* pDecryptedData, CK_ULONG_PTR pDecryptedDataLength);
   _EXT  CK_BBOOL             P11_SignData(P11_SIGNATURE_TEMPLATE* sSignTemplate, CK_CHAR_PTR* pSignauture, CK_ULONG_PTR pSignautureLength);
   _EXT  CK_BBOOL             P11_DigestKey(P11_HASH_MECH* sHash, CK_OBJECT_HANDLE  hKey);
   _EXT  CK_BBOOL             P11_ComputeKCV(CK_BYTE bKCVMethod, CK_OBJECT_HANDLE  hKey, CK_CHAR_PTR * pKcvBuffer);
   _EXT  CK_BBOOL             P11_BuildCKEncMecanism(P11_ENCRYPTION_MECH* encryption_mech, CK_MECHANISM_PTR  sEncMech);
   _EXT  CK_BBOOL             P11_GenerateRandom(CK_BYTE_PTR pbBuffer, CK_ULONG uLength);
   _EXT  void                 P11_Init();
   _EXT  CK_BBOOL             P11_LoadLibrary();
   _EXT  CK_BBOOL             P11_LoadFunctions();
   _EXT  CK_BBOOL             P11_LoadSfntExtensionFunctions();
   _EXT  void                 P11_Terminate();
   _EXT  CK_RV                P11_SelectStot(CK_SLOT_ID u32_SlotList);
   _EXT  CK_BBOOL             P11_FindKeyObject(CK_OBJECT_HANDLE Handle);
   _EXT  CK_OBJECT_HANDLE     P11_FindKeyObjectByLabelOrId(CK_CHAR_PTR sLabel, CK_CHAR_PTR sId);
   _EXT  CK_BBOOL             P11_FindObject(CK_OBJECT_HANDLE Handle);
   _EXT  CK_LONG              P11_GetObjectSize(CK_OBJECT_HANDLE Handle);
   _EXT  CK_OBJECT_CLASS      P11_GetObjectClass(CK_OBJECT_HANDLE Handle);
   _EXT  CK_KEY_TYPE          P11_GetKeyType(CK_OBJECT_HANDLE Handle);
   _EXT  CK_LONG              P11_GetKeyLength(CK_OBJECT_HANDLE Handle);
   _EXT  CK_BBOOL             P11_GetBooleanAttribute(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute);



#undef _EXT


#endif   /* _PKCS_11_H_ */