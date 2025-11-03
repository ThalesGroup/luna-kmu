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

#ifndef _PKCS8_H_
#define _PKCS8_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _PKCS8_C_
#define _EXT
#else
#define _EXT extern
#endif

   _EXT  CK_ULONG       pkcs8_DecodePublicKeyFromPem(CK_CHAR_PTR sPublicKey, CK_ULONG sPublicKeyLength);
   _EXT  CK_CHAR_PTR    pkcs8_EncodePublicKeyToPem(CK_CHAR_PTR sPublicKey, CK_ULONG sPublicKeyLength);
   _EXT  CK_CHAR_PTR    pkcs8_EncodeEncryptedPrivateKeyToPem(CK_CHAR_PTR sEncryptedPrivateKey, CK_ULONG sEncryptedPrivateKeyLength);
   _EXT  CK_ULONG       pkcs8_DecodeEncryptedPrivateKeyFromPem(CK_CHAR_PTR sEncryptedPrivateKey, CK_ULONG sEncryptedPrivateKeyLength);
   _EXT  CK_BBOOL       pksc8_Build_PublicKeyInfoRSA(RSA_PUBLIC_KEY* sRsaPublicKey);
   _EXT  CK_BBOOL       pksc8_Build_PublicKeyInfoEC(EC_PUBLIC_KEY* sEcdsaPublicKey, CK_KEY_TYPE ckKeyType);
   _EXT  CK_BBOOL       pksc8_Check_PublicKeyInfoDSA(DSA_PUBLIC_KEY* sDsaPublicKey, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       pksc8_Check_PublicKeyInfoDH(DH_PUBLIC_KEY* sDhPublicKey, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       pksc8_Check_PublicKeyInfoMLDSA(ML_DSA_PUBLIC_KEY* sMlDsaPublicKey, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       pksc8_Check_PublicKeyInfoMLKEM(ML_KEM_PUBLIC_KEY* sMlKemPublicKey, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       pkcs8_Check_EncryptedPrivateKeyInfoPbe(P11_PBE_ENC_PARAMS* sPbkd2, CK_CHAR_PTR data, CK_ULONG size);

   _EXT  CK_BBOOL       pksc8_Check_PublicKeyInfoRSA(RSA_PUBLIC_KEY* sRsaPublicKey, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       pksc8_Check_PublicKeyInfoEC(EC_PUBLIC_KEY* sECPublicKey, CK_CHAR_PTR data, CK_ULONG size, CK_KEY_TYPE ckKeyType);
   _EXT  CK_BBOOL       pksc8_Build_PublicKeyInfoDH(DH_PUBLIC_KEY* sDHPublicKey);
   _EXT  CK_BBOOL       pksc8_Build_PublicKeyInfoDSA(DSA_PUBLIC_KEY* sDSAPublicKey);
   _EXT  CK_BBOOL       pksc8_Build_PublicKeyInfoMLDSA(ML_DSA_PUBLIC_KEY* sMLDSAPublicKey);
   _EXT  CK_BBOOL       pksc8_Build_PublicKeyInfoMLKEM(ML_KEM_PUBLIC_KEY* sMLDSAPublicKey);
   _EXT  CK_BBOOL       pksc8_Build_EncryptedPrivateKeyInfoPbe(P11_PBE_ENC_PARAMS* sPbkd2_param);

#undef _EXT

#endif // _PKCS8_H_