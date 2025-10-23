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

#ifndef _ASN1_H_
#define _ASN1_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _ASN1_C
#define _EXT
#else
#define _EXT extern
#endif


   _EXT  CK_BBOOL       asn1_Build_RSApublicKeyInfo(RSA_PUBLIC_KEY * sRsaPublicKey);
   _EXT  CK_BBOOL       asn1_Build_ECpublicKeyInfo(EC_PUBLIC_KEY* sEcdsaPublicKey, CK_KEY_TYPE ckKeyType);
   _EXT  CK_BBOOL       asn1_Check_DSApublicKeyInfo(DSA_PUBLIC_KEY* sDsaPublicKey, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       asn1_Check_DHpublicKeyInfo(DH_PUBLIC_KEY* sDhPublicKey, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       asn1_Check_MLDSApublicKeyInfo(ML_DSA_PUBLIC_KEY* sMlDsaPublicKey, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       asn1_Build_Init();
   _EXT  CK_ULONG       asn1_Build_tlv(CK_BYTE tag, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_ULONG       asn1_Build_tlv_Long(CK_BYTE tag, CK_ULONG Value);
   _EXT  CK_ULONG       asn1_Build_tl(CK_BYTE tag, CK_ULONG size);
   _EXT  CK_ULONG       asn1_Build_t(CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_ULONG       asn1_BuildNullByte();
   _EXT  CK_CHAR_PTR    asn1_BuildGetBuffer();
   _EXT  CK_ULONG       asn1_GetBufferSize();

   _EXT  CK_BBOOL       asn1_Check_RSApublicKeyInfo(RSA_PUBLIC_KEY* sRsaPublicKey, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       asn1_Check_ECpublicKeyInfo(EC_PUBLIC_KEY* sECPublicKey, CK_CHAR_PTR data, CK_ULONG size, CK_KEY_TYPE ckKeyType);
   _EXT  CK_BBOOL       asn1_Build_DHpublicKeyInfo(DH_PUBLIC_KEY* sDHPublicKey);
   _EXT  CK_BBOOL       asn1_Build_DSApublicKeyInfo(DSA_PUBLIC_KEY* sDSAPublicKey);
   _EXT  CK_BBOOL       asn1_Build_MLDSApublicKeyInfo(ML_DSA_PUBLIC_KEY* sMLDSAPublicKey);
   _EXT  CK_BBOOL       asn1_Build_EncryptedPrivateKeyInfoPbkdf2(CK_PKCS5_PBKD2_ENC_PARAMS2* sPbkd2_param, CK_BYTE_PTR   pWrappedKey, CK_ULONG pulWrappedKeyLen);
   _EXT  void           asn1_Check_SetTlv(CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       asn1_Check_t(CK_BYTE tag);
   _EXT  CK_BBOOL       asn1_Check_tl(CK_BYTE tag);
   _EXT  CK_CHAR_PTR    asn1_Check_GetCurrentValueBuffer();
   _EXT  CK_CHAR_PTR    asn1_Check_GetCurrentTagBuffer();
   _EXT  CK_ULONG       asn1_Check_GetCurrentValueLen();
   _EXT  CK_ULONG       asn1_Check_GetCurrentTlvLen();
   _EXT  CK_BBOOL       asn1_Check_StepIn();
   _EXT  CK_BBOOL       asn1_Check_StepOut();
   _EXT  CK_BBOOL       asn1_Check_Next(CK_BYTE tag);
   _EXT  CK_BBOOL       asn1_Check_NoNextTlv();

#undef _EXT

#endif // _ASN1_H_