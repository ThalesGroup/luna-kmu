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

#ifndef _P11_STR_H_
#define _P11_STR_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _P11_UTIL_C_
#define _EXT
#else
#define _EXT extern
#endif

   _EXT  CK_CHAR_PTR                   P11Util_DisplayClassName(CK_OBJECT_CLASS u32Class);
   _EXT  CK_CHAR_PTR                   P11Util_DisplayBooleanName(CK_BBOOL ckbool);
   _EXT  P11_ECC_OID*                  P11Util_GetEcCurveOIDParam(CK_CHAR_PTR sKeyType);
   _EXT  P11_ECC_OID*                  P11Util_GetEcCurveOID(CK_CHAR_PTR sOid, CK_ULONG sOID_Size);
   _EXT  CK_MECHANISM_TYPE             P11Util_GetRSAGenMechParam(CK_CHAR_PTR sKeyType);
   _EXT  CK_MECHANISM_TYPE             P11Util_GetDHGenMechParam(CK_CHAR_PTR sKeyType);
   _EXT  P11_RSA_EXP*                  P11Util_GetPublicExpParam(CK_CHAR_PTR sPublicExp);
   _EXT  P11_ENCRYPTION_MECH*          P11Util_GetEncryptionParam(CK_CHAR_PTR sParamName, CK_ULONG    bKeyFlag);
   _EXT  P11_DERIVE_MECH*              P11Util_GetDerivationParam(CK_CHAR_PTR sParamName);
   _EXT  CK_KDF_PRF_TYPE               P11Util_GetKdfType(CK_CHAR_PTR sParamName);
   _EXT  CK_KDF_PRF_ENCODING_SCHEME    P11Util_GetKdfScheme(CK_CHAR_PTR sParamName);
   _EXT  CK_KEY_TYPE                   P11Util_GetCKType(CK_CHAR_PTR sKeyType, CK_ULONG uFlag);
   _EXT  CK_KEY_TYPE                   P11Util_GetClassFromCKType(CK_CHAR_PTR sKeyType,CK_ULONG uFlag);
   _EXT  CK_OBJECT_CLASS               P11Util_GetClass(CK_CHAR_PTR sKeyClass);
   _EXT  CK_CHAR_PTR                   P11Util_DisplayKeyTypeName(CK_KEY_TYPE keytype);
   _EXT  void                          P11Util_DisplayDate(CK_CHAR_PTR ByteArray, CK_DATE* Date, CK_LONG Length);
   _EXT  void                          P11Util_DisplayOIDName(CK_CHAR_PTR sOID, CK_BYTE bOIDLen);
   _EXT  P11_EDDSA_OID_CONVERT*        P11Util_EddsaConvertOidStd(CK_CHAR_PTR sOid, CK_LONG uOidLength);
   _EXT  P11_EDDSA_OID_CONVERT*        P11Util_EddsaConvertOidToStd(CK_CHAR_PTR sOid, CK_LONG uOidLength);
   _EXT  P11_HASH_MECH*                P11Util_GetHash(CK_CHAR_PTR sHash, CK_ULONG uFlag);
   _EXT  CK_CHAR_PTR                   P11Util_DisplayErrorName(CK_ULONG uErrorCode);
   _EXT  CK_CHAR_PTR                   P11Util_DisplayAttributeName(CK_ATTRIBUTE_TYPE ckAttribute);
   _EXT  CK_BYTE                       P11Util_GetKCVMethod(CK_CHAR_PTR sKCV);
   _EXT  CK_ATTRIBUTE_TYPE             P11Util_GetAttributeType(CK_CHAR_PTR sAttribute);
   _EXT  P11_ML_DSA_KEY *              P11Util_GetML_DSA_ParameterFromKeySize(CK_ULONG sPublicKeySize);
   _EXT  P11_ML_DSA_KEY*               P11Util_GetML_DSA_ParameterFromParameterSet(CK_ML_DSA_PARAMETER_SET_TYPE sParameterSet);
   _EXT  P11_ML_KEM_KEY*               P11Util_GetML_KEM_ParameterFromKeySize(CK_ULONG sPublicKeySize);
   _EXT  P11_ML_KEM_KEY*               P11Util_GetML_KEM_ParameterFromParameterSet(CK_ML_KEM_PARAMETER_SET_TYPE sParameterSet);

   _EXT  void                          P11Util_DisplaySupportedKeyType(CK_ULONG uFlag);
   _EXT  void                          P11Util_DisplayKeyGenMecanismInfo(CK_SLOT_ID u32_SlotID);
   _EXT  void                          P11Util_DisplaySupportedPublicExp();
   _EXT  void                          P11Util_DisplaySupportedRSAGenMechParam();
   _EXT  void                          P11Util_DisplaySupportedCurveName(CK_KEY_TYPE sKeyType);
   _EXT  void                          P11Util_DisplayEncryptionParam(CK_ULONG    bKeyFlag);
   _EXT  void                          P11Util_DisplayDerivationParam();
   _EXT  void                          P11Util_DisplayKdfType();
   _EXT  void                          P11Util_DisplayKdfScheme();
   _EXT  void                          P11Util_DisplaySupportedClass();
   _EXT  void                          P11Util_DisplaySupportedDHGenMechParam();
   _EXT  void                          P11Util_DisplaySupportedHash(CK_ULONG uFlag);
   _EXT  void                          P11Util_DisplaySupportedKCVMethod();
   _EXT  void                          P11Util_DisplaySupportedAttribute();
   _EXT  CK_CHAR_PTR                   P11Util_GetLMSTypeName(CK_LMS_TYPE uLMStype);
   _EXT  CK_CHAR_PTR                   P11Util_GetLMOTSTypeName(CK_LMS_TYPE uLMOTStype);
   _EXT  void                          P11Util_DisplaySupportedLMSType();
   _EXT  void                          P11Util_DisplaySupportedLMSOTSType();
   _EXT  CK_LMS_TYPE                   P11Util_GetLMSType(CK_CHAR_PTR uLMStypeName);
   _EXT  CK_LMOTS_TYPE                 P11Util_GetLMSOTSType(CK_CHAR_PTR uLMSOTtypeName);


#undef _EXT

#endif // _P11_STR_H_