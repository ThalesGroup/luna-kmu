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

#ifndef _TR31_H_
#define _TR31_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _TR31_C
#define _EXT
#else
#define _EXT extern
#endif


   _EXT  CK_BBOOL             TR31_UnwrapPrivateSecretKey(P11_UNWRAPTEMPLATE* sUnWrapTemplate, CK_CHAR_PTR pWrappedKey, CK_OBJECT_HANDLE* hKey);
   _EXT  CK_OBJECT_HANDLE     TR31_DeriveKeyMac(CK_OBJECT_HANDLE hWrappingKey);
   _EXT  CK_OBJECT_HANDLE     TR31_DeriveKeyEnc(CK_OBJECT_HANDLE hWrappingKey);
   _EXT  CK_BBOOL             TR31_VerifyMAC(CK_OBJECT_HANDLE hMacKey, CK_CHAR_PTR pHeader, CK_ULONG pHeaderLength, CK_CHAR_PTR pMac, CK_ULONG pMacLength);
   _EXT  CK_BBOOL             TR31_DecryptKey(CK_OBJECT_HANDLE hEncKey, CK_CHAR_PTR pEncryptedKey, CK_ULONG pEncryptedKEyLength, CK_CHAR_PTR pIV);
   _EXT  CK_BBOOL             TR31_ImportKey(P11_UNWRAPTEMPLATE* sUnWrapTemplate, CK_BYTE bKeyType, CK_CHAR_PTR pKey, CK_ULONG uKeyLength, CK_OBJECT_HANDLE* hKey);

#undef _EXT

#endif // _TR31_H_