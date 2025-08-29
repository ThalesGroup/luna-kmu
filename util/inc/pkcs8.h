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
#undef _EXT

#endif // _PKCS8_H_