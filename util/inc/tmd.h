/****************************************************************************\
*
* This file is part of the "Luna KMU" tool.
*
* The "KMU" tool is provided under the MIT license (see the
* following Web site for further details: https://mit-license.org/ ).
*
* Author: Sebastien Chapellier
*
* Copyright © 2023-2025 Thales Group
*
\****************************************************************************/

#ifndef _TMD_H_
#define _TMD_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _TMD_C
#define _EXT
#else
#define _EXT extern
#endif

   _EXT  CK_CHAR_PTR          tmd_getShareinfo();
   _EXT  CK_ULONG             tmd_getShareinfoLength();
   _EXT  CK_BBOOL             tmd_generateCSVFile(CK_CHAR_PTR sHsmEcPublicKey, CK_KEY_TYPE sKeyType, CK_LONG sKeyLength, CK_BYTE_PTR pKcvBuffer, CK_CHAR_PTR sOutputFilePath);


#undef _EXT

#endif // _TMD_H_