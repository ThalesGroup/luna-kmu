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

#ifndef _STR_H_
#define _STR_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _STR_C
#define _EXT
#else
#define _EXT extern
#endif

   extern const char strQuote;
   extern const char strSpace;
   extern const char strEqual;
   extern const char strDash;
   extern const char strBackSlashString[2];

   _EXT  void           str_DisplayByteArraytoString(CK_CHAR_PTR Name, CK_CHAR_PTR ByteArray, CK_LONG Length);
   _EXT  void           str_DisplayByteArraytoStringWithSpace(CK_CHAR_PTR ByteArray, CK_LONG Length, CK_LONG Space);
   _EXT  CK_CHAR_PTR    str_ByteArraytoString(CK_CHAR_PTR ByteArray, CK_LONG Length);
   _EXT  CK_CHAR_PTR    str_BytetoAsciiString(CK_ULONG Byte);
   _EXT  CK_CHAR_PTR    str_WordtoAsciiString(CK_ULONG word);
   _EXT  CK_LONG        str_StringtoInteger(CK_CHAR_PTR sKeyType);
   _EXT  CK_LONG_64     str_StringtoUnsignedInteger(CK_CHAR_PTR sKeyType);
   _EXT  CK_ULONG       str_StringtoByteArray(CK_CHAR_PTR sSource, CK_ULONG SourceSize);
   _EXT  void           str_TruncateString(CK_CHAR_PTR ByteArray, CK_LONG uLength);
   _EXT  CK_CHAR_PTR    str_RemoveQuotes(CK_CHAR_PTR ByteArray, CK_ULONG uLength);
   _EXT  CK_CHAR_PTR    str_RemoveLeadingSpace(CK_CHAR_PTR ByteArray);
   _EXT  CK_ULONG       str_DeleteSpace(CK_CHAR_PTR ByteArray);
   _EXT  CK_ULONG       str_ComparePartialString(CK_CHAR_PTR sString1, CK_CHAR_PTR sString2);
   _EXT  CK_CHAR_PTR    str_tolower(CK_CHAR_PTR sString);
   _EXT  void           str_ByteArrayXOR(CK_CHAR_PTR ByteArray1, CK_CHAR_PTR ByteArray2, CK_ULONG uLength);
   _EXT  void           str_ByteArrayComputeParityBit(CK_CHAR_PTR ByteArray, CK_LONG uLength);
   _EXT  CK_BBOOL       str_CheckASCII(CK_CHAR_PTR ByteArray, CK_ULONG uLength);
   _EXT  CK_BBOOL       str_PathRemoveFile(CK_CHAR_PTR ByteArray, CK_ULONG uLength);
   _EXT  CK_BBOOL       str_PathAppendFile(CK_CHAR_PTR sPath, CK_CHAR_PTR sFile);
   _EXT  CK_CHAR_PTR    str_Append(CK_CHAR_PTR sSource, CK_CHAR_PTR sDestination);
#undef _EXT

#endif // _STR_H_