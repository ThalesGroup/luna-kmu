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

#ifndef _FILE_H_
#define _FILE_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _FILE_C
#define _EXT
#else
#define _EXT extern
#endif

   _EXT CK_ULONG     File_Read(CK_CHAR_PTR pbFileName, CK_CHAR_PTR* ppMemBlock, CK_BBOOL isBinary);
   _EXT CK_LONG      File_Write(CK_CHAR_PTR pbFileName, CK_CHAR_PTR pMemBlock, CK_ULONG ulMemSize, CK_BBOOL isBinary);
   _EXT CK_BBOOL     File_ReadHexFile(CK_CHAR_PTR sInputFilePath, CK_CHAR_PTR* sSource, CK_ULONG_PTR SourceSize, CK_BBOOL bIsBinary);
   _EXT CK_ULONG     File_WriteHexFile(CK_CHAR_PTR sOutputFilePath, CK_CHAR_PTR sSource, CK_ULONG SourceSize, CK_BBOOL bIsBinary);
#undef _EXT

#endif // 