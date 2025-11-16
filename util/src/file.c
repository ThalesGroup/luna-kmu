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

#define _FILE_C

#ifdef OS_WIN32
#include <io.h>
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include <fcntl.h>
#include <sys/stat.h>
#include "str.h"



/****************************************************************************
*
* FUNCTION    : File_Read
*
* DESCRIPTION : Reads a binary file with the input file, allocates memory
*               to read it and returns the content using the input pointers.
*               Returns 1 if successful.
*
* PARAMETERS  : char *pbFileName
*               char **ppMemBlock
*               unsigned long *pulMemSize
*
* RETURN VALUE: int
*
****************************************************************************/
CK_ULONG File_Read(CK_CHAR_PTR pbFileName, CK_CHAR_PTR * ppMemBlock, CK_BBOOL isBinary)
{
   CK_LONG  isOK = 1;
   CK_LONG  fileHandle = 0;
   CK_LONG  isFileOpen = 0;
   CK_LONG  FlagOpen = 0;
   CK_ULONG FileSize = 0;
   CK_ULONG bytesRead;
   do
   {
      *ppMemBlock = 0;

      // Verify pointer
      if (!pbFileName || !ppMemBlock)
      {
         break;
      }


#ifdef OS_UNIX
      fileHandle = open(pbFileName, O_RDONLY);
#else
      FlagOpen = _O_RDONLY;
      if (isBinary)
      {
         FlagOpen |= _O_BINARY;
      }

      //fileHandle = _open(pbFileName, _O_RDONLY | _O_BINARY);
      _sopen_s(&fileHandle, pbFileName, FlagOpen, _SH_DENYNO, 0);
#endif

      if (fileHandle < 0)
      {
         break;
      }

#ifdef OS_UNIX
      struct stat fileStat;
      if (fstat(fileHandle, &fileStat))
      {
         isOK = 0;
      }
      *pulMemSize = fileStat.st_size;
      }
   if (isOK)
   {
#else
      FileSize = _filelength(fileHandle);
#endif

      // check if file binary
      if (isBinary)
      {
         // if binary file, allocate exact file size
         *ppMemBlock = malloc(FileSize);
      }
      else
      {
         FileSize++;
         // if not binary allocate 1 byte more to put \0 at the last byte
         *ppMemBlock = malloc((size_t)(FileSize));
      }

      if (*ppMemBlock == NULL)
      {
         FileSize = 0;
         break;
      }




#ifdef OS_UNIX
      bytesRead = (int)read(fileHandle, *ppMemBlock, bytesSupplied);
#else
      bytesRead = _read(fileHandle, *ppMemBlock, FileSize);
#endif
      if ((isBinary) && (bytesRead != FileSize))
      {
         FileSize = 0;
         // release memory
         free(*ppMemBlock);
         // error while reading
         break;
      }

      // if non binary file, put \0 at the last byte
      if (!isBinary)
      {
         (*ppMemBlock)[bytesRead] = 0;
         FileSize = bytesRead;
      }

   }while (FALSE);

   // Close file handle
   if (fileHandle > 0)
   {
#ifdef OS_UNIX
      close(fileHandle);
#else
      _close(fileHandle);
#endif
   }
   return FileSize;
}


/****************************************************************************
*                                                                            
* FUNCTION    : File_Write
*                                                                            
* DESCRIPTION : Writes to a binary file the content provided using the
*               input pointers.
*                                                                            
* PARAMETERS  : char *pbFileName
*               char *pMemBlock
*               unsigned long *pulMemSize
*                                                                                                                                                             
* RETURN VALUE: int
*                                                                            
****************************************************************************/
CK_LONG File_Write(CK_CHAR_PTR pbFileName, CK_CHAR_PTR pMemBlock, CK_ULONG ulMemSize, CK_BBOOL isBinary)
{
   CK_LONG fileHandle = 0;
   CK_LONG FlagOpen = 0;
   CK_LONG writtenSize = 0;
   do
   {
      // Verify pointer
      if (!pbFileName || !pMemBlock)
      {
         break;
      }

#ifdef OS_UNIX
      fileHandle = open(pbFileName,
         O_CREAT | O_RDWR | O_TRUNC,
         S_IRWXG | S_IRWXO | S_IRWXU);
#else
      FlagOpen = _O_RDWR | _O_CREAT | _O_TRUNC;
      if (isBinary)
      {
         FlagOpen |= _O_BINARY;
      }
      _sopen_s(&fileHandle, pbFileName, FlagOpen, _SH_DENYNO, _S_IREAD | _S_IWRITE);
#endif

      // Write file
      if (fileHandle > 0)
      {


#ifdef OS_UNIX
         result = (int)write(fileHandle, pMemBlock, ulMemSize);
#else
         writtenSize = _write(fileHandle, pMemBlock, ulMemSize);
#endif
      }
   } while (FALSE);

   // Close file handle
   if (fileHandle > 0)
   {
#ifdef OS_UNIX
      close(fileHandle);
#else
      _close(fileHandle);
#endif
   }

   return writtenSize;
}

/*
    FUNCTION:        CK_BBOOL    File_ReadHexFile(CK_CHAR_PTR sInputFilePath, CK_CHAR_PTR * sSource, CK_ULONG_PTR SourceSize, CK_BBOOL bIsBinary)
*/
CK_BBOOL File_ReadHexFile(CK_CHAR_PTR sInputFilePath, CK_CHAR_PTR* sSource, CK_ULONG_PTR SourceSize, CK_BBOOL bIsBinary)
{
   do
   {
      // read file
      *SourceSize = File_Read(sInputFilePath, sSource, bIsBinary);
      if (*SourceSize == 0)
      {
         printf("Cannot read file : %s \n", sInputFilePath);
         break;
      }

      // if format text convert to binary string
      if (bIsBinary == CK_FALSE)
      {
         *SourceSize = str_StringtoByteArray(*sSource, *SourceSize);
         if (*SourceSize == 0)
         {
            free(*sSource);
            printf("File format error. Size must be multiple of 2 bytes and hexadecimal value\n");
            break;
         }
      }
      return CK_TRUE;
   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_ULONG File_WriteHexFile(CK_CHAR_PTR sOutputFilePath, CK_CHAR_PTR sSource, CK_ULONG SourceSize, CK_BYTE FileFormat)
*/
CK_ULONG File_WriteHexFile(CK_CHAR_PTR sOutputFilePath, CK_CHAR_PTR sSource, CK_ULONG SourceSize, CK_BBOOL bIsBinary)
{
   CK_ULONG    uWrittenSize = 0;
   do
   {
      // if format is text, convert to string
      if (bIsBinary == CK_FALSE)
      {
         // allocate buffer for changing format
         CK_CHAR_PTR buffer = str_ByteArraytoString(sSource, SourceSize);

         // write in file as string
         uWrittenSize = File_Write(sOutputFilePath, buffer, (CK_ULONG)strlen(buffer), CK_FALSE);

         // release allocated buffer by str_ByteArraytoString
         free(buffer);
      }
      else
      {
         // write in file as binary
         uWrittenSize = File_Write(sOutputFilePath, sSource, SourceSize, CK_TRUE);
      }

   } while (FALSE);

   return uWrittenSize;
}
