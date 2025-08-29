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

#define _PKCS8_C_

#ifdef OS_WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "pkcs8.h"
#include "base64.h"

// constant
const CK_CHAR STR_BEGIN_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n";
const CK_CHAR STR_END_PUBLIC_KEY[] = "-----END PUBLIC KEY-----\n";
const CK_CHAR STR_BEGIN_ENCRYPTED_PRIVATE_KEY[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
const CK_CHAR STR_END_ENCRYPTED_PRIVATE_KEY[] = "-----END ENCRYPTED PRIVATE KEY-----\n";
const CK_CHAR STR_NEWLINE[] = "\n";

#define PKCS8_LINE_SIZE         0x40

/*
    FUNCTION:        CK_ULONG  pkcs8_DecodePublicKeyFromPem(CK_CHAR_PTR sEncryptedPrivateKey, CK_ULONG sEncryptedPrivateKeyLength)
*/
CK_ULONG  pkcs8_DecodePublicKeyFromPem(CK_CHAR_PTR sPublicKey, CK_ULONG sPublicKeyLength)
{

   CK_CHAR_PTR    sStringEndofFile = sPublicKey + sPublicKeyLength;
   CK_CHAR_PTR    sStringBeginOfLine;
   CK_CHAR_PTR    sStringEndPublicKey;
   CK_CHAR_PTR    sStringEndofLine;
   CK_CHAR_PTR    sStringBase64;
   CK_LONG        uSizeBase64 = 0;
   CK_LONG        uLineSize = 0;

   do
   {
      // search for begin public key string
      sStringBeginOfLine = strstr(sPublicKey, STR_BEGIN_PUBLIC_KEY);
      if (sStringBeginOfLine == NULL)
      {
         break;
      }
      // check begin public key string is the first string of the file
      if (sStringBeginOfLine != sPublicKey)
      {
         break;
      }
      // search for end public key string
      sStringEndPublicKey = strstr(sPublicKey, STR_END_PUBLIC_KEY);
      if (sStringEndPublicKey == NULL)
      {
         break;
      }

      // search for end public key string is the end of the file
      if ((sStringEndPublicKey + strlen(STR_END_PUBLIC_KEY)) != sPublicKey + sPublicKeyLength)
      {
         break;
      }

      // allocate a buffer of the size of the string (will be always little be higher than expected)
      sStringBase64 = malloc(sPublicKeyLength);

      // loop until end of string
      while (sStringBeginOfLine < sStringEndofFile)
      {
         // search for string \r\n (end of current line)
         sStringBeginOfLine = strstr(sStringBeginOfLine, STR_NEWLINE);
         sStringBeginOfLine += strlen(STR_NEWLINE);
         if (sStringBeginOfLine == NULL)
         {
            break;
         }
         // Search for end of current Line
         sStringEndofLine = strstr(sStringBeginOfLine, STR_NEWLINE);

         // if the current line is after the end of public key stop the loop
         if (sStringEndofLine >= sStringEndPublicKey)
         {
            break;
         }
         // get the size of the line
         uLineSize = (CK_ULONG)(sStringEndofLine - sStringBeginOfLine);
         // copy the line in sStringBase64 at current offset 
         memcpy(sStringBase64 + uSizeBase64, sStringBeginOfLine, uLineSize);
         // increment base64 buffer size
         uSizeBase64 += uLineSize;

         // Set Begin of lune, the current line
         sStringBeginOfLine = sStringEndofLine;
      }
      // Set \0 at the end of the string
      sStringBase64[uSizeBase64] = 0;

      // get the size of the decoded base64 buffer
      uSizeBase64 = (CK_ULONG)b64_decoded_size(sStringBase64);

      // decode the base64 buffer
      if (b64_decode(sStringBase64, (unsigned char*)sPublicKey, (size_t)sPublicKeyLength) == 0)
      {
         // in case of error, set the return size to 0
         uSizeBase64 = 0;
      }

      // release allocated buffer
      free(sStringBase64);

      // return the size of decoded string
      return uSizeBase64;
      
   } while (FALSE);

   // error
   return 0;
}

/*
    FUNCTION:        CK_ULONG  pkcs8_DecodePublicKeyFromPem(CK_CHAR_PTR sEncryptedPrivateKey, CK_ULONG sEncryptedPrivateKeyLength)
*/
CK_CHAR_PTR  pkcs8_EncodePublicKeyToPem(CK_CHAR_PTR sPublicKey, CK_ULONG sPublicKeyLength)
{
   CK_ULONG          uAllocatedBufferSize = 0;
   CK_ULONG          uAllocatedBufferOffset = 0;
   CK_ULONG          uLineNumber;
   CK_CHAR_PTR       sStringOutPemFile = NULL;
   CK_ULONG          sStringOutPemFileOffset = 0;
   CK_ULONG          sStringOutPemFileSize = 0;
   CK_ULONG          usPublicKeyOffset = 0;
   CK_CHAR_PTR       sStringEncoded64;
   CK_ULONG          sStringEncoded64Offset = 0;
   CK_ULONG          sStringEncoded64Length = 0;
   CK_ULONG          uSize;
   CK_ULONG          uRemainingSize = 0;

   // get the size of encoded base64 buffer
   sStringEncoded64Length = (CK_ULONG)b64_encoded_size((size_t)sPublicKeyLength);

   sStringEncoded64 = b64_encode(sPublicKey, (size_t)sPublicKeyLength);
   if(sStringEncoded64 == NULL)
   {
      return NULL;
   }

   // calculate max number of line
   uLineNumber = (sStringEncoded64Length / PKCS8_LINE_SIZE) + 1;

   // Buffer size include string begin key + string end key + n time number of line of size \r\n
   uAllocatedBufferSize = sStringEncoded64Length + (CK_ULONG)strlen(STR_BEGIN_PUBLIC_KEY) + (CK_ULONG)strlen(STR_END_PUBLIC_KEY) + (uLineNumber * (CK_ULONG)strlen(STR_NEWLINE)) + 1;

   // allocate buffer
   sStringOutPemFile = malloc(uAllocatedBufferSize);

   // if null stop the function
   if (sStringOutPemFile == NULL)
   {
      return NULL;
   }

   do
   {
      // append output pen buffer from begin public key
      uSize = (CK_ULONG)strlen(STR_BEGIN_PUBLIC_KEY);
      memcpy(sStringOutPemFile, STR_BEGIN_PUBLIC_KEY, uSize);
      sStringOutPemFileSize += uSize;
      sStringOutPemFileOffset += uSize;

      while (sStringEncoded64Offset < sStringEncoded64Length)
      {
         uRemainingSize = sStringEncoded64Length - sStringEncoded64Offset;
         // Check the number of remaining byte in the buffer
         if (uRemainingSize >= PKCS8_LINE_SIZE)
         {
            // set size of line
            uSize = PKCS8_LINE_SIZE;
         }
         else
         {
            // set the remaining size
            uSize = uRemainingSize;
         }

         // append output pen buffer from encoded base64 buffer
         memcpy(&sStringOutPemFile[sStringOutPemFileOffset], &sStringEncoded64[sStringEncoded64Offset], uSize);
         sStringEncoded64Offset += uSize;
         sStringOutPemFileOffset += uSize;

         // append output pen buffer with \n
         uSize = (CK_ULONG)strlen(STR_NEWLINE);
         memcpy(&sStringOutPemFile[sStringOutPemFileOffset], STR_NEWLINE, uSize);
         sStringOutPemFileOffset += uSize;

      }
      // append output pen buffer from end public key
      uSize = (CK_ULONG)strlen(STR_END_PUBLIC_KEY);
      memcpy(&sStringOutPemFile[sStringOutPemFileOffset], STR_END_PUBLIC_KEY, uSize);
      sStringOutPemFileSize += uSize;
      sStringOutPemFileOffset += uSize;
      sStringOutPemFile[sStringOutPemFileOffset] = 0;
   } while (FALSE);

   // release memory
   free(sStringEncoded64);

   // return buffer
   return sStringOutPemFile;
}


/*
    FUNCTION:        CK_CHAR_PTR  pkcs8_EncodeEncryptedPrivateKeyToPem(CK_CHAR_PTR sEncryptedPrivateKey, CK_ULONG sEncryptedPrivateKeyLength)
*/
CK_CHAR_PTR  pkcs8_EncodeEncryptedPrivateKeyToPem(CK_CHAR_PTR sEncryptedPrivateKey, CK_ULONG sEncryptedPrivateKeyLength)
{
   CK_ULONG          uAllocatedBufferSize = 0;
   CK_ULONG          uAllocatedBufferOffset = 0;
   CK_ULONG          uLineNumber;
   CK_CHAR_PTR       sStringOutPemFile = NULL;
   CK_ULONG          sStringOutPemFileOffset = 0;
   CK_ULONG          sStringOutPemFileSize = 0;
   CK_ULONG          usPublicKeyOffset = 0;
   CK_CHAR_PTR       sStringEncoded64;
   CK_ULONG          sStringEncoded64Offset = 0;
   CK_ULONG          sStringEncoded64Length = 0;
   CK_ULONG          uSize;
   CK_ULONG          uRemainingSize = 0;

   // get the size of encoded base64 buffer
   sStringEncoded64Length = (CK_ULONG)b64_encoded_size((size_t)sEncryptedPrivateKeyLength);

   sStringEncoded64 = b64_encode(sEncryptedPrivateKey, (size_t)sEncryptedPrivateKeyLength);
   if (sStringEncoded64 == NULL)
   {
      return NULL;
   }

   // calculate max number of line
   uLineNumber = (sStringEncoded64Length / PKCS8_LINE_SIZE) + 1;

   // Buffer size include string begin key + string end key + n time number of line of size \r\n
   uAllocatedBufferSize = sStringEncoded64Length + (CK_ULONG)strlen(STR_BEGIN_ENCRYPTED_PRIVATE_KEY) + (CK_ULONG)strlen(STR_END_ENCRYPTED_PRIVATE_KEY) + (uLineNumber * (CK_ULONG)strlen(STR_NEWLINE)) + 1;

   // allocate buffer
   sStringOutPemFile = malloc(uAllocatedBufferSize);

   // if null stop the function
   if (sStringOutPemFile == NULL)
   {
      return NULL;
   }

   do
   {
      // append output pen buffer from begin public key
      uSize = (CK_ULONG)strlen(STR_BEGIN_ENCRYPTED_PRIVATE_KEY);
      memcpy(sStringOutPemFile, STR_BEGIN_ENCRYPTED_PRIVATE_KEY, uSize);
      sStringOutPemFileSize += uSize;
      sStringOutPemFileOffset += uSize;

      while (sStringEncoded64Offset < sStringEncoded64Length)
      {
         uRemainingSize = sStringEncoded64Length - sStringEncoded64Offset;
         // Check the number of remaining byte in the buffer
         if (uRemainingSize >= PKCS8_LINE_SIZE)
         {
            // set size of line
            uSize = PKCS8_LINE_SIZE;
         }
         else
         {
            // set the remaining size
            uSize = uRemainingSize;
         }

         // append output pen buffer from encoded base64 buffer
         memcpy(&sStringOutPemFile[sStringOutPemFileOffset], &sStringEncoded64[sStringEncoded64Offset], uSize);
         sStringEncoded64Offset += uSize;
         sStringOutPemFileOffset += uSize;

         // append output pen buffer with \n
         uSize = (CK_ULONG)strlen(STR_NEWLINE);
         memcpy(&sStringOutPemFile[sStringOutPemFileOffset], STR_NEWLINE, uSize);
         sStringOutPemFileOffset += uSize;

      }
      // append output pen buffer from end public key
      uSize = (CK_ULONG)strlen(STR_END_ENCRYPTED_PRIVATE_KEY);
      memcpy(&sStringOutPemFile[sStringOutPemFileOffset], STR_END_ENCRYPTED_PRIVATE_KEY, uSize);
      sStringOutPemFileSize += uSize;
      sStringOutPemFileOffset += uSize;
      sStringOutPemFile[sStringOutPemFileOffset] = 0;
   } while (FALSE);

   // release memory
   free(sStringEncoded64);

   // return buffer
   return sStringOutPemFile;
}