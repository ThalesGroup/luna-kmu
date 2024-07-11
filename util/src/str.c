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

#define _STR_C

#ifdef OS_WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "p11.h"


#define ULONG_STR_LEN      10

const char strQuote = '"';
const char strSpace = ' ';
const char strEqual = '=';
const char strDash = '-';

const char strBackSlashString[2] = {'\\', 0};

/*
    FUNCTION:        void str_DisplayByteArraytoString(CK_CHAR_PTR ByteArray, CK_LONG Length)
*/
void str_DisplayByteArraytoString(CK_CHAR_PTR Name, CK_CHAR_PTR ByteArray, CK_LONG Length)
{
   CK_LONG loop;
   printf(Name);
   for (loop = 0; loop < Length; loop++)
   {
      printf("%02X", ByteArray[loop]);
   }
   printf("\n");
}

/*
    FUNCTION:        void str_DisplayByteArraytoString(CK_CHAR_PTR ByteArray, CK_LONG Length)
*/
CK_CHAR_PTR str_ByteArraytoString(CK_CHAR_PTR ByteArray, CK_LONG Length)
{

   CK_LONG loop;
   // allocate a string of the double of the size of the byte array
   CK_CHAR_PTR string = malloc(2 * Length + 1);

   do
   {
      // check allocation is OK
      if (string == NULL)
      {
         break;
      }

      // loop on all buffer and convert to string
      for (loop = 0; loop < Length; loop++)
      {
         sprintf(&string[loop<<1], "%02X", ByteArray[loop]);
      }

      return string;
   }while (FALSE);


   return NULL;
}

/*
    FUNCTION:        CK_LONG str_StringtoInteger(CK_CHAR_PTR sKeyType)
*/
CK_LONG str_StringtoInteger(CK_CHAR_PTR sKeyType)
{
   CK_LONG iSize = 0;
   CK_ULONG sLength = (CK_ULONG)strlen(sKeyType);
   
   if (sLength > ULONG_STR_LEN)
   {
      return -2;
   }

   // check source buffer is hex string
   for (CK_ULONG uloop = 0; uloop < sLength; uloop++)
   {
      // hex character between 0 and 9 in ascci
      if (sKeyType[uloop] < '0' || sKeyType[uloop] > '9')
      {
            return -3;
      }
   }

   // atoi returns 0 if the string is not a number
   iSize = atoi(sKeyType);

   if (iSize == 0x7FFFFFFF)
   {
      return -4;
   }

   return iSize;
}

/*
    FUNCTION:        CK_LONG_64 str_StringtoUnsignedInteger(CK_CHAR_PTR sKeyType)
*/
CK_LONG_64 str_StringtoUnsignedInteger(CK_CHAR_PTR sKeyType)
{
   CK_LONG_64 iSize = 0;
   CK_ULONG sLength = (CK_ULONG)strlen(sKeyType);

   if (sLength > ULONG_STR_LEN)
   {
      return -2;
   }

   // check source buffer is hex string
   for (CK_ULONG uloop = 0; uloop < sLength; uloop++)
   {
      // hex character between 0 and 9 in ascci
      if (sKeyType[uloop] < '0' || sKeyType[uloop] > '9')
      {
         return -3;
      }
   }

   // atoi returns 0 if the string is not a number
   iSize = atoll(sKeyType);

   if (iSize > (CK_LONG_64)0xFFFFFFFF)
   {
      return -4;
   }

   return iSize;
}




/*
    FUNCTION:        CK_ULONG str_StringtoByteArray(CK_CHAR_PTR sSource, CK_ULONG SourceSize)
*/
CK_ULONG str_StringtoByteArray(CK_CHAR_PTR sSource, CK_ULONG SourceSize)
{
   CK_CHAR_PTR sDestination = sSource;
   CK_ULONG destinationSize = 0;
   CK_CHAR sTempString[3] = {0x00};

   // if the file size is not multiple of 2, don't convert
   if ((SourceSize % 2) != 0)
   {
      return 0;
   }

   // check source buffer is hex string
   for (CK_ULONG uloop = 0; uloop < SourceSize; uloop++)
   {
      // hex character between 0 and F in ascci
      if (sSource[uloop] < '0' || sSource[uloop] > 'F')
      {
         if (sSource[uloop] < 'a' || sSource[uloop] > 'f')
         {
            return 0;
         }

      }
   }

   // divide by 2 the input length
   SourceSize = SourceSize >> 1;

   // loop on the buffer
   while (SourceSize--) 
   {
      // Read 2 bytes of the source string
      sTempString[0] = *sSource++;
      sTempString[1] = *sSource++;

      // write in destination buffer
      *sDestination++ = (byte)strtol(sTempString, NULL, 16);
      destinationSize++;
   }
   return destinationSize;
}


/*
    FUNCTION:        void str_TruncateString(CK_CHAR_PTR ByteArray, CK_LONG uLength)
*/
void str_TruncateString(CK_CHAR_PTR ByteArray, CK_LONG uLength)
{
   uLength--;
   while (ByteArray[uLength] == 0x20)
   {
      ByteArray[uLength] = 0;
      uLength--;
   }

}

/*
    FUNCTION:        void str_RemoveQuotes(CK_CHAR_PTR ByteArray, CK_LONG uLength)
*/
CK_CHAR_PTR str_RemoveQuotes(CK_CHAR_PTR ByteArray, CK_ULONG uLength)
{
   CK_ULONG uLoop;
   CK_ULONG uRemainingLength = uLength;
   CK_CHAR_PTR sString = NULL;

   do
   {
      if (ByteArray == NULL)
      {
         break;
      }
      // loop on all buffer
      for (uLoop = 0; uLoop < uLength; uLoop++)
      {
         // if match a quote, shift the memory
         if (ByteArray[uLoop] == strQuote)
         {
            memcpy(&ByteArray[uLoop], &ByteArray[uLoop +1], uRemainingLength);
            ByteArray[uLoop + uRemainingLength] = 0;
         }
         uRemainingLength--;
      }

   } while (FALSE);

   return sString;
}

/*
    FUNCTION:        CK_CHAR_PTR str_RemoveLeadingSpace(CK_CHAR_PTR ByteArray)
*/
CK_CHAR_PTR str_RemoveLeadingSpace(CK_CHAR_PTR ByteArray)
{
   CK_ULONG uOffset = 0;
   CK_ULONG uLength;

   if (ByteArray == NULL)
   {
      return NULL;
   }

   // get string length
   uLength = (CK_ULONG)strlen(ByteArray);

   do
   {
      if (ByteArray[uOffset] == strSpace)
      {
         ByteArray[uOffset] = 0;
         // increment to remove space
         uOffset++;
      }
      else
      {
         // stop the loop
         break;
      }
   } while (uOffset < uLength);

   return &ByteArray[uOffset];
   // Check if next character is a space

}
/*
    FUNCTION:        CK_ULONG str_ComparePartialString(CK_CHAR_PTR sString1, CK_CHAR_PTR sString2)
*/
CK_ULONG str_ComparePartialString(CK_CHAR_PTR sString1, CK_CHAR_PTR sString2)
{
   CK_ULONG uString1Len = (CK_ULONG)strlen(sString1);
   CK_ULONG uString2Len = (CK_ULONG)strlen(sString2);
   CK_ULONG uOffset = 0;

   // get the minimum length of the 2 strings
   uString1Len = min(uString1Len, uString2Len);

   // Loop on string 
   for (CK_ULONG uLoop = 0; uLoop < uString1Len; uLoop++)
   {
      if (sString1[uLoop] != sString2[uLoop])
      {
         break;
      }
      uOffset++;
   }

   // return offset where data match
   return uOffset;

}

/*
    FUNCTION:        CK_CHAR_PTR str_tolower(CK_CHAR_PTR sString)
*/
CK_CHAR_PTR str_tolower(CK_CHAR_PTR sString)
{
   for (CK_ULONG uLoop = 0; uLoop < strlen(sString); uLoop++) {

      // convert str[i] to lowercase
      sString[uLoop] = tolower(sString[uLoop]);
   }

   return sString;
}