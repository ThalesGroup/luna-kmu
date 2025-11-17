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

#define _TMD_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "p11.h"
#include "str.h"
#include "file.h"
#include "tmd.h"

// Shared info between the TMD and luna for x9.63 protocol
const CK_CHAR  sShareInfo[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30 , 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x00 };

const CK_CHAR  scsvcolomns[] = "VERSION, YEAR, MONTH, DAY, HOUR, MINUTE, SHARED INFORMATION, MZMK CHECK VALUE, MZMK KEY SCHEME, HSM PUBLIC KEY \r\n";

const CK_CHAR  sVersion[] = "1";
const CK_CHAR  sComma[] = ",";
const CK_CHAR  sUnderscore[] = "_";

const CK_CHAR sDESTriple[] = "Triple Length 3DES";
const CK_CHAR sAES_128[] = "128-bit AES";
const CK_CHAR sAES_192[] = "192-bit AES";
const CK_CHAR sAES_256[] = "256-bit AES";

#define CSV_FILE_LENGTH_FIXED    (sizeof(scsvcolomns) + strlen(sShareInfo) + 100)


const CK_CHAR sFileNameHeader[] = "MZMKdata_";
const CK_CHAR sFileNameExtension[] = ".csv";

#define MAX_FILE_NAME_LENGTH     50


/*
    FUNCTION:        CK_CHAR_PTR  tmd_getShareinfo()
*/
CK_CHAR_PTR  tmd_getShareinfo()
{
   return (CK_CHAR_PTR)sShareInfo;
}

/*
    FUNCTION:        CK_ULONG  tmd_getShareinfoLength()
*/
CK_ULONG  tmd_getShareinfoLength()
{
   return (CK_ULONG)sizeof(sShareInfo) - 1;
}

/*
    FUNCTION:        CK_BBOOL tmd_generateCSVFile(CK_CHAR_PTR sHsmEcPublicKey, CK_KEY_TYPE sKeyType, CK_LONG sKeyLength, CK_BYTE_PTR pKcvBuffer, CK_CHAR_PTR sOutputFilePath)
*/
CK_BBOOL tmd_generateCSVFile(CK_CHAR_PTR sHsmEcPublicKey, CK_KEY_TYPE sKeyType, CK_LONG sKeyLength, CK_BYTE_PTR pKcvBuffer, CK_CHAR_PTR sOutputFilePath)
{
   time_t         Time = {0};
   struct tm*     sTime = NULL;
   CK_CHAR_PTR    sCSVArray = NULL;
   CK_ULONG       sCSVArrayLength = 0;
   CK_CHAR_PTR    sCSVFileName = NULL;
   CK_CHAR_PTR    sTempArray = NULL;
   CK_ULONG       uWrittenSize = 0;


   do
   {
      // get current time
      Time = time(NULL);
      sTime = localtime(&Time);

      // allocate buffer for csv file
      sCSVArrayLength = (CK_ULONG)CSV_FILE_LENGTH_FIXED + (CK_ULONG)strlen(sHsmEcPublicKey) + (CK_ULONG)strlen(sShareInfo);
      sCSVArray = malloc(sCSVArrayLength);
      if (sCSVArray == NULL)
      {
         break;
      }
      memset(sCSVArray, 0, sCSVArrayLength);


      // allocate buffer for file name (name should contains date and time)
      sCSVFileName = malloc(MAX_FILE_NAME_LENGTH);
      if (sCSVFileName == NULL)
      {
         break;
      }
      memset(sCSVFileName, 0, MAX_FILE_NAME_LENGTH);

      // add csv file name
      str_Append(sCSVFileName, (CK_CHAR_PTR)sFileNameHeader);
            

      // add csv first line
      str_Append(sCSVArray, (CK_CHAR_PTR)scsvcolomns);


      // add version
      str_Append(sCSVArray, (CK_CHAR_PTR)sVersion);
      str_Append(sCSVArray, (CK_CHAR_PTR)sComma);


      // add year in csv
      sTempArray = str_WordtoAsciiString(1900 + sTime->tm_year);
      str_Append(sCSVArray, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVArray, (CK_CHAR_PTR)sComma);

      // add year in file name
      str_Append(sCSVFileName, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVFileName, (CK_CHAR_PTR)sUnderscore);

      // add month in csv
      sTempArray = str_BytetoAsciiString(sTime->tm_mon + 1);
      str_Append(sCSVArray, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVArray, (CK_CHAR_PTR)sComma);

      // add month in file name
      str_Append(sCSVFileName, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVFileName, (CK_CHAR_PTR)sUnderscore);

      // add day in csv
      sTempArray = str_BytetoAsciiString(sTime->tm_mday);
      str_Append(sCSVArray, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVArray, (CK_CHAR_PTR)sComma);

      // add day in file name
      str_Append(sCSVFileName, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVFileName, (CK_CHAR_PTR)sUnderscore);

      // add hours in csv
      sTempArray = str_BytetoAsciiString(sTime->tm_hour);
      str_Append(sCSVArray, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVArray, (CK_CHAR_PTR)sComma);

      // add hours in file name
      str_Append(sCSVFileName, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVFileName, (CK_CHAR_PTR)sUnderscore);

      // add minutes in csv
      sTempArray = str_BytetoAsciiString(sTime->tm_min);
      str_Append(sCSVArray, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVArray, (CK_CHAR_PTR)sComma);

      // add minutes in file name
      str_Append(sCSVFileName, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVFileName, (CK_CHAR_PTR)sFileNameExtension);

      // convert the share info to a ascii string. 
      sTempArray = str_ByteArraytoString((CK_CHAR_PTR)tmd_getShareinfo(), tmd_getShareinfoLength());

      // add share info to CSV
      str_Append(sCSVArray, (CK_CHAR_PTR)sTempArray);
      str_Append(sCSVArray, (CK_CHAR_PTR)sComma);
      free(sTempArray);

      // add KCV info to CSV
      str_Append(sCSVArray, (CK_CHAR_PTR)pKcvBuffer);
      str_Append(sCSVArray, (CK_CHAR_PTR)sComma);

      // add key type anme info to CSV
      switch (sKeyType)
      {
      case CKK_AES:
         if (sKeyLength == AES_128_KEY_LENGTH)
         {
            str_Append(sCSVArray, (CK_CHAR_PTR)sAES_128);
         }
         if (sKeyLength == AES_192_KEY_LENGTH)
         {
            str_Append(sCSVArray, (CK_CHAR_PTR)sAES_192);
         }
         if (sKeyLength == AES_256_KEY_LENGTH)
         {
            str_Append(sCSVArray, (CK_CHAR_PTR)sAES_256);
         }
         break;

      case CKK_DES3:
         str_Append(sCSVArray, (CK_CHAR_PTR)sDESTriple);
         break;

      default:
         break;
      }
      str_Append(sCSVArray, (CK_CHAR_PTR)sComma);

      // add hsm ecdh public key info to CSV
      str_Append(sCSVArray, (CK_CHAR_PTR)sHsmEcPublicKey);

      // write the file in the same directory as input data
      str_PathAppendFile(sOutputFilePath, (CK_CHAR_PTR)sCSVFileName);

      // write the file
      uWrittenSize = File_Write(sOutputFilePath, sCSVArray, (CK_ULONG)strlen(sCSVArray), CK_TRUE);

      // Check of file is written
      if (uWrittenSize > 0)
      {
         printf("\n\n");
         printf("Successfull: the file %s has been generated. You can upload in TMD. \n", sOutputFilePath);
         return CK_TRUE;
      }

   } while (FALSE);


   free(sCSVArray);
   free(sCSVFileName);

   return CK_FALSE;
}