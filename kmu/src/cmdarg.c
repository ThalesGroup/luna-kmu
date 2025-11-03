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

#define _CMD_ARG_C

#ifdef OS_WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "p11util.h"
#include "parser.h"
#include "cmdarg.h"
#include "str.h"
#include "console.h"

P11_ENCRYPTION_MECH     sCustomEncryption_mech;
P11_EXP_DOMAIN          sDh_Domain;

P11_DERIVE_MECH         sDerive_Mech;
/*
#define  MAX_KDF_LABEL_SIZE      32
#define  MAX_KDF_CONTEXT_SIZE    32
CK_CHAR  sKdfLabel[MAX_KDF_LABEL_SIZE];
CK_CHAR  sKdfContext[MAX_KDF_CONTEXT_SIZE];
*/
typedef struct Parser_Boolean
{
   const CK_CHAR_PTR sParamName;
   const CK_BBOOL bBool;
}PARSERBOOLEAN;

const CK_CHAR ARG_BOOL_TRUE[] = "true";
const CK_CHAR ARG_BOOL_ONE[] = "1";
const CK_CHAR ARG_BOOL_FALSE[] = "false";
const CK_CHAR ARG_BOOL_ZERO[] = "0";


#define SIZE_ARG_BOOLEAN		DIM(arg_boolean)


PARSERBOOLEAN arg_boolean[] = {
   {(CK_CHAR_PTR)&ARG_BOOL_TRUE, CK_TRUE},
   {(CK_CHAR_PTR)&ARG_BOOL_ONE, CK_TRUE},
   {(CK_CHAR_PTR)&ARG_BOOL_FALSE, CK_FALSE},
   {(CK_CHAR_PTR)&ARG_BOOL_ZERO, CK_FALSE},
};



typedef struct Parser_fileformat
{
   const CK_CHAR_PTR sParamName;
   const CK_BYTE bFormat;
}PARSER_FILE_FORMAT;

const CK_CHAR ARG_FORMAT_BINARY[] = "bin";
const CK_CHAR ARG_FORMAT_TEXT[] = "text";
const CK_CHAR ARG_FORMAT_TXT[] = "txt";
const CK_CHAR ARG_FORMAT_PKCS8[] = "pkcs8";
const CK_CHAR ARG_FORMAT_PKCS12[] = "pkcs12";
const CK_CHAR ARG_FORMAT_TR31[] = "tr31";


#define SIZE_ARG_FILEFORMAT		   DIM(arg_fileformat)
PARSER_FILE_FORMAT arg_fileformat[] = {
   {(CK_CHAR_PTR)&ARG_FORMAT_BINARY, FILE_FORMAT_BINARY},
   {(CK_CHAR_PTR)&ARG_FORMAT_TEXT, FILE_FORMAT_TEXT},
   {(CK_CHAR_PTR)&ARG_FORMAT_TXT, FILE_FORMAT_TEXT},
   {(CK_CHAR_PTR)&ARG_FORMAT_PKCS8, FILE_FORMAT_PKCS8},
   {(CK_CHAR_PTR)&ARG_FORMAT_TR31, FILE_FORMAT_TR31},
};

/*
    FUNCTION:        CK_SLOT_ID cmdarg_GetSlotID()
*/
CK_SLOT_ID cmdarg_GetSlotID()
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_LONG sInteger;

   arg = parser_SearchArgument(ARG_TYPE_SLOT);

   if (arg == NULL)
   {
      return CK_NULL_ELEMENT;
   }

   sInteger = str_StringtoInteger(arg->s_argPart2);

   if (sInteger < 0)
   {
      return CK_NULL_ELEMENT;
   }

   return (CK_SLOT_ID)sInteger;

}

/*
    FUNCTION:        CK_CHAR_PTR cmdarg_GetPassword()
*/
CK_CHAR_PTR cmdarg_GetPassword()
{
   PARSER_CURRENT_CMD_ARG* arg;

   arg = parser_SearchArgument(ARG_TYPE_PASSWORD);

   if (arg == NULL)
   {
      return NULL;
   }

   return arg->s_argPart2;

}

/*
    FUNCTION:        CK_BBOOL cmdarg_isCryptoUserLoginRequested()
*/
CK_BBOOL cmdarg_isCryptoUserLoginRequested()
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_BYTE u8Loop;

   arg = parser_SearchArgument(ARG_TYPE_CRYPTO_USER);

   do
   {
      if (arg == NULL)
      {
         break;
      }

      if (arg != NULL)
      {

         // Uppercase to lowercase
         arg->s_argPart2 = str_tolower(arg->s_argPart2);

         // loop on all boolean mech structure
         for (u8Loop = 0; u8Loop < SIZE_ARG_BOOLEAN; u8Loop++)
         {
            // only accept true value
            if (arg_boolean[u8Loop].bBool == CK_TRUE)
            {
               // if value match, retrun true
               if (strcmp(arg_boolean[u8Loop].sParamName, arg->s_argPart2) == 0)
               {
                  // return param is present
                  return arg_boolean[u8Loop].bBool;
               }
            }

         };
      }

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmdarg_SearchTypeBoolean(BYTE bArgType, CK_BBOOL* bOutValue, CK_BBOOL bdefaultValue)
*/
CK_BBOOL cmdarg_SearchTypeBoolean(BYTE bArgType, CK_BBOOL* bOutValue, CK_BBOOL bdefaultValue)
{
   PARSER_CURRENT_CMD_ARG* arg = parser_SearchArgument(bArgType);
   CK_BYTE u8Loop;

   if (bOutValue == NULL)
   {
      return CK_FALSE;
   }
   // set out value to the default value
   *bOutValue = bdefaultValue;

   if (arg != NULL)
   {

      // Uppercase to lowercase
      arg->s_argPart2 = str_tolower(arg->s_argPart2);

      // loop on all boolean mech structure
      for (u8Loop = 0; u8Loop < SIZE_ARG_BOOLEAN; u8Loop++)
      {
         // if curve name match, return OID
         if (strcmp(arg_boolean[u8Loop].sParamName, arg->s_argPart2) == 0)
         {
            // set value
            *bOutValue = arg_boolean[u8Loop].bBool;

            // return param is present
            return CK_TRUE;
         }
      };

      printf("Wrong parameter for argument: %s,  %s \n", arg->s_argPart1, arg->s_argPart2);
      printf("Ignored set to true\n");

   }

   // 
   return CK_FALSE;
}

/*
    FUNCTION:        void P11STR_DisplaySupportedFileFormat()
*/
void P11STR_DisplaySupportedFileFormat()
{
   CK_BYTE u8Loop;

   printf("Supported file format :\n");
   // loop on all structure
   for (u8Loop = 0; u8Loop < SIZE_ARG_FILEFORMAT; u8Loop++)
   {
      printf("-> %s\n", arg_fileformat[u8Loop].sParamName);
   }
}

/*
    FUNCTION:        CK_BYTE cmdarg_SearchFileFormat(BYTE bArgType)
*/
CK_BYTE cmdarg_SearchFileFormat(BYTE bArgType)
{
   PARSER_CURRENT_CMD_ARG* arg = parser_SearchArgument(bArgType);
   CK_BYTE u8Loop;


   CK_CHAR_PTR sKeyTypeString = NULL;

   if (arg == NULL)
   {
      // request the user to enter a key value
      P11STR_DisplaySupportedFileFormat();
      printf("Enter file format : ");
      if (Console_RequestString() < 0)
      {
         return CK_NULL_ELEMENT;
      }
      sKeyTypeString = Console_GetBuffer();
   }
   else
   {
      sKeyTypeString = arg->s_argPart2;
   }


   // Uppercase to lowercase
   sKeyTypeString = str_tolower(sKeyTypeString);

   // loop on all rsa mech structure
   for (u8Loop = 0; u8Loop < SIZE_ARG_FILEFORMAT; u8Loop++)
   {
      // if curve name match, return OID
      if (strcmp(arg_fileformat[u8Loop].sParamName, sKeyTypeString) == 0)
      {
         return arg_fileformat[u8Loop].bFormat;
      }
   };


   printf("Wrong parameter for argument: -format,  %s \n", sKeyTypeString);

   return 0;
}



/*
    FUNCTION:        CK_OBJECT_CLASS cmdarg_GetKeyClass
*/
CK_OBJECT_CLASS cmdarg_GetKeyClass()
{
   PARSER_CURRENT_CMD_ARG* arg = parser_SearchArgument(ARG_TYPE_KEYCLASS);
   CK_OBJECT_CLASS cClass;
   CK_CHAR_PTR sKeyTypeString = NULL;


   if (arg == NULL)
   {
      // request the user to enter a key value
      P11Util_DisplaySupportedClass();
      printf("Enter key class : ");
      if (Console_RequestString() < 0)
      {
         return CK_NULL_ELEMENT;
      }
      sKeyTypeString = Console_GetBuffer();
   }
   else
   {
      sKeyTypeString = arg->s_argPart2;
   }


   // Uppercase to lowercase
   sKeyTypeString = str_tolower(sKeyTypeString);

   cClass = P11Util_GetClass(sKeyTypeString);

   if (cClass != CK_NULL_ELEMENT)
   {
      return cClass;
   }

   printf("Wrong parameter for argument: -keyclass,  %s \n", sKeyTypeString);

   return CK_NULL_ELEMENT;
}


/*
    FUNCTION:        CK_KEY_TYPE cmdarg_GetKeytype(CK_BBOOL bForceRequest) -keytype
*/
CK_KEY_TYPE cmdarg_GetKeytype(CK_BBOOL bForceRequest, CK_ULONG uFlag)
{
   PARSER_CURRENT_CMD_ARG* arg = parser_SearchArgument(ARG_TYPE_KEYTYPE);
   CK_KEY_TYPE cktype;
   CK_CHAR_PTR sKeyTypeString = NULL;


   if (arg == NULL)
   {
      if (bForceRequest == CK_TRUE)
      {
         // request the user to enter a key value
         P11Util_DisplaySupportedKeyType(uFlag);
         printf("Enter key type : ");
         if (Console_RequestString() < 0)
         {
            return CK_NULL_ELEMENT;
         }
      }
      // Get the console buffer from previous call to cmdarg_GetKeyClass or cmdarg_GetClassFromkeyType
      sKeyTypeString = Console_GetBuffer();
   }
   else
   {
      sKeyTypeString = arg->s_argPart2;
   }

   // Uppercase to lowercase
   sKeyTypeString = str_tolower(sKeyTypeString);

   // get cktype value
   cktype = P11Util_GetCKType(sKeyTypeString, uFlag);
   if (cktype != CK_NULL_ELEMENT)
   {
      return cktype;
   }
   printf("Wrong parameter for argument: -keytype,  %s \n", sKeyTypeString);

   return CK_NULL_ELEMENT;
}

/*
    FUNCTION:        CK_OBJECT_CLASS parser_SearchKeyType -keytype
*/
CK_OBJECT_CLASS cmdarg_GetClassFromkeyType(CK_ULONG uFlag)
{
   PARSER_CURRENT_CMD_ARG* arg = parser_SearchArgument(ARG_TYPE_KEYTYPE);
   CK_OBJECT_CLASS cClass;
   CK_CHAR_PTR sKeyTypeString = NULL;


   if (arg == NULL)
   {
      // request the user to enter a key value
      P11Util_DisplaySupportedKeyType(uFlag);
      printf("Enter key type : ");
      if (Console_RequestString() < 0)
      {
         return CK_NULL_ELEMENT;
      }
      sKeyTypeString = Console_GetBuffer();
   }
   else
   {
      sKeyTypeString = arg->s_argPart2;
   }

   // Uppercase to lowercase
   sKeyTypeString = str_tolower(sKeyTypeString);

   cClass = P11Util_GetClassFromCKType(sKeyTypeString, uFlag);

   if (cClass != CK_NULL_ELEMENT)
   {
      return cClass;
   }

   printf("Wrong parameter for argument: -keytype,  %s \n", sKeyTypeString);

   return CK_NULL_ELEMENT;
}

/*
    FUNCTION:        CK_LONG cmdarg_SearchTypeHexString(BYTE bArgType, CK_CHAR_PTR* sHexString)
*/
CK_LONG cmdarg_SearchTypeHexString(BYTE bArgType, CK_CHAR_PTR* sHexString)
{
   CK_LONG uLength;
   CK_CHAR_PTR sBuffer;

   do
   {
      // get string
      sBuffer = cmdarg_SearchTypeString(bArgType, NULL, 0);

      // if null
      if (sBuffer == NULL)
      {
         return 0;
      }

      // convert to hex binary string
      uLength = str_StringtoByteArray(sBuffer, (CK_ULONG)strlen(sBuffer));

      // if length is zero, retrun error
      if (uLength == 0)
      {
         printf("\nwrong string value, not hexadecimal: %s \n", sBuffer);
         break;
      }

      // return buffer and length
      *sHexString = sBuffer;
      return uLength;
   } while (FALSE);

   // return error
   return CK_NULL_ELEMENT;
}

/*
    FUNCTION:        CK_LONG cmdarg_GetCKA_ID(CK_CHAR_PTR * sHexString) -id
*/
CK_LONG cmdarg_GetCKA_ID(CK_CHAR_PTR sCkaId, CK_ULONG sBufferSize)
{
   CK_ULONG uLength;
   CK_CHAR_PTR sBuffer;

   do
   {
      // get CKA ID string
      sBuffer = cmdarg_SearchTypeString(ARG_TYPE_CKA_ID, NULL, 0);

      // if null
      if (sBuffer == NULL)
      {
         return 0;
      }

      // convert to hex binary string
      uLength = str_StringtoByteArray(sBuffer, (CK_ULONG)strlen(sBuffer));

      // if length is zero, retrun error
      if (uLength == 0)
      {
         printf("wrong CKA_ID value, not hexadecimal: -id=%s \n", sBuffer);
         break;
      }

      if (uLength > sBufferSize)
      {
         printf("wrong CKA_ID value, too big: maximum length is %i \n", sBufferSize);
         break;
      }

      // return buffer and length
      memcpy(sCkaId, sBuffer, uLength);
      return uLength;
   } while (FALSE);

   // return error
   return CK_NULL_ELEMENT;
}

/*
    FUNCTION:        CK_OBJECT_HANDLE cmdarg_GetHandleValue(CK_BYTE bArgType)
*/
CK_OBJECT_HANDLE cmdarg_GetHandleValue(CK_BYTE bArgType)
{
   PARSER_CURRENT_CMD_ARG* arg;
   arg = parser_SearchArgument(bArgType);
   CK_CHAR_PTR sHandleString = NULL;
   CK_LONG_64 sValue;

   if (arg == NULL)
   {

      // request user to enter a string
      switch (bArgType)
      {
      case ARG_TYPE_HANDLE_WRAPKEY:
         printf("Enter wrap key handle (or 0 to list all objects): ");
         break;
      case ARG_TYPE_HANDLE_UNWRAPKEY:
         printf("Enter unwrap key handle (or 0 to list all objects): ");
         break;
      case ARG_TYPE_HANDLE:
         printf("Enter key handle (or 0 to list all objects): ");
         break;
      case ARG_TYPE_HANDLE_DERIVE:
         printf("Enter key handle to derive (or 0 to list all objects): ");
         break;
      case ARG_TYPE_HANDLE_EXPORT:
         printf("Enter key handle to export (or 0 to list all objects): ");
         break;
      case ARG_TYPE_HANDLE_ENCRYPT:
         printf("Enter encryption key handle (or 0 to list all objects): ");
         break;
      case ARG_TYPE_HANDLE_DECRYPT:
         printf("Enter decryption key handle (or 0 to list all objects): ");
         break;
      case ARG_TYPE_HANDLE_DELETE:
         printf("Enter handle of the key to delete (or 0 to list all objects): ");
         break;
      case ARG_TYPE_HANDLE_DIG_KEY:
         printf("Enter handle of the key to digest (or 0 to list all objects): ");
         break;
      case ARG_TYPE_HANDLE_KCV:
         printf("Enter handle of the key to compute KCV (or 0 to list all objects): ");
         break;

      default:
         return CK_NULL_ELEMENT;
      }

      if (Console_RequestString() < 0)
      {
         return CK_NULL_ELEMENT;
      }

      // get console buffer
      sHandleString = Console_GetBuffer();

      // Check if value is 0 (list objects)
      if (str_StringtoUnsignedInteger(sHandleString) == 0)
      {
         // list all objects
         P11_FindAllObjects(CK_NULL_ELEMENT);

         // request for object value
         printf("Enter handle : ");
         if (Console_RequestString() < 0)
         {
            return CK_NULL_ELEMENT;
         }
      }
   }
   else
   {
      sHandleString = arg->s_argPart2;
   }

   // convert string to integrer
   sValue = str_StringtoUnsignedInteger(sHandleString);

   // if value negative, it means it is not an integer
   if (sValue < 0)
   {
      return CK_NULL_ELEMENT;
   }

   // return the object handle
   return (CK_OBJECT_HANDLE)sValue;
}

/*
    FUNCTION:        CK_LONG cmdarg_SearchTypeInteger(CK_BYTE bArgType)
*/
CK_LONG cmdarg_SearchTypeInteger(CK_BYTE bArgType)
{
   PARSER_CURRENT_CMD_ARG* arg;
   arg = parser_SearchArgument(bArgType);

   if (arg == NULL)
   {
      return CK_NULL_ELEMENT;
   }

   return (CK_ULONG)str_StringtoInteger(arg->s_argPart2);
}

/*
    FUNCTION:        CK_LONG cmdarg_SearchTypeUnsignedInteger(CK_BYTE bArgType)
*/
CK_LONG cmdarg_SearchTypeUnsignedInteger(CK_BYTE bArgType)
{
   PARSER_CURRENT_CMD_ARG* arg;
   arg = parser_SearchArgument(bArgType);

   if (arg == NULL)
   {
      return CK_NULL_ELEMENT;
   }

   return (CK_ULONG)str_StringtoUnsignedInteger(arg->s_argPart2);
}


/*
    FUNCTION:        P11_EXP_DOMAIN* cmdarg_GetExpDomain(CK_BBOOL bIsSubPrime)
*/
P11_EXP_DOMAIN* cmdarg_GetExpDomain(CK_BBOOL bIsSubPrime)
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_CHAR_PTR sString = NULL;
   CK_ULONG uLength;

   // clear sDh_Domain
   memset(&sDh_Domain, 0, sizeof(sDh_Domain));

   do
   {
      // get argument prime
      arg = parser_SearchArgument(ARG_TYPE_DH_PRIME);

      if (arg != NULL)
      {
         // convert to hexadecimal array
         uLength = str_StringtoByteArray(arg->s_argPart2, (CK_ULONG)strlen(arg->s_argPart2));

         // if length is zero, retrun error
         if (uLength == 0)
         {
            printf("wrong Prime value, not hexadecimal: -id=%s \n", arg->s_argPart2);
            break;
         }
         // set prime value and length
         sDh_Domain.sPrime = arg->s_argPart2;
         sDh_Domain.uPrimeLength = uLength;
      }
      else
      {
         printf("Missing parameter -prime\n");
         break;
      }

      // get argument base
      arg = parser_SearchArgument(ARG_TYPE_DH_BASE);

      if (arg != NULL)
      {
         // convert to hexadecimal array
         uLength = str_StringtoByteArray(arg->s_argPart2, (CK_ULONG)strlen(arg->s_argPart2));

         // if length is zero, retrun error
         if (uLength == 0)
         {
            printf("wrong base value, not hexadecimal: -id=%s \n", arg->s_argPart2);
            break;
         }
         // set base value and length
         sDh_Domain.sBase = arg->s_argPart2;
         sDh_Domain.uBaseLength = uLength;
      }
      else
      {
         printf("Missing parameter -base\n");
         break;
      }
      // check if mech is x942, and request sub prime
      if (bIsSubPrime == CK_TRUE)
      {
         // get argument prime
         arg = parser_SearchArgument(ARG_TYPE_DH_SUBPRIME);

         if (arg != NULL)
         {
            // convert to hexadecimal array
            uLength = str_StringtoByteArray(arg->s_argPart2, (CK_ULONG)strlen(arg->s_argPart2));

            // if length is zero, retrun error
            if (uLength == 0)
            {
               printf("wrong sub prime value, not hexadecimal: -id=%s \n", arg->s_argPart2);
               break;
            }
            // set sub prime value and length
            sDh_Domain.sSubPrime = arg->s_argPart2;
            sDh_Domain.uSubPrimeLength = uLength;
         }
         else
         {
            printf("Missing parameter -subprime\n");
            break;
         }

      }

      // return value in input argument
      return &sDh_Domain;
   } while (FALSE);

   return NULL;
}

/*
    FUNCTION:        CK_CHAR_PTR  cmdarg_SearchTypeString(CK_BYTE bLabelType, CK_CHAR_PTR sBuffer, CK_LONG sBufferSize)
*/
CK_CHAR_PTR  cmdarg_SearchTypeString(CK_BYTE bLabelType, CK_CHAR_PTR sBuffer, CK_ULONG sBufferSize)
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_CHAR_PTR sString = NULL;
   CK_ULONG uLength;

   // get argument
   arg = parser_SearchArgument(bLabelType);

   if (arg != NULL)
   {
      if (sBuffer != NULL)
      {

         // if the length of the string is not empty, return the string
         uLength = (CK_ULONG)strlen(arg->s_argPart2);
         if ((uLength != 0) && (uLength < sBufferSize))
         {
            strcpy(sBuffer, arg->s_argPart2);
            return sBuffer;
         }
      }
      return arg->s_argPart2;
   }
   else
   {
      // request only if the buffer is not null
      if (sBuffer != NULL)
      {
         // request user to enter a string
         switch (bLabelType)
         {
         case ARG_TYPE_CKA_LABEL:
            printf("Enter label for key : ");
            break;
         case ARG_TYPE_LABEL_PUB:
            printf("Enter label for public key : ");
            break;
         case ARG_TYPE_LABEL_PRIV:
            printf("Enter label for private key : ");
            break;
         case ARG_TYPE_FILE_OUTPUT:
            printf("Enter output file name : ");
            break;
         case ARG_TYPE_FILE_INPUT:
            printf("Enter input file name : ");
            break;
         case ARG_TYPE_KDF_LABEL:
            printf("Enter kdf label value as hexadecimal string (migth be empty) : ");
            break;
         case ARG_TYPE_KDF_CONTEXT:
            printf("Enter kdf context value as hexadecimal string (migth be empty) : ");
            break;
         default:
            return NULL;

         }

         // request user
         if (Console_RequestString() < 0)
         {
            return NULL;
         }

         // get string
         sString = Console_GetBuffer();

         // if the length of the string is not empty, return the string
         uLength = (CK_ULONG)strlen(sString);
         if ((uLength != 0) && (uLength < sBufferSize))
         {
            strcpy(sBuffer, sString);
            return sBuffer;
         }
      }
   }
   return NULL;
}

/*
    FUNCTION:        CK_LONG  cmdarg_GetKeySize(CK_ULONG uKeyType)
*/
CK_LONG  cmdarg_GetKeySize(CK_ULONG uKeyType)
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_CHAR_PTR sString = NULL;
   CK_LONG sValue;
   // get label
   arg = parser_SearchArgument(ARG_TYPE_KEYSIZE);

   if (arg == NULL)
   {

      // print supported key size for AES
      if (uKeyType == TYPE_KEY_SIZE_AES)
      {
         printf("AES Key size in byte, supported key size is: \n-> 16 for AES-128\n-> 24 for AES-192\n-> 32 for AES-256\n");
      }

      // print supported key size for DES
      else if (uKeyType == TYPE_KEY_SIZE_DES)
      {
         printf("DES Key size in byte, supported key size is: \n-> 8 for DES\n-> 16 for 2DES\n-> 24 for 3DES\n");
      }

      // print supported key size for generic keys
      else if (uKeyType == TYPE_KEY_SIZE_HMAC_GEN)
      {
         printf("HMAC and generic Key size in byte, supported key size is: \nMinimum-> 8 (64 bits)\nMinimum in FIPS mode-> 16 (128 bits)\nMaximum size-> 512 (4096 bits)\n");
      }

      // print supported key size for RSA keys
      else if (uKeyType == TYPE_KEY_SIZE_RSA)
      {
         printf("RSA Key size in bits, supported key size is: \n");
         printf("->pkcs method : Minimum 256, Maximum size-> 8192\n");
         printf("->prime method : Minimum 2048, Maximum size-> 8192\n");
         printf("->aux method : Minimum 1024, Maximum size-> 8192\n");
      }
      // print supported key size for ml dsa keys
      else if (uKeyType == TYPE_KEY_SIZE_MLDSA)
      {
         printf("ML-DSA Key size in bytes, supported key size is: \n");
         printf("->ML-DSA-44 : 1312\n");
         printf("->ML-DSA-65 : 1952\n");
         printf("->ML-DSA-87 : 2592\n");
      }
      // print supported key size for ml kem keys
      else if (uKeyType == TYPE_KEY_SIZE_MLKEM)
      {
         printf("ML-KEM Key size in bytes, supported key size is: \n");
         printf("->ML-KEM-512  : 800\n");
         printf("->ML-KEM-768  : 1184\n");
         printf("->ML-KEM-1024 : 1568\n");
      }

      // print supported key size for mzmk
      else if (uKeyType == TYPE_KEY_SIZE_MZMK)
      {
         printf("MZMK Key size in bytes, supported key size is: \n");
         printf("-> 16 for AES-128\n");
         printf("-> 24 for AES-192\n");
         printf("-> 32 for AES-256\n");
         printf("-> 24 for 3DES\n");
      }

      printf("Enter size for key : ");

      // request user
      if (Console_RequestString() < 0)
      {
         return 0;
      }

      // get string
      sString = Console_GetBuffer();

   }
   else
   {
      sString = arg->s_argPart2;
   }

   sValue = str_StringtoInteger(sString);

   // if length negative, return 0
   if (sValue < 0)
   {
      return 0;
   }

   return sValue;
}

/*
    FUNCTION:        CK_LONG  cmdarg_GetCompomentsNumber()
*/
CK_LONG  cmdarg_GetCompomentsNumber()
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_CHAR_PTR sString = NULL;
   CK_LONG sValue;
   // get label
   arg = parser_SearchArgument(ARG_TYPE_KEY_COMP);


   do
   {
      // check if argment present in the command
      if (arg == NULL)
      {
         break;
      }
      else
      {
         sString = arg->s_argPart2;
      }

      sValue = str_StringtoInteger(sString);

      if (sValue < 2 || sValue > 16)
      {
         printf("The number of valid component number must be between 2 to 16. \nparameter -clearcomponents ignored ");
         break;
      }



      return sValue;
   } while (FALSE);

   return 0;
}


/*
    FUNCTION:        CK_CHAR_PTR cmdarg_GetPublicExponant()
*/
P11_RSA_EXP* cmdarg_GetPublicExponant()
{
   PARSER_CURRENT_CMD_ARG* arg;
   P11_RSA_EXP* pKeyPublicExp;
   CK_CHAR_PTR sString = NULL;

   // Get public key exponant
   arg = parser_SearchArgument(ARG_TYPE_PUBLIC_EXP);

   do
   {
      // check if argment present in the command
      if (arg == NULL)
      {
         // display list of supported public exponant
         P11Util_DisplaySupportedPublicExp();


         printf("Enter public exponant value : ");
         // request user
         if (Console_RequestString() < 0)
         {
            return 0;
         }

         // get string
         sString = Console_GetBuffer();

      }
      else
      {
         sString = arg->s_argPart2;
      }

      // convert the argument to public exponant value
      pKeyPublicExp = P11Util_GetPublicExpParam(sString);

      // check if publix exponant is valid
      if (pKeyPublicExp == NULL)
      {
         break;
      }

      return pKeyPublicExp;
   } while (FALSE);

   return NULL;
}

/*
    FUNCTION:        CK_MECHANISM_TYPE cmdarg_GetRSAGenMechParam()
*/
CK_MECHANISM_TYPE cmdarg_GetRSAGenMechParam()
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_CHAR_PTR sString = NULL;

   // Get keygen mech
   arg = parser_SearchArgument(ARG_TYPE_KEYGEN_MECH);

   do
   {
      // check if argment present in the command
      if (arg == NULL)
      {
         // display list of supported public exponant
         P11Util_DisplaySupportedRSAGenMechParam();


         printf("Enter RSA key gen mecanism value : ");
         // request user
         if (Console_RequestString() < 0)
         {
            return 0;
         }

         // get string
         sString = Console_GetBuffer();

      }
      else
      {
         sString = arg->s_argPart2;
      }

      // Uppercase to lowercase
      sString = str_tolower(sString);

      // convert the argument to public exponant value
      return P11Util_GetRSAGenMechParam(sString);

   } while (FALSE);

   return -1;
}

/*
    FUNCTION:        CK_MECHANISM_TYPE cmdarg_GetDHGenMechParam()
*/
CK_MECHANISM_TYPE cmdarg_GetDHGenMechParam()
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_CHAR_PTR sString = NULL;

   // Get keygen mech
   arg = parser_SearchArgument(ARG_TYPE_KEYGEN_MECH);

   do
   {
      // check if argment present in the command
      if (arg == NULL)
      {
         // display list of supported public exponant
         P11Util_DisplaySupportedDHGenMechParam();


         printf("Enter RH key gen mecanism value : ");
         // request user
         if (Console_RequestString() < 0)
         {
            return 0;
         }

         // get string
         sString = Console_GetBuffer();

      }
      else
      {
         sString = arg->s_argPart2;
      }

      // Uppercase to lowercase
      sString = str_tolower(sString);

      // convert the argument to public exponant value
      return P11Util_GetDHGenMechParam(sString);

   } while (FALSE);

   return -1;
}

/*
    FUNCTION:        P11_ECC_OID* cmdarg_ArgGetEcCurveOIDParam(CK_KEY_TYPE sKeyType)
*/
P11_ECC_OID* cmdarg_ArgGetEcCurveOIDParam(CK_KEY_TYPE sKeyType)
{
   PARSER_CURRENT_CMD_ARG* arg;
   P11_ECC_OID* ecc_curve;
   CK_CHAR_PTR sString = NULL;

   // Get public key exponant
   arg = parser_SearchArgument(ARG_TYPE_ECC_CURVE);

   do
   {
      // check if argment present in the command
      if (arg == NULL)
      {

         printf("Enter ECC curve name (or 0 to list all supported curves): ");
         // request user
         if (Console_RequestString() < 0)
         {
            return 0;
         }

         // get string
         sString = Console_GetBuffer();

         // Check if value is 0 (list objects)
         if (str_StringtoInteger(sString) == 0)
         {
            P11Util_DisplaySupportedCurveName(sKeyType);
            // request for object value
            printf("Enter ECC curve name : ");
            if (Console_RequestString() < 0)
            {
               return NULL;
            }
         }
      }
      else
      {
         sString = arg->s_argPart2;
      }

      // convert the argument to public exponant value
      ecc_curve = P11Util_GetEcCurveOIDParam(sString);

      // check if ecc curve is valid
      if (ecc_curve == NULL)
      {
         break;
      }

      return ecc_curve;
   } while (FALSE);

   return NULL;
}

/*
    FUNCTION:        P11_ENCRYPTION_MECH* cmdarg_GetWrapAlgoValue()
*/
P11_ENCRYPTION_MECH* cmdarg_SearchEncryptionAlgoValue(BYTE bArgType)
{
   PARSER_CURRENT_CMD_ARG* arg;
   P11_ENCRYPTION_MECH* wrapalgo;
   CK_CHAR_PTR sString = NULL;
   CK_ULONG    bKeyFlag = KEY_TYPE_IMPORT_EXPORTKEY; //set the flag encrypt to accept only wrap algo
   BYTE bArgTypeOri = bArgType;

   // if the keytype is encryption, set the flag encrypt to accept only encryption algo
   if (bArgType == ARG_TYPE_ALGO)
   {
      bKeyFlag = KEY_TYPE_ENCRYPT;
   }
   else if (bArgType == ARG_TYPE_PBE)
   {
      bKeyFlag = KEY_TYPE_PBE;
      bArgType = ARG_TYPE_WRAP_ALGO;
   }

   // Get public key exponant
   arg = parser_SearchArgument(bArgType);



   do
   {
      // check if argment present in the command
      if (arg == NULL)
      {
         P11Util_DisplayEncryptionParam(bKeyFlag);
         // request user to enter a string
         switch (bArgTypeOri)
         {
         case ARG_TYPE_WRAP_ALGO:
            printf("Enter wrap algorithm : ");
            break;
         case ARG_TYPE_UNWRAP_ALGO:
            printf("Enter unwrap algorithm : ");
            break;
         case ARG_TYPE_ALGO:
            printf("Enter encryption algorithm : ");
            break;
         case ARG_TYPE_PBE:
            printf("Enter password based encryption algorithm : ");
            break;
         default:
            return NULL;
         }
         // request user
         if (Console_RequestString() < 0)
         {
            return NULL;
         }

         // get string
         sString = Console_GetBuffer();
      }
      else
      {
         sString = arg->s_argPart2;
      }

      // Uppercase to lowercase
      sString = str_tolower(sString);

      // convert the argument to public exponant value
      wrapalgo = P11Util_GetEncryptionParam(sString, bKeyFlag);

      // check if public exponant is valid
      if (wrapalgo == NULL)
      {
         break;
      }

      return wrapalgo;
   } while (FALSE);

   return NULL;
}

/*
    FUNCTION:       P11_DERIVE_MECH* cmdarg_SearchDerivationAlgoValue(BYTE bArgType)
*/
P11_DERIVE_MECH* cmdarg_SearchDerivationAlgoValue(BYTE bArgType)
{
   PARSER_CURRENT_CMD_ARG* arg;
   P11_DERIVE_MECH* sDeriveAlgo;
   CK_CHAR_PTR sString = NULL;

   // Get public key exponant
   arg = parser_SearchArgument(bArgType);

   do
   {
      // check if argment present in the command
      if (arg == NULL)
      {
         // display supported derivation mecansim
         P11Util_DisplayDerivationParam();

         // request user to enter a string
         printf("Enter derivation algorithm : ");

         // request user
         if (Console_RequestString() < 0)
         {
            return NULL;
         }

         // get string
         sString = Console_GetBuffer();
      }
      else
      {
         sString = arg->s_argPart2;
      }

      // Uppercase to lowercase
      sString = str_tolower(sString);

      // convert the argument to public exponant value
      sDeriveAlgo = P11Util_GetDerivationParam(sString);

      // check if public exponant is valid
      if (sDeriveAlgo == NULL)
      {
         break;
      }

      return sDeriveAlgo;
   } while (FALSE);

   return NULL;
}


/*
    FUNCTION:        CK_MECHANISM_TYPE cmdarg_SearchHash(BYTE bArgType)
*/
P11_HASH_MECH* cmdarg_SearchHash(BYTE bArgType)
{
   PARSER_CURRENT_CMD_ARG* arg = NULL;
   CK_CHAR_PTR          sString;
   CK_ULONG             uFlag = KEY_TYPE_HASH;

   if (bArgType == ARG_TYPE_RSA_OAEP_HASH)
   {
      uFlag = KEY_TYPE_ENCRYPT | KEY_TYPE_IMPORT_EXPORTKEY;
   }

   // Get argument -oaep_hash 
   arg = parser_SearchArgument(bArgType);

   if (arg == NULL)
   {
      // request the user to enter a key value
      P11Util_DisplaySupportedHash(uFlag);
      printf("Enter hash value : ");
      if (Console_RequestString() < 0)
      {
         return NULL;
      }
      sString = Console_GetBuffer();
   }
   else
   {
      sString = arg->s_argPart2;
   }

   // Uppercase to lowercase
   sString = str_tolower(sString);

   // convert the argument to public exponant value
   return P11Util_GetHash(sString, uFlag);
}

/*
P11_ENCRYPTION_MECH* cmdarg_GetEncryptionMecansim(BYTE bArgType)
*/
P11_ENCRYPTION_MECH* cmdarg_GetEncryptionMecansim(BYTE bArgType)
{
   P11_ENCRYPTION_MECH* DefaultEncryption_mech = NULL;
   CK_CHAR_PTR          sIV;
   CK_CHAR_PTR          sAAD;
   CK_ULONG             uLength;
   P11_KEYGENTEMPLATE sKeyGenTemplate = { 0 };


   memset(&sCustomEncryption_mech, 0, sizeof(P11_ENCRYPTION_MECH));

   do
   {
      // get algo
      if ((DefaultEncryption_mech = cmdarg_SearchEncryptionAlgoValue(bArgType)) == NULL)
      {
         break;
      }
      // Check encryption alogrithm type
      switch (DefaultEncryption_mech->ckMechType)
      {
      case CKM_AES_ECB:
      case CKM_AES_KWP:
      case CKM_AES_KW:
         // return default enc param
         return DefaultEncryption_mech;
      case CKM_AES_CBC:
      case CKM_AES_CBC_PAD:
      case CKM_AES_CFB8:
      case CKM_AES_CFB128:
      case CKM_AES_OFB:
      case CKM_AES_CBC_PAD_IPSEC:
         // Get sIV from argument
         sIV = cmdarg_ArgGetIV();

         // if iv is not null in argument, use it
         if (sIV != NULL)
         {
            // Set the encryption mecansim
            sCustomEncryption_mech.ckMechType = DefaultEncryption_mech->ckMechType;

            uLength = str_StringtoByteArray(sIV, (CK_ULONG)strlen(sIV));
            // convert the sIV to hex binary string
            if (uLength != AES_IV_LENGTH)
            {
               printf("wrong IV length or value: -iv=%s \n", sIV);
               break;
            }
            // Set the custom sIV
            sCustomEncryption_mech.aes_param.pIv = sIV;

            // return custom enc param
            return &sCustomEncryption_mech;
         }
         // return default enc param
         return DefaultEncryption_mech;

      case CKM_AES_GCM:
         // Get sIV from argument
         sIV = cmdarg_ArgGetIV();

         // if iv is not null in argument, use it
         if (sIV != NULL)
         {
            // Set the encryption mecansim
            sCustomEncryption_mech.ckMechType = DefaultEncryption_mech->ckMechType;

            uLength = str_StringtoByteArray(sIV, (CK_ULONG)strlen(sIV));
            // convert the sIV to hex binary string
            if (uLength < AES_GCM_IV_MIN_LENGTH)
            {
               printf("wrong IV length or value: -iv=%s \n", sIV);
               break;;
            }
            // Set the custom sIV
            sCustomEncryption_mech.aes_gcm_param.pIv = sIV;
            sCustomEncryption_mech.aes_gcm_param.ulIvLen = uLength;
            sCustomEncryption_mech.aes_gcm_param.ulIvBits = uLength << 3;

            // get authentication data
            sAAD = cmdarg_GetGCMAuthData();
            if (sAAD != NULL)
            {
               uLength = str_StringtoByteArray(sAAD, (CK_ULONG)strlen(sAAD));
               if (uLength == 0)
               {
                  printf("wrong Additionnal Authentification Data value, not hexadecimal: -aad=%s \n", sAAD);
                  break;
               }
               sCustomEncryption_mech.aes_gcm_param.pAAD = sAAD;
               sCustomEncryption_mech.aes_gcm_param.ulAADLen = uLength;
            }
            // Get auth data length
            uLength = cmdarg_GetGCMAuthTagLen();
            // if tag absent, set the default value
            if (uLength == CK_NULL_ELEMENT)
            {
               // set the default value to 96 bits
               sCustomEncryption_mech.aes_gcm_param.ulTagBits = AES_GCM_AUTH_TAG_LENGTH_96;
            }
            else if (uLength < 0)
            {
               printf("wrong  value, not a valid integer: -aad=%i \n", uLength);
               break;
            }
            else
            {
               // Set the length in bits
               sCustomEncryption_mech.aes_gcm_param.ulTagBits = uLength;
            }
            // return custom enc param
            return &sCustomEncryption_mech;
         }
         // return default enc param
         return DefaultEncryption_mech;

      case CKM_RSA_PKCS_OAEP:
         // Check if hash algo is defined in DefaultEncryption_mech
         if (DefaultEncryption_mech->rsa_oeap_param.hashAlg == 0)
         {
            P11_HASH_MECH* sHash = { 0 };
            sCustomEncryption_mech.ckMechType = CKM_RSA_PKCS_OAEP;

            // get the hash algo -hash
            sHash = cmdarg_SearchHash(ARG_TYPE_RSA_OAEP_HASH);

            if (sHash == NULL)
            {
               printf("wrong argument -hash \n");
               break;
            }

            // Set custom hash mecanism
            sCustomEncryption_mech.rsa_oeap_param.hashAlg = sHash->ckMechType;
            // set mgf hash
            sCustomEncryption_mech.rsa_oeap_param.mgf = sHash->ckMechOaepMgfType;
            // set source to CKZ_DATA_SPECIFIED
            sCustomEncryption_mech.rsa_oeap_param.source = CKZ_DATA_SPECIFIED;

            // return custom enc param
            return &sCustomEncryption_mech;
         }
         // return default enc param
         return DefaultEncryption_mech;
      }
   } while (FALSE);

   return NULL;
}

/*
P11_ENCRYPTION_MECH* cmdarg_GetPBEMecansim()
*/
P11_ENCRYPTION_MECH* cmdarg_GetPBEMecansim()
{
   P11_ENCRYPTION_MECH* DefaultEncryption_mech = NULL;
   CK_CHAR_PTR          sIV;
   CK_CHAR_PTR          sSalt;
   CK_ULONG             uLength;
   CK_LONG              lIteration = 0;
   P11_KEYGENTEMPLATE sKeyGenTemplate = { 0 };


   memset(&sCustomEncryption_mech, 0, sizeof(P11_ENCRYPTION_MECH));

   do
   {
      // get algo
      if ((DefaultEncryption_mech = cmdarg_SearchEncryptionAlgoValue(ARG_TYPE_PBE)) == NULL)
      {
         break;
      }
      // Check encryption alogrithm type
      switch (DefaultEncryption_mech->ckMechType)
      {
      case CKM_PKCS5_PBKD2:
         sCustomEncryption_mech.pbe_param.ckPbeMechType = CKM_PKCS5_PBKD2;

         // Change ckMechType with the symetric key mechanism
         sCustomEncryption_mech.ckMechType = DefaultEncryption_mech->pbe_param.ckEncMechType;
         sCustomEncryption_mech.sMechName = DefaultEncryption_mech->sMechName;

         // set key type
         sCustomEncryption_mech.pbe_param.sEncClass = DefaultEncryption_mech->pbe_param.sEncClass;
         sCustomEncryption_mech.pbe_param.ckEncMechType = DefaultEncryption_mech->pbe_param.ckEncMechType;
         sCustomEncryption_mech.pbe_param.sEnckeyType = DefaultEncryption_mech->pbe_param.sEnckeyType;
         sCustomEncryption_mech.pbe_param.sEnckeySize = DefaultEncryption_mech->pbe_param.sEnckeySize;

         lIteration = cmdarg_GetIteration();

         if (lIteration < 0)
         {
            // set default iteration
            sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.iterations = PBFKD2_DEFAULT_ITERATION;
         }
         else
         {
            sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.iterations = (CK_ULONG)lIteration;
         }

         // Set default prf (only hmac-sha1 supported by hsm)
         sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.prf = DefaultEncryption_mech->pbe_param.pbkdf2.pbfkd2_param.prf;

         // Set the salt
         sSalt = cmdarg_ArgGetSalt();
         if (sSalt == NULL)
         {
            P11_GenerateRandom((CK_BYTE_PTR)&sCustomEncryption_mech.pbe_param.pbkdf2.sSalt[0], sizeof(sCustomEncryption_mech.pbe_param.pbkdf2.sSalt));
            sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.pSaltSourceData = (CK_BYTE_PTR)&sCustomEncryption_mech.pbe_param.pbkdf2.sSalt;
            sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.ulSaltSourceDataLen = PBFKD2_SALT_LENGTH;
         }
         else
         {
            uLength = str_StringtoByteArray(sSalt, (CK_ULONG)strlen(sSalt));

            sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.pSaltSourceData = sSalt;
            sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.ulSaltSourceDataLen = uLength;

         }
         sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.saltSource = CKZ_SALT_SPECIFIED;

         // get password
         sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.pPassword = cmdarg_GetKeyPassword();
         sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.usPasswordLen = (CK_ULONG)strlen((CK_BYTE_PTR)sCustomEncryption_mech.pbe_param.pbkdf2.pbfkd2_param.pPassword);

         // get IV
         sIV = cmdarg_ArgGetIV();
         if (sIV == NULL)
         {
            // generate random sIV
            sIV = (CK_BYTE_PTR)&sCustomEncryption_mech.pbe_param.pbkdf2.sIV[0];
            P11_GenerateRandom(sIV, DefaultEncryption_mech->pbe_param.ulIvLen);
            // Set the sIV to the pointer
            sCustomEncryption_mech.pbe_param.pIv = (CK_BYTE_PTR)&sCustomEncryption_mech.pbe_param.pbkdf2.sIV;
         }
         else
         {

            uLength = str_StringtoByteArray(sIV, (CK_ULONG)strlen(sIV));
            // convert the sIV to hex binary string
            if (uLength != DefaultEncryption_mech->pbe_param.ulIvLen)
            {
               printf("wrong IV length or value: -iv=%s \n", sIV);
               break;
            }

            // Set the sIV to the pointer
            sCustomEncryption_mech.pbe_param.pIv = (CK_BYTE_PTR)sIV;
            sCustomEncryption_mech.pbe_param.ulIvLen = uLength;
         }

         // set IV length
         sCustomEncryption_mech.pbe_param.ulIvLen = DefaultEncryption_mech->pbe_param.ulIvLen;

         return &sCustomEncryption_mech;

      }
   } while (FALSE);

   return NULL;
}

/*
    FUNCTION:       P11_DERIVE_MECH* cmdarg_GetDerivationMecansim(BYTE bArgType)
*/
P11_DERIVE_MECH* cmdarg_GetDerivationMecansim(BYTE bArgType)
{
   P11_DERIVE_MECH* DefaultDerive_mech = NULL;
   CK_LONG_64           i64_Counter;
   CK_LONG              sBufferLength;
   CK_CHAR_PTR          pSBuffer = NULL;

   memset(&sDerive_Mech, 0, sizeof(P11_DERIVE_MECH));

   do
   {
      if ((DefaultDerive_mech = cmdarg_SearchDerivationAlgoValue(bArgType)) == NULL)
      {
         printf("wrong argument : -mech \n");
         break;
      }

      // Check derive alogrithm type
      switch (DefaultDerive_mech->ckMechType)
      {
      case CKM_PRF_KDF:
      case CKM_NIST_PRF_KDF:

         // set the derive mech in sDerive_Mech
         sDerive_Mech.ckMechType = DefaultDerive_mech->ckMechType;

         // get KDF type
         sDerive_Mech.sPrfKdfParams.prfType = cmdarg_GetKdfType();

         // if wrong kdf, return error
         if (sDerive_Mech.sPrfKdfParams.prfType == CK_NULL_ELEMENT)
         {
            printf("wrong value -kdk-type \n");
            return NULL;
         }

         // get KDF scheme
         sDerive_Mech.sPrfKdfParams.ulEncodingScheme = cmdarg_GetKdfScheme();

         // if wrong kdf, return error
         if (sDerive_Mech.sPrfKdfParams.ulEncodingScheme == CK_NULL_ELEMENT)
         {
            printf("wrong value -kdk-scheme \n");
            return NULL;
         }

         // get counter
         i64_Counter = cmdarg_GetKdfCounter();
         if (i64_Counter < 0)
         {
            printf("wrong value -kdk-counter \n");
         }
         sDerive_Mech.sPrfKdfParams.ulCounter = (CK_ULONG)i64_Counter;

         // get kdf label, don't request label
         sBufferLength = cmdarg_SearchTypeHexString(ARG_TYPE_KDF_LABEL, &pSBuffer);
         if (sBufferLength > 0)
         {
            // set label in structure
            sDerive_Mech.sPrfKdfParams.ulLabelLen = (CK_ULONG)sBufferLength;
            sDerive_Mech.sPrfKdfParams.pLabel = pSBuffer;
         }

         // get kdf context, don't request context
         sBufferLength = cmdarg_SearchTypeHexString(ARG_TYPE_KDF_CONTEXT, &pSBuffer);
         if (sBufferLength > 0)
         {
            // set context in structure
            sDerive_Mech.sPrfKdfParams.ulContextLen = (CK_ULONG)sBufferLength;
            sDerive_Mech.sPrfKdfParams.pContext = pSBuffer;
         }

         // return sDerive_Mech
         return &sDerive_Mech;

      case CKM_SHA1_KEY_DERIVATION:
      case CKM_SHA224_KEY_DERIVATION:
      case CKM_SHA256_KEY_DERIVATION:
      case CKM_SHA384_KEY_DERIVATION:
      case CKM_SHA512_KEY_DERIVATION:
      case CKM_SHA3_224_KEY_DERIVE:
      case CKM_SHA3_256_KEY_DERIVE:
      case CKM_SHA3_384_KEY_DERIVE:
      case CKM_SHA3_512_KEY_DERIVE:
         // do nothing, return DefaultDerive_mech
         break;

      default:
         printf("wrong argument : -mech \n");
         return NULL;
      }

      // return DefaultDerive_mech
      return DefaultDerive_mech;

   } while (FALSE);

   return NULL;
}

/*
    FUNCTION:       CK_KDF_PRF_TYPE cmdarg_GetKdfType()
*/
CK_KDF_PRF_TYPE cmdarg_GetKdfType()
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_CHAR_PTR sString = NULL;

   do
   {
      // get KDF type
      arg = parser_SearchArgument(ARG_TYPE_KDF_TYPE);

      if (arg == NULL)
      {
         P11Util_DisplayKdfType();

         // request user to enter a string
         printf("Enter KDF type algorithm : ");

         // request user
         if (Console_RequestString() < 0)
         {
            break;
         }

         // get string
         sString = Console_GetBuffer();

      }
      else
      {
         // use string in parameter
         sString = arg->s_argPart2;
      }

      // Uppercase to lowercase
      sString = str_tolower(sString);

      return P11Util_GetKdfType(sString);
   } while (FALSE);


   return CK_NULL_ELEMENT;
}

/*
    FUNCTION:       CK_KDF_PRF_ENCODING_SCHEME cmdarg_GetKdfScheme()
*/
CK_KDF_PRF_ENCODING_SCHEME cmdarg_GetKdfScheme()
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_CHAR_PTR sString = NULL;

   do
   {
      // get KDF type
      arg = parser_SearchArgument(ARG_TYPE_KDF_SCHEME);

      if (arg == NULL)
      {
         P11Util_DisplayKdfScheme();

         // request user to enter a string
         printf("Enter KDF scheme algorithm : ");

         // request user
         if (Console_RequestString() < 0)
         {
            break;
         }

         // get string
         sString = Console_GetBuffer();
      }
      else
      {
         // use string in parameter
         sString = arg->s_argPart2;
      }

      // Uppercase to lowercase
      sString = str_tolower(sString);

      return P11Util_GetKdfScheme(sString);
   } while (FALSE);


   return CK_NULL_ELEMENT;
}

/*
    FUNCTION:       CK_LONG_64 cmdarg_GetKdfCounter()
*/
CK_LONG_64 cmdarg_GetKdfCounter()
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_CHAR_PTR sString = NULL;

   do
   {
      // get KDF type
      arg = parser_SearchArgument(ARG_TYPE_KDF_COUNTER);

      if (arg == NULL)
      {

         // request user to enter a string
         printf("Enter KDF counter value between 0 and 4294967295 (0xFFFFFFFF) : ");

         // request user
         if (Console_RequestString() < 0)
         {
            break;
         }

         // get string
         sString = Console_GetBuffer();
      }
      else
      {
         // use string in parameter
         sString = arg->s_argPart2;
      }

      // Uppercase to lowercase
      sString = str_tolower(sString);

      return str_StringtoUnsignedInteger(sString);
   } while (FALSE);

   return -1;
}


/*
    FUNCTION:        BYTE cmdarg_GetKCVMethod()
*/
BYTE cmdarg_GetKCVMethod()
{
   PARSER_CURRENT_CMD_ARG* arg = NULL;
   CK_CHAR_PTR          sString;

   // Get argument -oaep_hash 
   arg = parser_SearchArgument(ARG_TYPE_METHOD_KCV);

   if (arg == NULL)
   {
      // request the user to enter a key value
      P11Util_DisplaySupportedKCVMethod();
      printf("Enter KCV Method : ");
      if (Console_RequestString() < 0)
      {
         return 0;
      }
      sString = Console_GetBuffer();
   }
   else
   {
      sString = arg->s_argPart2;
   }

   // Uppercase to lowercase
   sString = str_tolower(sString);

   // convert the argument to public exponant value
   return P11Util_GetKCVMethod(sString);
}

/*
    FUNCTION:        CK_ATTRIBUTE_TYPE cmdarg_AttributeType()
*/
CK_ATTRIBUTE_TYPE cmdarg_AttributeType()
{
   PARSER_CURRENT_CMD_ARG* arg = NULL;
   CK_CHAR_PTR          sString;

   // Get argument -attribute
   arg = parser_SearchArgument(ARG_TYPE_ATTR_NAME);

   if (arg == NULL)
   {
      // request the user to enter a attribute name
      P11Util_DisplaySupportedAttribute();
      printf("Enter Attribute Name : ");
      if (Console_RequestString() < 0)
      {
         return 0;
      }
      sString = Console_GetBuffer();
   }
   else
   {
      sString = arg->s_argPart2;
   }

   // Uppercase to lowercase
   sString = str_tolower(sString);

   // convert the attribute type
   return P11Util_GetAttributeType(sString);
}

/*
    FUNCTION:        CK_LONG cmdarg_GetKDFHexString(CK_BYTE bLabelType, CK_CHAR_PTR sBuffer, CK_ULONG sBufferSize)
*/
/*
CK_LONG cmdarg_GetKDFHexString(CK_BYTE bLabelType, CK_CHAR_PTR * pBuffer, CK_ULONG sBufferSize)
{
   CK_LONG uLength;
   CK_CHAR_PTR sBuffer = pBuffer[0];


   do
   {
      // get ID string
      sBuffer = cmdarg_SearchTypeString(bLabelType, sBuffer, sBufferSize);

      // if null
      if (sBuffer == NULL)
      {
         break;
      }

      // convert to hex binary string
      uLength = str_StringtoByteArray(sBuffer, (CK_ULONG)strlen(sBuffer));

      // if length is zero, retrun error
      if (uLength == 0)
      {
         printf("wrong string value, not hexadecimal: -id=%s \n", sBuffer);
         break;
      }

      // return buffer length
      sBuffer[uLength] = 0;
      *pBuffer = sBuffer;
      return uLength;
   } while (FALSE);

   // return error
   return CK_NULL_ELEMENT;
}*/

/*
    FUNCTION:        CK_CHAR_PTR cmdarg_GetKeyPassword()
*/
CK_CHAR_PTR cmdarg_GetKeyPassword()
{
   PARSER_CURRENT_CMD_ARG* arg;
   CK_CHAR_PTR sString = NULL;

   do
   {
      // get KDF type
      arg = parser_SearchArgument(ARG_TYPE_KEY_PASSWORD);

      if (arg == NULL)
      {
         // request user to enter a string
         printf("Enter the password for the password based encryption : ");

         // request user
         if (Console_RequestPassword() < 0)
         {
            break;
         }

         printf("\n\n");

         // get string
         sString = Console_GetBuffer();
      }
      else
      {
         // use string in parameter
         sString = arg->s_argPart2;
      }

      // Uppercase to lowercase
      sString = str_tolower(sString);

      return sString;
   } while (FALSE);

   return NULL;

}
