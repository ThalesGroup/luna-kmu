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

#define _CMD_C

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
#include "p11util.h"
#include "kmu.h"
#include "cmd.h"
#include "parser.h"
#include "cmdarg.h"
#include "file.h"
#include "str.h"
#include "asn1.h"
#include "pkcs8.h"
#include "console.h"
#include "tr31.h"
#include "tmd.h"

#define MAX_LABEL_SIZE        100
CK_CHAR  cmd_Label[MAX_LABEL_SIZE];
CK_CHAR  cmd_Label_public[MAX_LABEL_SIZE];
CK_CHAR  cmd_Label_private[MAX_LABEL_SIZE];

#define  MAX_CKA_ID_SIZE 4096
CK_CHAR  cmd_cka_ID[MAX_CKA_ID_SIZE];

#define MAX_FILE_NAME_SIZE       260
CK_CHAR  cmd_OutputFile[MAX_FILE_NAME_SIZE];
CK_CHAR  cmd_InputFile[MAX_FILE_NAME_SIZE];


/*
    FUNCTION:        CK_BBOOL cmd_IsLoggedIn(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_IsLoggedIn()
{
   // Check if session is loggued
   if (P11_IsLoggedIn() == CK_FALSE)
   {
      // Login
      if (cmd_kmu_login(CK_FALSE) != CK_TRUE)
      {
         return CK_FALSE;
      }
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL kmu_list(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_list(CK_BBOOL bIsConsole)
{
   CK_LONG uLimit = 0;
   if (cmd_IsLoggedIn() == CK_FALSE)
   {
      return CK_FALSE;
   }

   // get limit
   uLimit = cmdarg_Limit();

   // check if limit is set with correct integer value or absent.
   if (uLimit < 0)
   {
      if (uLimit != CK_NULL_ELEMENT)
      {
         printf("Invalid argument value, must be an integer: -limit\n");
         return CK_FALSE;
      }
   }

   return P11_FindAllObjects(uLimit);
}

/*
    FUNCTION:        CK_BBOOL kmu_list_SLot(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_list_SLot(CK_BBOOL bIsConsole)
{
   // List all the slot available
   if (P11_ListStot() > 0)
   {
      return CK_TRUE;
   }

   printf("Error : No slot available\n");
   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_login(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_login(CK_BBOOL bIsConsole)
{
   CK_SLOT_ID u32_SlotID;
   CK_CHAR_PTR sPassword;
   CK_CHAR_PTR sString;
   CK_BBOOL bUsePassword = CK_TRUE;
   CK_ULONG uStringLength;

   do
   {

      // Check if already logged in
      if (P11_IsLoggedIn() == CK_TRUE)
      {
         printf("Already loggin to a this slot. Please logout first\n");
         break;
      }

      // Select slot and login.
      u32_SlotID = cmdarg_GetSlotID();
      if (u32_SlotID == CK_NULL_ELEMENT)
      {
         // List Slot
         if (P11_ListStot() > 0)
         {
            printf("Select Slot : ");
            u32_SlotID = Console_RequestInteger();
         }
         else
         {
            // invalid input
            printf("Error : No slot available\n");
            break;
         }
         // call the console to get the slot ID
         if (u32_SlotID > 0x80000000)
         {
            // invalid input
            printf("Error : Invalid slot value\n");
            break;
         }
      }
      else if (u32_SlotID > 0x80000000)
      {
         printf("Error : Invalid slot value\n");
         break;
      }

      // Select Slot
      if (P11_SelectStot(u32_SlotID) == CK_NULL_ELEMENT)
      {
         printf("Error : Slot not found : %i\n", u32_SlotID);
         break;
      }


      // Get the password from argument
      sPassword = cmdarg_GetPassword();


      // request if need to use ped
      if ((sPassword == NULL) && (P11_IsLoginPasswordRequired() == CK_FALSE))
      {
         printf("\n\nThe TokenInfo flag CKF_PROTECTED_AUTHENTICATION_PATH is set.\n");
         printf("If the partition challenge is not initialized, you should use PED without password.\n");
         printf("Do you want to use PED without providing password ? (y/n): ");
         if (Console_RequestString() < 0)
         {
            break;
         }
         sString = Console_GetBuffer();
         uStringLength = (CK_ULONG)strlen(sString);

         // if answer is yes, use the PED
         if ((uStringLength == 1) && (sString[0] == 'y'))
         {
            bUsePassword = CK_FALSE;
            sPassword = NULL;
         }
      }

      // check if use password or not
      if (bUsePassword == CK_TRUE)
      {
         // request password if not provided
         if (sPassword == NULL)
         {
            // request for password
            printf("\nEnter the password : ");
            if (Console_RequestPassword() > 0)
            {
               // get password buffer
               sPassword = Console_GetBuffer();
            }
            printf("\n");
         }
      }

      // authenticate to selected slot ID
      if (P11_Login(u32_SlotID, sPassword, cmdarg_isCryptoUserLoginRequested()) != CKR_OK)
      {
         printf("login error\n");
         break;
      }

      return CK_TRUE;
   } while (FALSE);
   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_logout(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_logout(CK_BBOOL bIsConsole)
{
   // logout the current slot
   if (P11_Logout() == CKR_OK)
   {
      printf("Logged out\n");
      return CK_TRUE;
   }

   printf("Failed to logout.\n");
   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_getcapabilies(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_getcapabilities(CK_BBOOL bIsConsole)
{
   CK_SLOT_ID u32_SlotID = 0;
   CK_SLOT_INFO slotInfo = { 0 };
   do
   {
      // get the slot ID
      u32_SlotID = cmdarg_GetSlotID();

      // if not slot ID provided, use slot 0
      if (u32_SlotID == CK_NULL_ELEMENT)
      {
         u32_SlotID = 0;
      }
      
      // check if slot exist
      if (p11_GetSlotInfo(u32_SlotID, &slotInfo) == CK_FALSE)
      {
         printf("invalid slot ID \n");
         break;
      }

      // display the mecansim info
      P11Util_DisplayKeyGenMecanismInfo(u32_SlotID);

      return CK_TRUE;
   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_generateKey(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_generateKey(CK_BBOOL bIsConsole)
{
   P11_KEYGENTEMPLATE			sKeyGenTemplate = {0};
   CK_BBOOL							bKeyGenPair = CK_FALSE;
   CK_BBOOL                   bIsSubPrime = CK_FALSE;
   CK_LONG                    sComponentNumber;

   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // set attribute token, private ans sensitive to true as default value
      cmdarg_GetCKAToken(&sKeyGenTemplate.bCKA_Token);
      cmdarg_GetCKAPrivate(&sKeyGenTemplate.bCKA_Private);
      cmdarg_GetCKASensitive(&sKeyGenTemplate.bCKA_Sensitive);

      // Get attribute value from argument
      cmdarg_GetCKADecrypt(&sKeyGenTemplate.bCKA_Decrypt);
      cmdarg_GetCKAEncrypt(&sKeyGenTemplate.bCKA_Encrypt);
      cmdarg_GetCKASign(&sKeyGenTemplate.bCKA_Sign);
      cmdarg_GetCKAVerify(&sKeyGenTemplate.bCKA_Verify);
      cmdarg_GetCKAWrap(&sKeyGenTemplate.bCKA_Wrap);
      cmdarg_GetCKAUnwrap(&sKeyGenTemplate.bCKA_Unwrap);
      cmdarg_GetCKADerive(&sKeyGenTemplate.bCKA_Derive);
      cmdarg_GetCKAExtractable(&sKeyGenTemplate.bCKA_Extractable);
      cmdarg_GetCKAModifiable(&sKeyGenTemplate.bCKA_Modifiable);
      cmdarg_GetCKAEncapsulate(&sKeyGenTemplate.bCKA_Encapsulate);
      cmdarg_GetCKADecapsulate(&sKeyGenTemplate.bCKA_Decapsulate);

      // Get CKA id
      sKeyGenTemplate.pCKA_ID = cmd_cka_ID;
      sKeyGenTemplate.uCKA_ID_Length = cmdarg_GetCKA_ID(sKeyGenTemplate.pCKA_ID, MAX_CKA_ID_SIZE);
      if (sKeyGenTemplate.uCKA_ID_Length == CK_NULL_ELEMENT)
      {
         break;
      }
      
      // get class value from -keytype 
      if (((sKeyGenTemplate.sClass = cmdarg_GetClassFromkeyType(KEY_TYPE_GENKEY)) == CK_NULL_ELEMENT))
      {
         break;
      }

      // if private key, set the public key class
      if (sKeyGenTemplate.sClass == CKO_PRIVATE_KEY)
      {
         sKeyGenTemplate.sClassPublic = CKO_PUBLIC_KEY;
         bKeyGenPair = CK_TRUE;
      }

      // get keytype (CK_KEY_TYPE) from -keytype. Do not force to user to repeat -keytype if -keytype not provided
      if (((sKeyGenTemplate.skeyType = cmdarg_GetKeytype(CK_FALSE, KEY_TYPE_GENKEY)) == CK_NULL_ELEMENT))
      {
         break;
      }

      // Check if gen key pair
      if (bKeyGenPair)
      {
         // get label (-label)
         // if param is absent, will not request user
         sKeyGenTemplate.pKeyLabel = cmdarg_GetLabel(NULL,0);

         // if label is null, get public and private label
         if (sKeyGenTemplate.pKeyLabel == NULL)
         {
            // get label private
            sKeyGenTemplate.pKeyLabelPrivate = cmdarg_GetLabelPrivate(cmd_Label_private, MAX_LABEL_SIZE);
            // get label public
            sKeyGenTemplate.pKeyLabelPublic = cmdarg_GetLabelPublic(cmd_Label_public, MAX_LABEL_SIZE);

            if ((sKeyGenTemplate.pKeyLabelPrivate == NULL) && (sKeyGenTemplate.pKeyLabelPublic == NULL))
            {
               printf("Missing argument : -LabelPrivate and LabelPublic \n");
               break;
            }

         }
         else
         {
            // otherwise public and private label taken from label
            sKeyGenTemplate.pKeyLabelPublic = sKeyGenTemplate.pKeyLabel;
            sKeyGenTemplate.pKeyLabelPrivate = sKeyGenTemplate.pKeyLabel;
         }

         switch (sKeyGenTemplate.skeyType)
         {
         case CKK_RSA:
            // get arg size
            sKeyGenTemplate.skeySize = cmdarg_GetKeySize(TYPE_KEY_SIZE_RSA);

            if (sKeyGenTemplate.skeySize == 0)
            {
               printf("Invalid or missing arg  : -keysize\n");
               return CK_FALSE;
            }

            // Get public key exponant
            sKeyGenTemplate.pKeyPublicExp = cmdarg_GetPublicExponant();

            if (sKeyGenTemplate.pKeyPublicExp == NULL)
            {
               printf("Invalid or missing argument : -publicexponant\n");
               return CK_FALSE;
            }

            // get key gen mechanism
            sKeyGenTemplate.sKeyGenMech = cmdarg_GetRSAGenMechParam();
            if (sKeyGenTemplate.sKeyGenMech == -1)
            {
               return CK_FALSE;
            }
            break;
         case CKK_DH:
            bIsSubPrime = CK_FALSE;
            // get key gen mechanism
            sKeyGenTemplate.sKeyGenMech = cmdarg_GetDHGenMechParam();
            if (sKeyGenTemplate.sKeyGenMech == -1)
            {
               printf("Invalid or missing argument : -mech\n");
               return CK_FALSE;
            }

            // if x9.42 dh, force to request the subprime
            if (sKeyGenTemplate.sKeyGenMech == CKM_X9_42_DH_KEY_PAIR_GEN)
            {
               bIsSubPrime = CK_TRUE;
            }

            // request the DH domain
            sKeyGenTemplate.pDHDomain = cmdarg_GetExpDomain(bIsSubPrime);
            if (sKeyGenTemplate.pDHDomain == NULL)
            {
               return CK_FALSE;
            }
            break;
         case CKK_DSA:

            // request the DSA domain
            sKeyGenTemplate.pDSADomain = cmdarg_GetExpDomain(CK_TRUE);
            if (sKeyGenTemplate.pDHDomain == NULL)
            {
               return CK_FALSE;
            }
            break;
         case CKK_ECDSA:
         case CKK_SM2:
         case CKK_EC_EDWARDS:
         case CKK_EC_MONTGOMERY:
            // request OID
            sKeyGenTemplate.pECCurveOID = cmdarg_ArgGetEcCurveOIDParam(sKeyGenTemplate.skeyType);
            if (sKeyGenTemplate.pECCurveOID == NULL)
            {
               printf("Invalid or missing argument : -curve\n");
               return CK_FALSE;
            }
            break;

         case CKK_ML_DSA:

            // get arg size
            sKeyGenTemplate.skeySize = cmdarg_GetKeySize(TYPE_KEY_SIZE_MLDSA);

            if (sKeyGenTemplate.skeySize == 0)
            {
               printf("Invalid or missing arg  : -keysize\n");
               return CK_FALSE;
            }

            // get parameter set from key size
            sKeyGenTemplate.pML_DSA = P11Util_GetML_DSA_ParameterFromKeySize(sKeyGenTemplate.skeySize);

            if (sKeyGenTemplate.pML_DSA == NULL)
            {
               printf("Invalid size  : -keysize\n");
               return CK_FALSE;
            }
            break;

         case CKK_ML_KEM:

            // get arg size
            sKeyGenTemplate.skeySize = cmdarg_GetKeySize(TYPE_KEY_SIZE_MLKEM);

            if (sKeyGenTemplate.skeySize == 0)
            {
               printf("Invalid or missing arg  : -keysize\n");
               return CK_FALSE;
            }

            // get parameter set from key size
            sKeyGenTemplate.pML_KEM = P11Util_GetML_KEM_ParameterFromKeySize(sKeyGenTemplate.skeySize);

            if (sKeyGenTemplate.pML_KEM == NULL)
            {
               printf("Invalid size  : -keysize\n");
               return CK_FALSE;
            }
            break;

         default:
            return CK_FALSE;
         }
         // generate key pair
         return P11_GenerateKeyPair(&sKeyGenTemplate, NULL, NULL, CK_TRUE);
      }
      else // keygen
      {
         // get label (-label)
         sKeyGenTemplate.pKeyLabel = cmdarg_GetLabel(cmd_Label, MAX_LABEL_SIZE);

         if (sKeyGenTemplate.pKeyLabel == NULL)
         {
            printf("Missing argument : -label \n");
            break;
         }

         switch (sKeyGenTemplate.skeyType)
         {
         case CKK_AES:
            // for AES and hmac, key length is required
            if ((sKeyGenTemplate.skeySize = cmdarg_GetKeySize(TYPE_KEY_SIZE_AES)) == 0)
            {
               printf("Invalid or missing argument  : -keysize \n");
               return CK_FALSE;
            }
            break;

         case CKK_GENERIC_SECRET:   
            // for AES and hmac, key length is required
            if ((sKeyGenTemplate.skeySize = cmdarg_GetKeySize(TYPE_KEY_SIZE_HMAC_GEN)) == 0)
            {
               printf("Invalid or missing argument  : -keysize \n");
               return CK_FALSE;
            }
            break;
         case CKK_DES:
            // for AES and hmac, key length is required
            if ((sKeyGenTemplate.skeySize = cmdarg_GetKeySize(TYPE_KEY_SIZE_DES)) == 0)
            {
               printf("Invalid or missing argument  : -keysize \n");
               return CK_FALSE;
            }
            break;
         case CKK_SM4:
            // put the size for SM4
            sKeyGenTemplate.skeySize = SM4_KEY_LENGTH;
         }

         // get number of compomenent
         sComponentNumber = cmdarg_GetCompomentsNumber();

         // if no compoment, just generate a key
         if (sComponentNumber == 0)
         {
            // generate key
            return P11_GenerateKey(&sKeyGenTemplate, NULL, CK_TRUE);
         }
         else
         {

            // check key type is DES and AES
            switch (sKeyGenTemplate.skeyType)
            {
            case CKK_AES:
               if ((sKeyGenTemplate.skeySize == AES_128_KEY_LENGTH) || (sKeyGenTemplate.skeySize == AES_192_KEY_LENGTH) || (sKeyGenTemplate.skeySize == AES_256_KEY_LENGTH))
               {
                  break;
               }
               printf("Wrong key size\n");
               return CK_FALSE;
            case CKK_DES:
               if (sKeyGenTemplate.skeySize == DES_KEY_LENGTH)
               {
                  break;
               }
               if (sKeyGenTemplate.skeySize == DES2_KEY_LENGTH)
               {
                  sKeyGenTemplate.skeyType = CKK_DES2;
                  break;
               }
               if (sKeyGenTemplate.skeySize == DES3_KEY_LENGTH)
               {
                  sKeyGenTemplate.skeyType = CKK_DES3;
                  break;
               }
               printf("Wrong key size\n");
               return CK_FALSE;
            default:
               printf("Only DES and AES key are supported for generation using compoments\n");
               return CK_FALSE;
            }

            return cmd_GenerateSecretKeyWithComponent(&sKeyGenTemplate, sComponentNumber);
         }
      }
   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_createDO(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_createDO(CK_BBOOL bIsConsole)
{
   CK_OBJECT_HANDLE  hHandle = 0;

   P11_DOTEMPLATE sDoTemplate = {0};
   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // set attribute token, private ans sensitive to true as default value
       cmdarg_GetCKAToken(&sDoTemplate.bCKA_Token);
       cmdarg_GetCKAPrivate(&sDoTemplate.bCKA_Private);
       cmdarg_GetCKAModifiable(&sDoTemplate.bCKA_Modifiable);

      // get and request label (-label)
      sDoTemplate.pLabel = cmdarg_GetLabel(cmd_Label, MAX_LABEL_SIZE);
      if (sDoTemplate.pLabel == NULL)
      {
         printf("Missing argument : -label \n");
         break;
      }

      sDoTemplate.upValueLength = cmdarg_GetValue(&sDoTemplate.pValue);
      if (sDoTemplate.upValueLength == CK_NULL_ELEMENT)
      {
         printf("Wrong argument : -value \n");
         break;
      }

      sDoTemplate.pApplication = cmdarg_GetApp(NULL, 0);

      // create DO
      return P11_CreateDO(&sDoTemplate);

   } while (FALSE);

   return CK_FALSE;
}


/*
    FUNCTION:        CK_BBOOL cmd_kmu_getattribute(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_getattribute(CK_BBOOL bIsConsole)
{
   CK_OBJECT_HANDLE  hHandle = 0;
   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // get handle
      hHandle = cmdarg_GetHandleValue(ARG_TYPE_HANDLE);
      if (hHandle == CK_NULL_ELEMENT)
      {
         printf("wrong argument : -handle \n");
         break;
      }

      // display objects attributes
      return P11_GetAttributes(hHandle);

   } while (FALSE);

   return CK_FALSE;
}
/*
readattribute -handle=336 -outputfile=output.bin -attribute=value
*/

/*
    FUNCTION:        CK_BBOOL cmd_kmu_readattribute(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_readattribute(CK_BBOOL bIsConsole)
{
   CK_OBJECT_HANDLE  hHandle = 0;
   CK_CHAR_PTR       sFilePath = NULL;
   CK_ATTRIBUTE_TYPE cAttribute;
   CK_CHAR_PTR       sFileArray = NULL;
   CK_ULONG          sFileLength = 0;
   CK_BBOOL          bIsBinary = CK_FALSE;
   CK_ULONG          uWrittenSize = 0;

   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // get handle
      hHandle = cmdarg_GetHandleValue(ARG_TYPE_HANDLE);
      if (hHandle == CK_NULL_ELEMENT)
      {
         printf("wrong argument : -handle \n");
         break;
      }

      // search for object handle
      if (P11_FindObject(hHandle) == CK_FALSE)
      {
         printf("object with handle %i not found.\n", hHandle);
         break;
      }

      // get output file path
      sFilePath = cmdarg_GetOutputFilePath(cmd_OutputFile, MAX_FILE_NAME_SIZE);
      if (sFilePath == NULL)
      {
         printf("wrong or missing argument : -outputfile \n");
         break;
      }

      // getattribute type
      cAttribute = cmdarg_AttributeType();

      // read attributes
      if (P11_GetAttributesArray(hHandle, cAttribute, &sFileArray, &sFileLength) == CK_TRUE)
      {
         // check attribute type and set binary flag
         switch (cAttribute)
         {
         case CKA_ID:
         case CKA_VALUE:
            bIsBinary = CK_TRUE;
            break;
         }

         // write the file
         uWrittenSize = File_Write(sFilePath, sFileArray, sFileLength, bIsBinary);

         // free memory
         free(sFileArray);

         // Check of file is written
         if (uWrittenSize > 0)
         {
            printf("\n");
            printf("Successfull: %i bytes written in file : %s \n", uWrittenSize, sFilePath);
            return CK_TRUE;
         }

         printf("Error: Cannot write file : %s \n", sFilePath);
      }

   } while (FALSE);

   return CK_FALSE;
}
/*
writeattribute -handle=336 -inputfile=id.bin -attribute=value
writeattribute -handle=336 -inputfile=id.bin -attribute=application
writeattribute -handle=336 -inputfile=id.bin -attribute=application
writeattribute -handle=336 -inputfile=application.txt -attribute=application
*/
/*
    FUNCTION:        CK_BBOOL cmd_kmu_writeattribute(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_writeattribute(CK_BBOOL bIsConsole)
{
   CK_OBJECT_HANDLE  hHandle = 0;
   CK_CHAR_PTR       sFilePath = NULL;
   CK_ATTRIBUTE_TYPE cAttribute;
   CK_CHAR_PTR       sFileArray = NULL;
   CK_ULONG          sFileLength = 0;
   CK_BBOOL          bResult = CK_FALSE;
   CK_BBOOL          bValidFormat = CK_FALSE;

   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         return CK_FALSE;
      }

      // get handle
      hHandle = cmdarg_GetHandleValue(ARG_TYPE_HANDLE);
      if (hHandle == CK_NULL_ELEMENT)
      {
         printf("wrong argument : -handle \n");
         return CK_FALSE;
      }

      // search for object handle
      if (P11_FindObject(hHandle) == CK_FALSE)
      {
         printf("object with handle %i not found.\n", hHandle);
         return CK_FALSE;
      }

      // get output file path
      sFilePath = cmdarg_GetInputFilePath(cmd_InputFile, MAX_FILE_NAME_SIZE);
      if (sFilePath == NULL)
      {
         printf("wrong or missing argument : -inputfile \n");
         return CK_FALSE;
      }

      // getattribute type
      cAttribute = cmdarg_AttributeType();

      switch (cAttribute)
      {
      case CKA_ID:
      case CKA_VALUE:
         // read the file as binary
         sFileLength = File_Read(sFilePath, &sFileArray, CK_TRUE);
         bValidFormat = CK_TRUE;
         break;
      case CKA_APPLICATION:
         // read the file as non binary
         sFileLength = File_Read(sFilePath, &sFileArray, CK_FALSE);
         
         // check format ascii
         bValidFormat = str_CheckASCII(sFileArray, sFileLength);
         break;
      default:
         printf("invalid attribute name:\n");
         return CK_FALSE;
      }

      // check file
      if (sFileLength == 0)
      {
         printf("cannot read file : %s \n", sFilePath);
         break;
      }

      // check format
      if (bValidFormat == CK_FALSE)
      {
         printf("Invalid file format\n");
         break;
      }

      // set attribute in object
      bResult = P11_SetAttributeArray(hHandle, cAttribute, sFileArray, sFileLength);

   } while (FALSE);

   // release memory
   free(sFileArray);

   return bResult;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_setattribute(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_setattribute(CK_BBOOL bIsConsole)
{
   CK_OBJECT_HANDLE  hHandle = 0;
   CK_OBJECT_CLASS   sClass;
   CK_BYTE           bUpdateNumber = 0;

   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // get handle
      hHandle = cmdarg_GetHandleValue(ARG_TYPE_HANDLE);
      if (hHandle == CK_NULL_ELEMENT)
      {
         printf("wrong argument : -handle \n");
         break;
      }

      // search for object handle
      if (P11_FindObject(hHandle) == CK_FALSE)
      {
         printf("object with handle %i not found.\n", hHandle);
         break;
      }

      printf("\nAttempt to update attributes on object %i ...\n", hHandle);

      // get object class
      sClass = P11_GetObjectClass(hHandle);

      switch (sClass)
      {
      case CKO_SECRET_KEY:
      case CKO_PUBLIC_KEY:
      case CKO_PRIVATE_KEY:

         // update key attributes
         bUpdateNumber += cmd_setattributeBoolean(hHandle, ARG_TYPE_CKA_SIGN, CKA_SIGN);
         bUpdateNumber += cmd_setattributeBoolean(hHandle, ARG_TYPE_CKA_VERIFY, CKA_VERIFY);
         bUpdateNumber += cmd_setattributeBoolean(hHandle, ARG_TYPE_CKA_WRAP, CKA_WRAP);
         bUpdateNumber += cmd_setattributeBoolean(hHandle, ARG_TYPE_CKA_UNWRAP, CKA_UNWRAP);
         bUpdateNumber += cmd_setattributeBoolean(hHandle, ARG_TYPE_CKA_ENCRYPT, CKA_ENCRYPT);
         bUpdateNumber += cmd_setattributeBoolean(hHandle, ARG_TYPE_CKA_DECRYPT, CKA_DECRYPT);
         bUpdateNumber += cmd_setattributeBoolean(hHandle, ARG_TYPE_CKA_DERIVE, CKA_DERIVE);
         bUpdateNumber += cmd_setattributeBoolean(hHandle, ARG_TYPE_CKA_EXTRACTABLE, CKA_EXTRACTABLE);

         // update id
         bUpdateNumber += cmd_setattributeArray(hHandle, ARG_TYPE_CKA_ID, CKA_ID);

         break;
      case CKO_DATA:

         // update value
         bUpdateNumber += cmd_setattributeArray(hHandle, ARG_TYPE_CKA_VALUE, CKA_VALUE);
         // update application
         bUpdateNumber += cmd_setattributeString(hHandle, ARG_TYPE_CKA_APPLICATION, CKA_APPLICATION);

         break;
      default:
         printf("Unsupported object type\n");
         break;
      }

      // update generic object attribute
      bUpdateNumber += cmd_setattributeBoolean(hHandle, ARG_TYPE_CKA_PRIVATE, CKA_PRIVATE);
      bUpdateNumber += cmd_setattributeBoolean(hHandle, ARG_TYPE_CKA_MODIFIABLE, CKA_MODIFIABLE);

      // update label
      bUpdateNumber += cmd_setattributeString(hHandle, ARG_TYPE_CKA_LABEL, CKA_LABEL);

      
      // print number of attributes updated
      if (bUpdateNumber != 0)
      {
         if (bUpdateNumber == 1)
         {
            printf("\n%i attribute updated\n", bUpdateNumber);
         }
         else
         {
            printf("\n%i attributes updated\n", bUpdateNumber);
         }
      }
      else
      {
         printf("No attributes updated\n");
      }

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_import(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_import(CK_BBOOL bIsConsole)
{
   P11_UNWRAPTEMPLATE sUnwrapTemplate = { 0 };
   CK_BYTE           FileFormat = 0;
   CK_CHAR_PTR       sFilePath;
   CK_LONG           sComponentNumber = 0;

   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // Get attribute value from argument 
      cmdarg_GetCKAToken(&sUnwrapTemplate.bCKA_Token);
      cmdarg_GetCKAPrivate(&sUnwrapTemplate.bCKA_Private);
      cmdarg_GetCKASensitive(&sUnwrapTemplate.bCKA_Sensitive);
      cmdarg_GetCKADecrypt(&sUnwrapTemplate.bCKA_Decrypt);
      cmdarg_GetCKAEncrypt(&sUnwrapTemplate.bCKA_Encrypt);
      cmdarg_GetCKASign(&sUnwrapTemplate.bCKA_Sign);
      cmdarg_GetCKAVerify(&sUnwrapTemplate.bCKA_Verify);
      cmdarg_GetCKAWrap(&sUnwrapTemplate.bCKA_Wrap);
      cmdarg_GetCKAUnwrap(&sUnwrapTemplate.bCKA_Unwrap);
      cmdarg_GetCKADerive(&sUnwrapTemplate.bCKA_Derive);
      cmdarg_GetCKAExtractable(&sUnwrapTemplate.bCKA_Extractable);
      cmdarg_GetCKAModifiable(&sUnwrapTemplate.bCKA_Modifiable);
      cmdarg_GetCKAEncapsulate(&sUnwrapTemplate.bCKA_Encapsulate);
      cmdarg_GetCKADecapsulate(&sUnwrapTemplate.bCKA_Decapsulate);
      
      // Get CKA id
      sUnwrapTemplate.pCKA_ID = cmd_cka_ID;
      sUnwrapTemplate.uCKA_ID_Length = cmdarg_GetCKA_ID(sUnwrapTemplate.pCKA_ID, MAX_CKA_ID_SIZE);
      if (sUnwrapTemplate.uCKA_ID_Length == CK_NULL_ELEMENT)
      {
         break;
      }
   
      // get key type (CK_KEY_TYPE)
      if ((sUnwrapTemplate.skeyType = cmdarg_GetKeytype(CK_TRUE, KEY_TYPE_IMPORT_EXPORTKEY)) == CK_NULL_ELEMENT)
      {
         printf("wrong or missing argument : -keytype \n");
         break;
      }

      // get label
      if ((sUnwrapTemplate.pKeyLabel = cmdarg_GetLabel(cmd_Label, MAX_LABEL_SIZE)) == NULL)
      {
         printf("Missing argument : -label \n");
         break;
      }

      // get number of compomenent
      sComponentNumber = cmdarg_GetCompomentsNumber();

      // if compoment requested, import with component.
      if (sComponentNumber != 0)
      {
         sUnwrapTemplate.sClass = CKO_SECRET_KEY;

         if (sUnwrapTemplate.skeyType == CKK_AES)
         {
            // get key size
            sUnwrapTemplate.skeySize = cmdarg_GetKeySize(TYPE_KEY_SIZE_AES);

            if (sUnwrapTemplate.skeySize == 0)
            {
               printf("Invalid or missing arg : -keysize\n");
               break;;
            }
         }

         // check key type is DES and AES
         switch (sUnwrapTemplate.skeyType)
         {
         case CKK_AES:
            if ((sUnwrapTemplate.skeySize == AES_128_KEY_LENGTH) || (sUnwrapTemplate.skeySize == AES_192_KEY_LENGTH) || (sUnwrapTemplate.skeySize == AES_256_KEY_LENGTH))
            {
               break;
            }
            printf("Wrong key size\n");
            return CK_FALSE;
         case CKK_DES:
            sUnwrapTemplate.skeySize = DES_KEY_LENGTH;
            break;
         case CKK_DES2:
            sUnwrapTemplate.skeySize = DES2_KEY_LENGTH;
            break;
         case CKK_DES3:
            sUnwrapTemplate.skeySize = DES3_KEY_LENGTH;
            break;
         default:
            printf("Only DES and AES key are supported for importing key using compoments\n");
            return CK_FALSE;
         }

         // execute import with compoments
         return cmd_ImportSecretKeyWithComponent(&sUnwrapTemplate, sComponentNumber);
      }

      // get class value from arg -keyclass
      if ((sUnwrapTemplate.sClass = cmdarg_GetKeyClass()) == CK_NULL_ELEMENT)
      {
         printf("wrong or missing argument : -keyclass \n");
         break;
      }

      // get output file path
      sFilePath = cmdarg_GetInputFilePath(cmd_InputFile, MAX_FILE_NAME_SIZE);
      if (sFilePath == NULL)
      {
         printf("wrong or missing argument : -outputfile \n");
         break;
      }

      // get format (now only text or binary, not yet PKCS8)
      FileFormat = cmdarg_SearchFileFormat(ARG_TYPE_FORMAT_FILE);

      // ckeck class of key
      switch (sUnwrapTemplate.sClass)
      {
      case CKO_PRIVATE_KEY:
         if (FileFormat == FILE_FORMAT_PKCS8)
         {
            // To do : detect type from pem file

            sUnwrapTemplate.bPbe = CK_TRUE;
            return cmd_UnwrapPrivateSecretkey(&sUnwrapTemplate, sFilePath, FileFormat);
         }
         // continue
      case CKO_SECRET_KEY:
         // get handle for wrap key
         sUnwrapTemplate.hWrappingKey = cmdarg_GetHandleValue(ARG_TYPE_HANDLE_UNWRAPKEY);
         if (sUnwrapTemplate.hWrappingKey == CK_NULL_ELEMENT)
         {
            printf("wrong argument : -key \n");
            break;
         }

         // search for object handle
         if (P11_FindKeyObject(sUnwrapTemplate.hWrappingKey) == CK_FALSE)
         {
            printf("key with handle %i not found.\n", sUnwrapTemplate.hWrappingKey);
            break;
         }

         // Check if wrapping key has attribute CKA_UNWRAP
         if (P11_GetBooleanAttribute(sUnwrapTemplate.hWrappingKey, CKA_UNWRAP) == CK_FALSE)
         {
            printf("key with handle %i doesn't has CKA_UNWRAP attribute.\n", sUnwrapTemplate.hWrappingKey);
            break;
         }

         // check if file format is different of TR 31
         if (FileFormat != FILE_FORMAT_TR31)
         {
            // get wrap algo
            if ((sUnwrapTemplate.wrapmech = cmdarg_GetEncryptionMecansim(ARG_TYPE_UNWRAP_ALGO)) == NULL)
            {
               printf("wrong or missing argument : -algo \n");
               break;
            }

            // if wrap algo is AES KW, the input key size if required
            if (sUnwrapTemplate.wrapmech->ckMechType == CKM_AES_KW)
            {
               // get key size
               sUnwrapTemplate.skeySize = cmdarg_GetKeySize(TYPE_KEY_SIZE_AES);
            }
         }

         return cmd_UnwrapPrivateSecretkey(&sUnwrapTemplate, sFilePath, FileFormat);

      case CKO_PUBLIC_KEY:
         return cmd_ImportPublickey(&sUnwrapTemplate, sFilePath, FileFormat);
         break;
      }

   } while (FALSE);

   return CK_FALSE;
}
/*
    FUNCTION:        CK_BBOOL cmd_kmu_export(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_export(CK_BBOOL bIsConsole)
{

   CK_OBJECT_CLASS   KeyToWrapClass = -1;
   CK_CHAR_PTR       sFilePath;
   CK_BYTE           FileFormat = 0;
   P11_WRAPTEMPLATE  sExportTemplate = {0};

   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // get handle for key to wrap
      sExportTemplate.hKeyToExport = cmdarg_GetHandleValue(ARG_TYPE_HANDLE_EXPORT);
      if (sExportTemplate.hKeyToExport == CK_NULL_ELEMENT)
      {
         printf("wrong argument : -handle \n");
         break;
      }

      // search for object handle
      if (P11_FindKeyObject(sExportTemplate.hKeyToExport) == CK_FALSE)
      {
         printf("key with handle %i not found.\n", sExportTemplate.hKeyToExport);
         break;
      }

      // get output file path
      sFilePath = cmdarg_GetOutputFilePath(cmd_OutputFile, MAX_FILE_NAME_SIZE);
      if (sFilePath == NULL)
      {
         printf("wrong or missing argument : -outputfile \n");
         break;
      }

      // get format (now only text or binary, not yet PKCS8)
      FileFormat = cmdarg_SearchFileFormat(ARG_TYPE_FORMAT_FILE);
      if (FileFormat == 0)
      {
         break;
      }

      // get key to wrap class
      sExportTemplate.sClass = P11_GetObjectClass(sExportTemplate.hKeyToExport);

      // ckeck class of key
      switch (sExportTemplate.sClass)
      {
      case CKO_PRIVATE_KEY:

         // Check if key to export is extractable
         if (P11_GetBooleanAttribute(sExportTemplate.hKeyToExport, CKA_EXTRACTABLE) == CK_FALSE)
         {
            printf("key with handle %i is not extractable.\n", sExportTemplate.hKeyToExport);
            break;
         }

         // check if format is pkcs8. 
         // pkcs8 for private key is based on password based encryption
         if (FileFormat == FILE_FORMAT_PKCS8)
         {
            // get wrap algo
            sExportTemplate.wrap_key_mech = cmdarg_GetPBEMecansim();
            if (sExportTemplate.wrap_key_mech == NULL)
            {
               printf("wrong or missing argument : -algo \n");
               break;
            }

            // Set PBE mode
            sExportTemplate.bPbe = CK_TRUE;
         }
         else
         {
            // get wrap algo
            sExportTemplate.wrap_key_mech = cmdarg_GetEncryptionMecansim(ARG_TYPE_WRAP_ALGO);
            if (sExportTemplate.wrap_key_mech == NULL)
            {
               printf("wrong or missing argument : -algo \n");
               break;
            }

            // get handle for wrap key
            sExportTemplate.hWrappingKey = cmdarg_GetHandleValue(ARG_TYPE_HANDLE_WRAPKEY);
            if (sExportTemplate.hWrappingKey == CK_NULL_ELEMENT)
            {
               printf("wrong argument : -key \n");
               break;
            }

            // search for object handle
            if (P11_FindKeyObject(sExportTemplate.hWrappingKey) == CK_FALSE)
            {
               printf("key with handle %i not found.\n", sExportTemplate.hWrappingKey);
               break;
            }

            // Check if wrapping key has wrap attribute
            if (P11_GetBooleanAttribute(sExportTemplate.hWrappingKey, CKA_WRAP) == CK_FALSE)
            {
               printf("key with handle %i doesn't has CKA_WRAP attribute.\n", sExportTemplate.hKeyToExport);
               break;
            }
         }
         return cmd_WrapPrivateSecretkey(&sExportTemplate, sFilePath, FileFormat);

      case CKO_SECRET_KEY:

         // Check if key to export is extractable
         if (P11_GetBooleanAttribute(sExportTemplate.hKeyToExport, CKA_EXTRACTABLE) == CK_FALSE)
         {
            printf("key with handle %i is not extractable.\n", sExportTemplate.hKeyToExport);
            break;
         }

         // get wrap algo
         sExportTemplate.wrap_key_mech = cmdarg_GetEncryptionMecansim(ARG_TYPE_WRAP_ALGO);
         if (sExportTemplate.wrap_key_mech == NULL)
         {
            printf("wrong or missing argument : -algo \n");
            break;
         }

         // get handle for wrap key
         sExportTemplate.hWrappingKey = cmdarg_GetHandleValue(ARG_TYPE_HANDLE_WRAPKEY);
         if (sExportTemplate.hWrappingKey == CK_NULL_ELEMENT)
         {
            printf("wrong argument : -key \n");
            break;
         }

         // search for object handle
         if (P11_FindKeyObject(sExportTemplate.hWrappingKey) == CK_FALSE)
         {
            printf("key with handle %i not found.\n", sExportTemplate.hWrappingKey);
            break;
         }

         // Check if wrapping key has wrap attribute
         if (P11_GetBooleanAttribute(sExportTemplate.hWrappingKey, CKA_WRAP) == CK_FALSE)
         {
            printf("key with handle %i doesn't has CKA_WRAP attribute.\n", sExportTemplate.hKeyToExport);
            break;
         }

         return cmd_WrapPrivateSecretkey(&sExportTemplate, sFilePath, FileFormat);
      case CKO_PUBLIC_KEY:

         // get key to key type
         sExportTemplate.skeyType = P11_GetKeyType(sExportTemplate.hKeyToExport);

         // export the public key and write in file
         return cmd_ExportPublickey(&sExportTemplate, sFilePath, FileFormat);
      }
   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL    cmd_kmu_encrypt(CK_BBOOL bIsConsole)
*/
CK_BBOOL    cmd_kmu_encrypt(CK_BBOOL bIsConsole)
{
   P11_ENCRYPT_TEMPLATE    sEncryptTemplate = { 0 };
   CK_CHAR_PTR             sInputFilePath;
   CK_CHAR_PTR             sOutputFilePath;
   CK_BYTE                 FileFormat = 0;
   CK_BBOOL                bIsBinary = CK_FALSE;
   CK_BBOOL                bResult = CK_FALSE;
   CK_CHAR_PTR             sEncryptedData;
   CK_ULONG                sEncryptedDataLength;
   CK_ULONG                uWrittenSize = 0;

   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // get handle for encrpyion key
      sEncryptTemplate.hEncyptiontKey = cmdarg_GetHandleValue(ARG_TYPE_HANDLE_ENCRYPT);
      if (sEncryptTemplate.hEncyptiontKey == CK_NULL_ELEMENT)
      {
         printf("wrong or missing argument : -key \n");
         break;
      }

      // search for object handle
      if (P11_FindKeyObject(sEncryptTemplate.hEncyptiontKey) == CK_FALSE)
      {
         printf("key with handle %i not found.\n", sEncryptTemplate.hEncyptiontKey);
         break;
      }

      sEncryptTemplate.sClass = P11_GetObjectClass(sEncryptTemplate.hEncyptiontKey);
      sEncryptTemplate.skeyType = P11_GetKeyType(sEncryptTemplate.hEncyptiontKey);

      // Check if wrapping key has attribute CKA_UNWRAP
      if (P11_GetBooleanAttribute(sEncryptTemplate.hEncyptiontKey, CKA_ENCRYPT) == CK_FALSE)
      {
         printf("key with handle %i doesn't has CKA_ENCRYPT attribute.\n", sEncryptTemplate.hEncyptiontKey);
         break;
      }

      // get algo
      if ((sEncryptTemplate.encryption_mech = cmdarg_GetEncryptionMecansim(ARG_TYPE_ALGO)) == NULL)
      {
         printf("wrong or missing argument : -algo \n");
         break;
      }

      // get input file path
      sInputFilePath = cmdarg_GetInputFilePath(cmd_InputFile, MAX_FILE_NAME_SIZE);
      if (sInputFilePath == NULL)
      {
         printf("wrong or missing argument : -outputfile \n");
         break;
      }

      // get output file path
      sOutputFilePath = cmdarg_GetOutputFilePath(cmd_OutputFile, MAX_FILE_NAME_SIZE);
      if (sInputFilePath == NULL)
      {
         printf("wrong or missing argument : -outputfile \n");
         break;
      }

      // get format (now only text or binary, not yet PKCS8)
      FileFormat = cmdarg_SearchFileFormat(ARG_TYPE_FORMAT_FILE);
      if (FileFormat == 0)
      {
         break;
      }
      // Read hex file
      if (File_ReadHexFile(sInputFilePath, &sEncryptTemplate.sInputData, &sEncryptTemplate.sInputDataLength, (CK_BBOOL)(FileFormat & MASK_BINARY)) == CK_FALSE)
      {
         break;
      }

      // encrypt data
      bResult = P11_EncryptData(&sEncryptTemplate, &sEncryptedData, &sEncryptedDataLength);

      // release memory input data
      free(sEncryptTemplate.sInputData);

      // if encryption 
      if (bResult != CK_TRUE)
      {
         break;
      }

      // Write hex File
      uWrittenSize = File_WriteHexFile(sOutputFilePath, sEncryptedData, sEncryptedDataLength, (CK_BBOOL)(FileFormat & MASK_BINARY));

      // release memory
      free(sEncryptedData);

      // Check of file is written
      if (uWrittenSize > 0)
      {
         printf("\n");
         printf("Encrypt successfull: %i bytes written in file : %s \n", uWrittenSize, sOutputFilePath);
         return CK_TRUE;
      }

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL    cmd_kmu_decrypt(CK_BBOOL bIsConsole)
*/
CK_BBOOL    cmd_kmu_decrypt(CK_BBOOL bIsConsole)
{
   P11_ENCRYPT_TEMPLATE    sDecryptTemplate = { 0 };
   CK_CHAR_PTR             sInputFilePath;
   CK_CHAR_PTR             sOutputFilePath;
   CK_BYTE                 FileFormat = 0;
   CK_BBOOL                bIsBinary = CK_FALSE;
   CK_BBOOL                bResult = CK_FALSE;
   CK_CHAR_PTR             sDecryptedData;
   CK_ULONG                sDecryptedDataLength;
   CK_ULONG                uWrittenSize = 0;

   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // get handle for encrpyion key
      sDecryptTemplate.hEncyptiontKey = cmdarg_GetHandleValue(ARG_TYPE_HANDLE_DECRYPT);
      if (sDecryptTemplate.hEncyptiontKey == CK_NULL_ELEMENT)
      {
         printf("wrong argument : -key \n");
         break;
      }

      // search for object handle
      if (P11_FindKeyObject(sDecryptTemplate.hEncyptiontKey) == CK_FALSE)
      {
         printf("key with handle %i not found.\n", sDecryptTemplate.hEncyptiontKey);
         break;
      }

      sDecryptTemplate.sClass = P11_GetObjectClass(sDecryptTemplate.hEncyptiontKey);
      sDecryptTemplate.skeyType = P11_GetKeyType(sDecryptTemplate.hEncyptiontKey);

      // Check if wrapping key has attribute CKA_UNWRAP
      if (P11_GetBooleanAttribute(sDecryptTemplate.hEncyptiontKey, CKA_DECRYPT) == CK_FALSE)
      {
         printf("key with handle %i doesn't has CKA_DECRYPT attribute.\n", sDecryptTemplate.hEncyptiontKey);
         break;
      }

      // get wrap algo
      if ((sDecryptTemplate.encryption_mech = cmdarg_GetEncryptionMecansim(ARG_TYPE_ALGO)) == NULL)
      {
         printf("wrong or missing argument : -algo \n");
      }

      // get input file path
      sInputFilePath = cmdarg_GetInputFilePath(cmd_InputFile, MAX_FILE_NAME_SIZE);
      if (sInputFilePath == NULL)
      {
         printf("wrong or missing argument : -inputfile \n");
         break;
      }

      // get output file path
      sOutputFilePath = cmdarg_GetOutputFilePath(cmd_OutputFile, MAX_FILE_NAME_SIZE);
      if (sInputFilePath == NULL)
      {
         printf("wrong or missing argument : -outputfile \n");
         break;
      }

      // get format (now only text or binary, not yet PKCS8)
      FileFormat = cmdarg_SearchFileFormat(ARG_TYPE_FORMAT_FILE);
      if (FileFormat == 0)
      {
         break;
      }

      // Read hex file
      if (File_ReadHexFile(sInputFilePath, &sDecryptTemplate.sInputData, &sDecryptTemplate.sInputDataLength, (CK_BBOOL)(FileFormat & MASK_BINARY)) == CK_FALSE)
      {
         break;
      }

      // encrypt data
      bResult = P11_DecryptData(&sDecryptTemplate, &sDecryptedData, &sDecryptedDataLength);

      // release memory input data
      free(sDecryptTemplate.sInputData);

      // if encryption 
      if (bResult != CK_TRUE)
      {
         break;
      }

      // Write hex File
      uWrittenSize = File_WriteHexFile(sOutputFilePath, sDecryptedData, sDecryptedDataLength, (CK_BBOOL)(FileFormat & MASK_BINARY));

      // release memory
      free(sDecryptedData);

      // Check of file is written
      if (uWrittenSize > 0)
      {
         printf("\n");
         printf("Decrypt successfull : %i bytes written in file : %s \n", uWrittenSize, sOutputFilePath);
         return CK_TRUE;
      }

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_derive(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_derive(CK_BBOOL bIsConsole)
{
   P11_DERIVETEMPLATE sDeriveTemplate = {0};
   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // Get attribute value from argument 
      cmdarg_GetCKAToken(&sDeriveTemplate.bCKA_Token);
      cmdarg_GetCKAPrivate(&sDeriveTemplate.bCKA_Private);
      cmdarg_GetCKASensitive(&sDeriveTemplate.bCKA_Sensitive);
      cmdarg_GetCKADecrypt(&sDeriveTemplate.bCKA_Decrypt);
      cmdarg_GetCKAEncrypt(&sDeriveTemplate.bCKA_Encrypt);
      cmdarg_GetCKASign(&sDeriveTemplate.bCKA_Sign);
      cmdarg_GetCKAVerify(&sDeriveTemplate.bCKA_Verify);
      cmdarg_GetCKAWrap(&sDeriveTemplate.bCKA_Wrap);
      cmdarg_GetCKAUnwrap(&sDeriveTemplate.bCKA_Unwrap);
      cmdarg_GetCKADerive(&sDeriveTemplate.bCKA_Derive);
      cmdarg_GetCKAExtractable(&sDeriveTemplate.bCKA_Extractable);
      cmdarg_GetCKAModifiable(&sDeriveTemplate.bCKA_Modifiable);

      // Get CKA id
      sDeriveTemplate.pCKA_ID = cmd_cka_ID;
      sDeriveTemplate.uCKA_ID_Length = cmdarg_GetCKA_ID(sDeriveTemplate.pCKA_ID, MAX_CKA_ID_SIZE);
      if (sDeriveTemplate.uCKA_ID_Length == CK_NULL_ELEMENT)
      {
         break;
      }

      // get handle for master derivation key key
      sDeriveTemplate.hMasterKey = cmdarg_GetHandleValue(ARG_TYPE_HANDLE_DERIVE);
      if (sDeriveTemplate.hMasterKey == CK_NULL_ELEMENT)
      {
         break;
      }

      // get key class 
      sDeriveTemplate.sDerivedClass = cmdarg_GetClassFromkeyType(KEY_TYPE_DERIVEKEY);
      if (sDeriveTemplate.sDerivedClass == CK_NULL_ELEMENT)
      {
         printf("wrong or missing argument : -keytype \n");
         break;
      }

      // get key type (CK_KEY_TYPE)
      if ((sDeriveTemplate.sderivedKeyType = cmdarg_GetKeytype(CK_FALSE, KEY_TYPE_DERIVEKEY)) == CK_NULL_ELEMENT)
      {
         printf("wrong or missing argument : -keytype \n");
         break;
      }

      // get size according key type
      switch (sDeriveTemplate.sderivedKeyType)
      {
      case CKK_AES:
         sDeriveTemplate.sderivedKeyLength = cmdarg_GetKeySize(TYPE_KEY_SIZE_AES);
         break;
      case CKK_DES:
      case CKK_DES2:
      case CKK_DES3:
         sDeriveTemplate.sderivedKeyLength = cmdarg_GetKeySize(TYPE_KEY_SIZE_DES);
         break;
      case CKK_GENERIC_SECRET:
         sDeriveTemplate.sderivedKeyLength = cmdarg_GetKeySize(TYPE_KEY_SIZE_HMAC_GEN);
         break;
      default:
         printf("Invalid key type\n");
         return CK_FALSE;
      }

      // get derived key length
      if (sDeriveTemplate.sderivedKeyLength == 0)
      {
         printf("Invalid or missing argument  : -keysize \n");
         return CK_FALSE;
      }

      // get label (-label)
      sDeriveTemplate.pDerivedKeyLabel = cmdarg_GetLabel(cmd_Label, MAX_LABEL_SIZE);
      if (sDeriveTemplate.pDerivedKeyLabel == NULL)
      {
         printf("Missing argument : -label \n");
         break;
      }

      sDeriveTemplate.sDeriveMech = cmdarg_GetDerivationMecansim(ARG_TYPE_DERIVE_MECH);
      if (sDeriveTemplate.sDeriveMech == NULL)
      {
         break;
      }

      // derive the key
      return P11_DeriveKey(&sDeriveTemplate, NULL, CK_TRUE);

      return CK_TRUE;
   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_convert(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_convert(CK_BBOOL bIsConsole)
{
   CK_CHAR_PTR             sInputFilePath;
   CK_CHAR_PTR             sOutputFilePath;
   CK_BYTE                 bInputFileFormat = 0;
   CK_BYTE                 bOutputFileFormat = 0;
   CK_CHAR_PTR             sFileContent = NULL;
   CK_ULONG                uFileContentLength = 0;
   CK_BBOOL                bResult = CK_FALSE;
   do
   {

      // get output file path
      sInputFilePath = cmdarg_GetInputFilePath(cmd_InputFile, MAX_FILE_NAME_SIZE);
      if (sInputFilePath == NULL)
      {
         printf("wrong or missing argument : -outputfile \n");
         break;
      }

      // get output file path
      sOutputFilePath = cmdarg_GetOutputFilePath(cmd_OutputFile, MAX_FILE_NAME_SIZE);
      if (sOutputFilePath == NULL)
      {
         printf("wrong or missing argument : -outputfile \n");
         break;
      }

      // get in format 
      bInputFileFormat = cmdarg_SearchFileFormat(ARG_TYPE_INFORM_FILE);
      if (bInputFileFormat == 0)
      {
         break;
      }

      // get format (now only text or binary, not yet PKCS8)
      bOutputFileFormat = cmdarg_SearchFileFormat(ARG_TYPE_OUTFORM_FILE);
      if (bInputFileFormat == 0)
      {
         break;
      }

      if (bInputFileFormat == bOutputFileFormat)
      {
         printf("Input file format must be different of output file format\n");
         break;
      }

      // check file format
      switch (bInputFileFormat)
      {
      case FILE_FORMAT_BINARY:
      case FILE_FORMAT_TEXT:
         bResult = File_ReadHexFile(sInputFilePath, &sFileContent, &uFileContentLength, (CK_BBOOL)(bInputFileFormat & MASK_BINARY));
         break;
      default:
         printf("Wrong input file format\n");
         return CK_FALSE;
      }

      // if cannot read file
      if (bResult == CK_FALSE)
      {
         break;
      }

      switch (bOutputFileFormat)
      {
      case FILE_FORMAT_BINARY:
      case FILE_FORMAT_TEXT:
         // Write hex File
         uFileContentLength = File_WriteHexFile(sOutputFilePath, sFileContent, uFileContentLength, (CK_BBOOL)(bOutputFileFormat & MASK_BINARY));
         break;
      default:
         printf("Wrong output file format\n");
         break;
      }

      // free memory allocated when readin the file
      free(sFileContent);

      if (uFileContentLength > 0)
      {
         printf("\n");
         printf("convert : \n%i bytes written in file : %s \n", uFileContentLength, sOutputFilePath);
      }

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_delete(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_delete(CK_BBOOL bIsConsole)
{
   CK_OBJECT_HANDLE  hHandle = 0;
   CK_BBOOL bResult;
   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // get handle for encrpyion key
      hHandle = cmdarg_GetHandleValue(ARG_TYPE_HANDLE_DELETE);
      if (hHandle == CK_NULL_ELEMENT)
      {
         printf("wrong or missing argument : -handle \n");
         break;
      }

      // delete object handle
      bResult =  P11_DeleteObject(hHandle);

      if (bResult == CK_TRUE)
      {

         printf("Object with handle %i deleted\n", hHandle);
      }

      return bResult;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_digestKey(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_digestKey(CK_BBOOL bIsConsole)
{
   CK_OBJECT_HANDLE  hHandle = 0;
   P11_HASH_MECH*     sHashmech;
   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // get handle for encrpyion key
      hHandle = cmdarg_GetHandleValue(ARG_TYPE_HANDLE_DIG_KEY);
      if (hHandle == CK_NULL_ELEMENT)
      {
         printf("wrong or missing argument : -handle \n");
         break;
      }

      // search for object handle
      if (P11_FindKeyObject(hHandle) == CK_FALSE)
      {
         printf("key with handle %i not found.\n", hHandle);
         break;
      }

      if (P11_GetObjectClass(hHandle) != CKO_SECRET_KEY)
      {
         printf("Object is not a secret key\n");
         break;
      }
      

      // get handle for encrpyion key
      sHashmech = cmdarg_GetHash();
      if (sHashmech == NULL)
      {
         printf("wrong or missing argument : -hash \n");
         break;
      }
      // digest key
      return P11_DigestKey(sHashmech, hHandle);

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_compute_KCV(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_compute_KCV(CK_BBOOL bIsConsole)
{
   CK_OBJECT_HANDLE  hHandle = 0;
   BYTE bKCV_Method;
   CK_CHAR_PTR pKcvBuffer = NULL;

   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // get handle for encrpyion key
      hHandle = cmdarg_GetHandleValue(ARG_TYPE_HANDLE_KCV);
      if (hHandle == CK_NULL_ELEMENT)
      {
         printf("wrong or missing argument : -handle \n");
         break;
      }

      if ((bKCV_Method = cmdarg_GetKCVMethod()) == 0)
      {
         printf("wrong or missing argument : -method \n");
         break;
      }

      // call commute KCV
      if (P11_ComputeKCV(bKCV_Method, hHandle, &pKcvBuffer) == FALSE)
      {
         break;
      }

      printf("KCV of the key %u is equal to : ", hHandle);
      str_DisplayByteArraytoString("", pKcvBuffer, 3);

      // free buffer
      free(pKcvBuffer);

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_kmu_remote_mzmk(CK_BBOOL bIsConsole)
*/
CK_BBOOL cmd_kmu_remote_mzmk(CK_BBOOL bIsConsole)
{
   CK_CHAR_PTR             sInputFilePath = NULL;
   CK_CHAR_PTR             sInputFile = NULL;
   CK_CHAR_PTR             sOutPutFile = NULL;
   CK_CHAR_PTR             sHsmPublicKeyAsn1 = NULL;
   CK_BYTE_PTR             pKcvBuffer = NULL;
   CK_BYTE_PTR             pKcv = NULL;
   EC_PUBLIC_KEY           sTmdEcPublicKey = {0};
   EC_PUBLIC_KEY           sHsmEcPublicKey = { 0 };
   P11_KEYGENTEMPLATE      sKeyGenTemplate = { 0 };
   P11_DERIVETEMPLATE      sDeriveTemplate = { 0 };
   P11_DERIVE_MECH         sDeriveMech = { 0 };
   CK_OBJECT_HANDLE        hPrivateKey = 0;
   CK_OBJECT_HANDLE        hPublicKey = 0;
   CK_OBJECT_HANDLE        hMZMKKey = 0;
   CK_ULONG                sHsmPublicKeyAsn1Length = 0;
   CK_ULONG                sInputFileLength = 0;
   CK_BBOOL                bResult = CK_FALSE;

   do
   {
      // check if loggued to the slot
      if (cmd_IsLoggedIn() == CK_FALSE)
      {
         break;
      }

      // set attribute token, private ans sensitive to true as default value
      cmdarg_GetCKAToken(&sDeriveTemplate.bCKA_Token);
      cmdarg_GetCKAPrivate(&sDeriveTemplate.bCKA_Private);
      cmdarg_GetCKASensitive(&sDeriveTemplate.bCKA_Sensitive);

      // Get attribute value from argument
      cmdarg_GetCKADecrypt(&sDeriveTemplate.bCKA_Decrypt);
      cmdarg_GetCKAEncrypt(&sDeriveTemplate.bCKA_Encrypt);
      cmdarg_GetCKASign(&sDeriveTemplate.bCKA_Sign);
      cmdarg_GetCKAVerify(&sDeriveTemplate.bCKA_Verify);
      cmdarg_GetCKAWrap(&sDeriveTemplate.bCKA_Wrap);
      cmdarg_GetCKAUnwrap(&sDeriveTemplate.bCKA_Unwrap);
      cmdarg_GetCKADerive(&sDeriveTemplate.bCKA_Derive);
      cmdarg_GetCKAExtractable(&sDeriveTemplate.bCKA_Extractable);
      cmdarg_GetCKAModifiable(&sDeriveTemplate.bCKA_Modifiable);

      // Get CKA id
      sDeriveTemplate.pCKA_ID = cmd_cka_ID;
      sDeriveTemplate.uCKA_ID_Length = cmdarg_GetCKA_ID(sKeyGenTemplate.pCKA_ID, MAX_CKA_ID_SIZE);
      if (sDeriveTemplate.uCKA_ID_Length == CK_NULL_ELEMENT)
      {
         break;
      }

      // get MZMK key type 
      if ((sDeriveTemplate.sderivedKeyType = cmdarg_GetKeytype(CK_TRUE, KEY_TYPE_MZMK)) == CK_NULL_ELEMENT)
      {
         printf("wrong or missing argument : -keytype \n");
         break;
      }

      // get MZMK get size
      if ((sDeriveTemplate.sderivedKeyLength = cmdarg_GetKeySize(TYPE_KEY_SIZE_MZMK)) == 0)
      {
         printf("Invalid or missing argument  : -keysize \n");
         return CK_FALSE;
      }

      // check key type and size
      switch (sDeriveTemplate.sderivedKeyType)
      {
      case CKK_AES:

         if ((sDeriveTemplate.sderivedKeyLength == AES_128_KEY_LENGTH) || (sDeriveTemplate.sderivedKeyLength == AES_192_KEY_LENGTH) || (sDeriveTemplate.sderivedKeyLength == AES_256_KEY_LENGTH))
         {
            break;
         }
         printf("Wrong key size\n");
         return CK_FALSE;

      case CKK_DES:
         if (sDeriveTemplate.sderivedKeyLength == DES3_KEY_LENGTH)
         {
            sDeriveTemplate.sderivedKeyType = CKK_DES3;
            break;
         }

         printf("Wrong key size\n");
         return CK_FALSE;
      }

      if ((sDeriveTemplate.pDerivedKeyLabel = cmdarg_GetLabel(cmd_Label, MAX_LABEL_SIZE)) == NULL)
      {
         printf("Missing argument : -label \n");
         break;
      }

      // get output file path
      sInputFilePath = cmdarg_GetInputFilePath(cmd_InputFile, MAX_FILE_NAME_SIZE);
      if (sInputFilePath == NULL)
      {
         printf("wrong or missing argument : -outputfile \n");
         break;
      }

      // read input file
      if ((sInputFileLength = File_Read(sInputFilePath, &sInputFile, CK_FALSE)) == 0)
      {
         printf("cannot read input file : %s \n", sInputFilePath);
         break;
      }

      // convert to byte array
      sInputFileLength = str_StringtoByteArray(sInputFile, sInputFileLength);

      // Check if EC public key and get parameters. 
      if (pksc8_Check_PublicKeyInfoEC(&sTmdEcPublicKey, sInputFile, sInputFileLength, CKK_ECDSA) == CK_FALSE)
      {
         break;
      }

      // create a session ECDSA public key
      sKeyGenTemplate.skeyType = CKK_ECDSA;
      sKeyGenTemplate.sClass = CKO_PRIVATE_KEY;
      sKeyGenTemplate.sClassPublic = CKO_PUBLIC_KEY;
      sKeyGenTemplate.bCKA_Token = CK_FALSE;
      sKeyGenTemplate.bCKA_Private = CK_TRUE;
      sKeyGenTemplate.bCKA_Sensitive = CK_TRUE;
      sKeyGenTemplate.bCKA_Derive = CK_TRUE;
      sKeyGenTemplate.bCKA_Modifiable = CK_TRUE;
      sKeyGenTemplate.pCKA_ID = "";
      sKeyGenTemplate.uCKA_ID_Length = 0;
      sKeyGenTemplate.pECCurveOID = P11Util_GetEcCurveOID(sTmdEcPublicKey.sOid, sTmdEcPublicKey.uOidSize);
      sKeyGenTemplate.pKeyLabelPrivate = "tmd_temp_ecc_private";
      sKeyGenTemplate.pKeyLabelPublic = "tmd_temp_ecc_public";
      if (P11_GenerateKeyPair(&sKeyGenTemplate, &hPrivateKey, &hPublicKey, CK_FALSE) == CK_FALSE)
      {
         break;
      }

      // Derive MZMK Key with ECDH and SHA256 KDF, X9.63 derivation
      sDeriveTemplate.sDerivedClass = CKO_SECRET_KEY;
      sDeriveTemplate.hMasterKey = hPrivateKey;
      sDeriveTemplate.sDeriveMech = &sDeriveMech;
      sDeriveTemplate.sDeriveMech->ckMechType = CKM_ECDH1_DERIVE;
      sDeriveTemplate.sDeriveMech->sEcdh1DeriveParams.kdf = CKD_SHA256_KDF;
      sDeriveTemplate.sDeriveMech->sEcdh1DeriveParams.pSharedData = tmd_getShareinfo();
      sDeriveTemplate.sDeriveMech->sEcdh1DeriveParams.ulSharedDataLen = tmd_getShareinfoLength();
      sDeriveTemplate.sDeriveMech->sEcdh1DeriveParams.pPublicData = sTmdEcPublicKey.sPublicPoint;
      sDeriveTemplate.sDeriveMech->sEcdh1DeriveParams.ulPublicDataLen = sTmdEcPublicKey.uPublicPointLength;
      if (P11_DeriveKey(&sDeriveTemplate, &hMZMKKey, CK_TRUE) == CK_FALSE)
      {
         break;
      }

      // compute KCV for MZMK
      if (P11_ComputeKCV(KCV_PCI, hMZMKKey, &pKcvBuffer) == CK_FALSE)
      {
         break;
      }

      // display KCV
      str_DisplayByteArraytoString("MZMK Key check value : ", pKcvBuffer, 3);  
      
      // get ECDSA public key
      P11_GetEccPublicKey(hPublicKey, &sHsmEcPublicKey, CKK_ECDSA);

      // build public key info object
      pksc8_Build_PublicKeyInfoEC(&sHsmEcPublicKey, CKK_ECDSA);
      
      // convert to string array
      sHsmPublicKeyAsn1 = str_ByteArraytoString(asn1_BuildGetBuffer(), asn1_GetBufferSize());

      // get the path from the input file
      if (strlen(sInputFilePath) > MAX_PATH)
      {
         break;
      }

      // allocate buffer for output path
      sOutPutFile = malloc(MAX_PATH);
      if (sOutPutFile == NULL)
      {
         break;
      }

      // copy input path in out put and get the parent folder
      strcpy(sOutPutFile, sInputFilePath);
      str_PathRemoveFile(sOutPutFile, (CK_ULONG)strlen(sOutPutFile));
      pKcv = str_ByteArraytoString(pKcvBuffer, 3);

      // generate csv file for tmd
      if (tmd_generateCSVFile(sHsmPublicKeyAsn1, sDeriveTemplate.sderivedKeyType, sDeriveTemplate.sderivedKeyLength, pKcv, sOutPutFile) == CK_FALSE)
      {
         break;
      }

      bResult = CK_TRUE;
   } while (FALSE);


   // free memory
   if (sHsmPublicKeyAsn1 != NULL)
   {
      free(sHsmPublicKeyAsn1);
   }

   // free memory
   if (sInputFile != NULL)
   {
      free(sInputFile);
   }
  
   // free memory
   if (pKcvBuffer != NULL)
   {
      free(pKcvBuffer);
   }   

   // free memory
   if (pKcv != NULL)
   {
      free(pKcv);
   }

   // free memory
   if (sOutPutFile != NULL)
   {
      free(sOutPutFile);
   }

   // delete key pair
   if (hPrivateKey != 0)
   {
      P11_DeleteObject(hPrivateKey);
   }
   if (hPublicKey != 0)
   {
      P11_DeleteObject(hPublicKey);
   }
   return bResult;
}

/*
    FUNCTION:        CK_BBOOL cmd_WrapPrivateSecretkey(P11_WRAPTEMPLATE *  sWrapTemplate, CK_CHAR_PTR sFilePath, CK_BYTE FileFormat)
*/
CK_BBOOL cmd_WrapPrivateSecretkey(P11_WRAPTEMPLATE *  sWrapTemplate, CK_CHAR_PTR sFilePath, CK_BYTE FileFormat)
{
   CK_LONG              KeyToWrapSize = 0;
   CK_LONG              WrappingKeySize = 0;
   CK_CHAR_PTR          sWrappedkeyBuffer = NULL;
   CK_BBOOL             bResult = CK_FALSE;
   P11_KEYGENTEMPLATE   sKeyGenTemplate = { 0 };

   do
   {

      // pbe is activated, generate the pbe wrap key
      if (sWrapTemplate->bPbe == CK_TRUE)
      {
         // Create key gen template
         sKeyGenTemplate.sClass = sWrapTemplate->wrap_key_mech->pbe_param.sEncClass;
         sKeyGenTemplate.skeyType = sWrapTemplate->wrap_key_mech->pbe_param.sEnckeyType;
         sKeyGenTemplate.skeySize = sWrapTemplate->wrap_key_mech->pbe_param.sEnckeySize;
         sKeyGenTemplate.bCKA_Wrap = CK_TRUE;
         sKeyGenTemplate.bCKA_Unwrap = CK_TRUE;
         sKeyGenTemplate.pKeyLabel = "pbe_temp";
         sKeyGenTemplate.bCKA_Private = CK_TRUE;
         sKeyGenTemplate.bCKA_Sensitive = CK_TRUE;
         sKeyGenTemplate.bCKA_Token = CK_FALSE;

         // generate pbe wrap key
         if (P11_GenerateKeyPbe(&sKeyGenTemplate, &sWrapTemplate->hWrappingKey, &sWrapTemplate->wrap_key_mech->pbe_param, CK_FALSE) == CK_FALSE)
         {
            printf("C_WrapKey cannot generate pbe wrap key\n");
            break;
         }
      }

      // check format is text or binary
      if (!((FileFormat == FILE_FORMAT_TEXT) || (FileFormat == FILE_FORMAT_BINARY) || (FileFormat == FILE_FORMAT_PKCS8)))
      {
         printf("Wrong file format");
         break;
      }

      // Get key size
      KeyToWrapSize = P11_GetObjectSize(sWrapTemplate->hKeyToExport);
      WrappingKeySize = P11_GetObjectSize(sWrapTemplate->hWrappingKey);

      if (KeyToWrapSize != 0)
      {
         // we assume the size of the buffer is the max of key to wrap and wrapping key 
         // if symetric wrap size of key will be less than size of object, if rsa oaep wrap size will be the size of rsa key modulus
         CK_LONG AllocateSize = MAX(KeyToWrapSize, WrappingKeySize);

         // Allocate a buffer of the size of the key + extra
         sWrappedkeyBuffer = malloc(AllocateSize);
         if (sWrappedkeyBuffer == NULL)
         {
            printf("general error : cannot allocate memory \n");
            break;
         }

         // wrap the key
         if (P11_WrapPrivateSecretKey(sWrapTemplate, sWrappedkeyBuffer, &AllocateSize) == CK_TRUE)
         {
            CK_LONG writtenSize = 0;

            if (FileFormat == FILE_FORMAT_PKCS8)
            {
               CK_CHAR_PTR buffer;
               CK_BBOOL bResult;

               if (sWrapTemplate->bPbe == CK_TRUE)
               {
                  // create encrypted private key info
                  sWrapTemplate->wrap_key_mech->pbe_param.pWrappedKey = sWrappedkeyBuffer;
                  sWrapTemplate->wrap_key_mech->pbe_param.ulWrappedKeyLen = AllocateSize;
                  bResult = pksc8_Build_EncryptedPrivateKeyInfoPbe(&sWrapTemplate->wrap_key_mech->pbe_param);

                  if (bResult == CK_TRUE)
                  {
                     // Encode the asn1 string to pkcs8 pem
                     buffer = pkcs8_EncodeEncryptedPrivateKeyToPem(asn1_BuildGetBuffer(), asn1_GetBufferSize());

                     // write in file as string
                     writtenSize = File_Write(sFilePath, buffer, (CK_ULONG)strlen(buffer), CK_FALSE);

                     // release allocated buffer by pkcs8_EncodePublicKeyToPem
                     free(buffer);
                  }
               }
            }
            else
            {
               // Write hex File
               writtenSize = File_WriteHexFile(sFilePath, sWrappedkeyBuffer, AllocateSize, (CK_BBOOL)(FileFormat & MASK_BINARY));
            }
            if (writtenSize > 0)
            {
               bResult = CK_TRUE;
               printf("\n");
               printf("Export : Key (handle=%i) successfully wrapped with key (handle=%i).\n%i bytes written in file : %s \n", sWrapTemplate->hKeyToExport, sWrapTemplate->hWrappingKey, writtenSize, sFilePath);
            }
            else
            {
               printf("error writing in %s \n", sFilePath);
            }
         }
         else
         {
            printf("C_WrapKey command error\n");
         }

         // release allocated buffer
         free(sWrappedkeyBuffer);
      }
   } while (FALSE);

   if (sWrapTemplate->bPbe == CK_TRUE)
   {
      // delete pbe wrap key, generated before
      P11_DeleteObject(sWrapTemplate->hWrappingKey);
   }

   return bResult;
}

/*
    FUNCTION:        CK_BBOOL cmd_UnwrapPrivateSecretkey(P11_UNWRAPTEMPLATE* sUnwrapTemplate,  CK_CHAR_PTR sFilePath, CK_BYTE FileFormat)
*/
CK_BBOOL cmd_UnwrapPrivateSecretkey(P11_UNWRAPTEMPLATE* sUnwrapTemplate,  CK_CHAR_PTR sFilePath, CK_BYTE FileFormat)
{
   CK_BBOOL             bIsBinary = CK_FALSE;
   CK_CHAR_PTR          sWrappedKey = NULL;
   CK_ULONG             sWrappedKeyLength = 0;
   CK_BBOOL             bResult = CK_FALSE;
   CK_OBJECT_HANDLE     hKey = 0;
   P11_ENCRYPTION_MECH  wrapalgo = { 0 };
   P11_KEYGENTEMPLATE   sKeyGenTemplate = { 0 };

   do
   {
      // check file format
      switch (FileFormat)
      {
      case FILE_FORMAT_TEXT:
      case FILE_FORMAT_BINARY:
         // Read hex file
         if (File_ReadHexFile(sFilePath, &sWrappedKey, &sWrappedKeyLength, (CK_BBOOL)(FileFormat & MASK_BINARY)) == CK_FALSE)
         {
            printf("Cannot read file \n");
            break;
         }

         // call unwrap key fonction
         bResult = P11_UnwrapPrivateSecretKey(sUnwrapTemplate, sWrappedKey, sWrappedKeyLength, &hKey);
         break;

      case FILE_FORMAT_TR31:

         // read ascii file
         if (File_Read(sFilePath, &sWrappedKey, (CK_BBOOL)(FileFormat & MASK_BINARY)) == CK_FALSE)
         {
            printf("Cannot read file \n");
            break;
         }

         // call unwrap key fonction for TR 31
         bResult = TR31_UnwrapPrivateSecretKey(sUnwrapTemplate, sWrappedKey, &hKey);
         break;
      case FILE_FORMAT_PKCS8: 
         // check key type is private key
         if (sUnwrapTemplate->sClass != CKO_PRIVATE_KEY)
         {
            break;
         }

         // Read file
         sWrappedKeyLength = File_Read(sFilePath, &sWrappedKey, CK_FALSE);
         if (sWrappedKeyLength == CK_FALSE)
         {
            printf("Cannot read file \n");
            break;
         }

         if (sUnwrapTemplate->bPbe == CK_TRUE)
         {
            // Get private key from file
            sWrappedKeyLength = pkcs8_DecodeEncryptedPrivateKeyFromPem(sWrappedKey, sWrappedKeyLength);
            if (sWrappedKeyLength == 0)
            {
               printf("Cannot decode PKCS8 file \n");
               break;
            }

            // check encrypted private key
            if (pkcs8_Check_EncryptedPrivateKeyInfoPbe(&wrapalgo.pbe_param, sWrappedKey, sWrappedKeyLength) == CK_FALSE)
            {
               printf("Error when decoding EncryptedPrivateKeyInfo \n");
               break;
            }

            // get password
            wrapalgo.pbe_param.pbkdf2.pbfkd2_param.pPassword = cmdarg_GetKeyPassword();
            wrapalgo.pbe_param.pbkdf2.pbfkd2_param.usPasswordLen = (CK_ULONG)strlen((CK_BYTE_PTR)wrapalgo.pbe_param.pbkdf2.pbfkd2_param.pPassword);

            sKeyGenTemplate.sClass = wrapalgo.pbe_param.sEncClass;
            sKeyGenTemplate.skeyType = wrapalgo.pbe_param.sEnckeyType;
            sKeyGenTemplate.skeySize = wrapalgo.pbe_param.sEnckeySize;
            sKeyGenTemplate.bCKA_Wrap = CK_TRUE;
            sKeyGenTemplate.bCKA_Unwrap = CK_TRUE;
            sKeyGenTemplate.pKeyLabel = "pbkdf2_temp";
            sKeyGenTemplate.bCKA_Private = CK_TRUE;
            sKeyGenTemplate.bCKA_Sensitive = CK_TRUE;

            // generate pbe wrap key
            if (P11_GenerateKeyPbe(&sKeyGenTemplate, &sUnwrapTemplate->hWrappingKey, &wrapalgo.pbe_param, CK_FALSE) == CK_FALSE)
            {
               break;
            }

            sUnwrapTemplate->wrapmech = &wrapalgo;
            sUnwrapTemplate->wrapmech->ckMechType = wrapalgo.pbe_param.ckEncMechType;
         }
         else
         {
            // to do : other format not yet supported
            break;
         }

         // call unwrap key fonction
         bResult = P11_UnwrapPrivateSecretKey(sUnwrapTemplate, wrapalgo.pbe_param.pWrappedKey, wrapalgo.pbe_param.ulWrappedKeyLen, &hKey);

         break;

      default:
         printf("Wrong file format");
      }
   } while (FALSE);


   // check if successfull
   if (bResult == CK_TRUE)
   {
      printf("Key successfully unwrapped: handle is : %i, label is : %s \n", hKey, sUnwrapTemplate->pKeyLabel);
   }

   // release allocated buffer when reading file
   if (sWrappedKey != NULL)
   {
      free(sWrappedKey);
   }

   if (sUnwrapTemplate->bPbe == CK_TRUE)
   {
      // delete pbe wrap key, generated before
      P11_DeleteObject(sUnwrapTemplate->hWrappingKey);
   }

   return bResult;
}

/*
    FUNCTION:        CK_BBOOL cmd_ImportPublickey(P11_UNWRAPTEMPLATE* sImportTemplate, CK_CHAR_PTR sFilePath, CK_BYTE FileFormat)
*/
CK_BBOOL cmd_ImportPublickey(P11_UNWRAPTEMPLATE* sImportTemplate, CK_CHAR_PTR sFilePath, CK_BYTE FileFormat)
{
   CK_CHAR_PTR       sPublicKey = NULL;
   CK_ULONG          sPblicKeyLength = 0;;
   CK_BBOOL          bResult = CK_FALSE;
   CK_BBOOL          bIsBinary = CK_FALSE;
   PUBLIC_KEY        uPublicKey = { 0 };
   
   // if file binary set the flag
   if (FileFormat == FILE_FORMAT_BINARY)
   {
      bIsBinary = CK_TRUE;
   }

   // read file
   sPblicKeyLength = File_Read(sFilePath, &sPublicKey, bIsBinary);

   // check if can read the file
   if (sPblicKeyLength == 0)
   {
      printf("Cannot read file : %s \n", sFilePath);
      return CK_FALSE;
   }

   do
   {
      // if format test, convert string to byte array
      if (FileFormat == FILE_FORMAT_TEXT)
      {

         // convert to byte hex string before calling unwrap
         sPblicKeyLength = str_StringtoByteArray(sPublicKey, sPblicKeyLength);

         if (sPblicKeyLength == 0)
         {
            printf("File format error. Size must be multiple of 2 bytes and hexadecimal value\n");
            break;
         }
      }
      // if format PKsc8, convert to byte array
      else if (FileFormat == FILE_FORMAT_PKCS8)
      {

         // Get Public key from file
         sPblicKeyLength = pkcs8_DecodePublicKeyFromPem(sPublicKey, sPblicKeyLength);

         if (sPblicKeyLength == 0)
         {
            printf("cannot decode PKCS8 file \n");
            break;
         }
      }

      // check the key type
      switch (sImportTemplate->skeyType)
      {
      case CKK_RSA:
         // check RSApublicKeyInfo
         bResult = pksc8_Check_PublicKeyInfoRSA(&uPublicKey.sRsaPublicKey, sPublicKey, sPblicKeyLength);
         break;

      case CKK_DSA:
         // check RSApublicKeyInfo
         bResult = pksc8_Check_PublicKeyInfoDSA(&uPublicKey.sDsaPublicKey, sPublicKey, sPblicKeyLength);
         break;
      case CKK_DH:
         // check RSApublicKeyInfo
         bResult = pksc8_Check_PublicKeyInfoDH(&uPublicKey.sDhPublicKey, sPublicKey, sPblicKeyLength);
         break;

      case CKK_ECDSA:
      case CKK_EC_EDWARDS:
      case CKK_EC_MONTGOMERY:
      case CKK_EC_EDWARDS_OLD:
      case CKK_EC_MONTGOMERY_OLD:
      case CKK_SM2:
         // check ECpublicKeyInfo
         bResult = pksc8_Check_PublicKeyInfoEC(&uPublicKey.sEcPublicKey, sPublicKey, sPblicKeyLength, sImportTemplate->skeyType);
         break;

      case CKK_ML_DSA:
         // check MLDSApublicKeyInfo
         bResult = pksc8_Check_PublicKeyInfoMLDSA(&uPublicKey.sMlDsaPublicKey, sPublicKey, sPblicKeyLength);
         break;

      case CKK_ML_KEM:
         // check MLKEMpublicKeyInfo
         bResult = pksc8_Check_PublicKeyInfoMLKEM(&uPublicKey.sMlKemPublicKey, sPublicKey, sPblicKeyLength);
         break;
      
      default:
         break;
      }

      // if decoding is corret, create the public key object
      if (bResult == CK_TRUE)
      {
         // Create public key object
         bResult = P11_CreatePublicKey(sImportTemplate, &uPublicKey);
         break;
      }

      printf("Error when decoding publicKeyInfo \n");

   } while (FALSE);


   // release allocated buffer
   free(sPublicKey);

   return bResult;
}

/*
    FUNCTION:        CK_BBOOL cmd_ExportPublickey(P11_WRAPTEMPLATE* sExportTemplate, CK_CHAR_PTR sFilePath, CK_BYTE FileFormat)
*/
CK_BBOOL cmd_ExportPublickey(P11_WRAPTEMPLATE* sExportTemplate, CK_CHAR_PTR sFilePath, CK_BYTE FileFormat)
{
   PUBLIC_KEY        sPublicKey = { 0 };
   CK_LONG           writtenSize = 0;
   // temp

   switch (sExportTemplate->skeyType)
   {
   case CKK_RSA:
      
      // read public key
      if (P11_GetRsaPublicKey(sExportTemplate->hKeyToExport, &sPublicKey.sRsaPublicKey) == CK_TRUE)
      {
         // build RSA public key info
         pksc8_Build_PublicKeyInfoRSA(&sPublicKey.sRsaPublicKey);
         break;
      }

      printf("Error: Cannot read RSA public key");
      return CK_FALSE;
   case CKK_DSA:

      // read public key
      if (P11_GetDsaPublicKey(sExportTemplate->hKeyToExport, &sPublicKey.sDsaPublicKey) == CK_TRUE)
      {
         // build RSA public key info
         pksc8_Build_PublicKeyInfoDSA(&sPublicKey.sDsaPublicKey);
         break;
      }

      printf("Error: Cannot read DSA public key");
      return CK_FALSE;
   case CKK_DH:
   case CKK_X9_42_DH:

      // read public key
      if (P11_GetDHPublicKey(sExportTemplate->hKeyToExport, &sPublicKey.sDhPublicKey, sExportTemplate->skeyType) == CK_TRUE)
      {
         // build RSA public key info
         pksc8_Build_PublicKeyInfoDH(&sPublicKey.sDhPublicKey);
         break;
      }
      printf("Error: Cannot read DH public key");
      return CK_FALSE;
   case CKK_ECDSA:
   case CKK_EC_EDWARDS:
   case CKK_EC_EDWARDS_OLD:
   case CKK_EC_MONTGOMERY:
   case CKK_EC_MONTGOMERY_OLD:
   case CKK_SM2:
      if (P11_GetEccPublicKey(sExportTemplate->hKeyToExport, &sPublicKey.sEcPublicKey, sExportTemplate->skeyType) == CK_TRUE)
      {
         // build EC public key info
         pksc8_Build_PublicKeyInfoEC(&sPublicKey.sEcPublicKey, sExportTemplate->skeyType);
         break;
      }

      printf("Error: Cannot read ECC public key");
      return CK_FALSE;
   case CKK_ML_DSA:
      if (P11_GetMLDSAPublicKey(sExportTemplate->hKeyToExport, &sPublicKey.sMlDsaPublicKey) == CK_TRUE)
      {
         // build ML DSA public key info
         pksc8_Build_PublicKeyInfoMLDSA(&sPublicKey.sMlDsaPublicKey);
         break;
      }

      printf("Error: Cannot read ML-DSA public key");
      return CK_FALSE;
   case CKK_ML_KEM:
      if (P11_GetMLKEMPublicKey(sExportTemplate->hKeyToExport, &sPublicKey.sMlKemPublicKey) == CK_TRUE)
      {
         // build ML KEM public key info
         pksc8_Build_PublicKeyInfoMLKEM(&sPublicKey.sMlKemPublicKey);
         break;
      }

      printf("Error: Cannot read ML-KEM: public key");
      return CK_FALSE;

   default:
      return CK_FALSE;
   }

   // if format is text, convert to string
   if (FileFormat == FILE_FORMAT_TEXT)
   {
      // convert string byte array to string 
      CK_CHAR_PTR buffer = str_ByteArraytoString(asn1_BuildGetBuffer(), asn1_GetBufferSize());

      // write in file as string
      writtenSize = File_Write(sFilePath, buffer, (CK_ULONG)strlen(buffer), CK_FALSE);

      // release allocated buffer by str_ByteArraytoString
      free(buffer);
   }
   else if (FileFormat == FILE_FORMAT_BINARY)
   {
      // write in file as binary
      writtenSize = File_Write(sFilePath, asn1_BuildGetBuffer(), asn1_GetBufferSize(), CK_TRUE);
   }
   else if (FileFormat == FILE_FORMAT_PKCS8)
   {
      // Encode the asn1 string to pkcs8 pem
      CK_CHAR_PTR buffer = pkcs8_EncodePublicKeyToPem(asn1_BuildGetBuffer(), asn1_GetBufferSize());

      // write in file as string
      writtenSize = File_Write(sFilePath, buffer, (CK_ULONG)strlen(buffer), CK_FALSE);

      // release allocated buffer by pkcs8_EncodePublicKeyToPem
      free(buffer);
   }

   // Check of file is written
   if (writtenSize > 0)
   {
      printf("\n");
      printf("Export public key : Key (handle=%i) successfully exported.\n%i bytes written in file : %s \n", sExportTemplate->hKeyToExport, writtenSize, sFilePath);
      return CK_TRUE;
   }

   printf("cmd_ExportPublickey command error");

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BYTE cmd_setattributeBoolean(CK_OBJECT_HANDLE hHandle, BYTE bArgType, CK_ATTRIBUTE_TYPE cAttribute)
*/
CK_BYTE cmd_setattributeBoolean(CK_OBJECT_HANDLE hHandle, BYTE bArgType, CK_ATTRIBUTE_TYPE cAttribute)
{
   CK_BBOOL bIsPresent;
   CK_BBOOL bValue;

   bIsPresent = cmdarg_SearchTypeBoolean(bArgType, &bValue, CK_TRUE);
   if (bIsPresent == CK_TRUE)
   {
      printf("Updating attribute %s ... ", P11Util_DisplayAttributeName(cAttribute));
      if (P11_SetAttributeBoolean(hHandle, cAttribute, bValue) == CK_TRUE)
      {
         // display attribute updated and value
         printf("Success. Value = %s\n", P11Util_DisplayBooleanName(bValue));
         return 1;
      }
      //printf("Failed. Error code : %s \n", P11Util_DisplayErrorName(retCode));
   }

   return 0;
}

/*
    FUNCTION:        CK_BYTE cmd_setattributeString(CK_OBJECT_HANDLE hHandle, BYTE bArgType, CK_ATTRIBUTE_TYPE cAttribute)
*/
CK_BYTE cmd_setattributeString(CK_OBJECT_HANDLE hHandle, BYTE bArgType, CK_ATTRIBUTE_TYPE cAttribute)
{
   CK_CHAR_PTR       sString;

   sString = cmdarg_SearchTypeString(bArgType, NULL, 0);
   if (sString != NULL)
   {
      // if string as input, update the attribute
      P11_SetAttributeString(hHandle, cAttribute, sString);
      return 1;
   }

   return 0;
}

/*
    FUNCTION:        CK_BYTE cmd_setattributeArray(CK_OBJECT_HANDLE hHandle, BYTE bArgType, CK_ATTRIBUTE_TYPE cAttribute)
*/
CK_BYTE cmd_setattributeArray(CK_OBJECT_HANDLE hHandle, BYTE bArgType, CK_ATTRIBUTE_TYPE cAttribute)
{
   CK_CHAR_PTR       sString;
   CK_ULONG          sStringLength;

   // Get value
   sStringLength = cmdarg_SearchTypeHexString(bArgType , &sString);
   if ((CK_LONG)(sStringLength) > 0)
   {
      // if string as input, update the attribute
      P11_SetAttributeArray(hHandle, cAttribute, sString, sStringLength);

      // display attribute updated and value
      printf("Value = ");
      str_DisplayByteArraytoString("", sString, sStringLength);
      return 1;
   }

   return 0;
}

/*
    FUNCTION:        cmd_GenerateSecretKeyWithComponent(P11_KEYGENTEMPLATE* sKeyGenTemplate, CK_LONG sCompomentNumber)
*/
CK_BBOOL cmd_GenerateSecretKeyWithComponent(P11_KEYGENTEMPLATE* sKeyGenTemplate, CK_LONG sCompomentNumber)
{
   CK_LONG sLoop;
   CK_LONG sKeyLength;
   CK_BYTE_PTR pbCompoment;
   CK_BYTE_PTR pbKey;
   P11_UNWRAPTEMPLATE sKeyTemplate = {0};
   CK_OBJECT_HANDLE  hWrapKey = 0;
   CK_OBJECT_HANDLE  hKey = 0;
   CK_BYTE_PTR pKcvBuffer;
   CK_BBOOL bError = CK_FALSE;

   printf("This command generates key as several compoments and subject to security issues.\n");
   printf("This operation requires a specific security procedure to avoid key holder to see multiple key components\n");
   printf("The command will request to clear the console after the generation of each component\n");
   printf("Start the generation of the first key compoment enter (Y/N): ");

   if (!((Console_RequestString() == 1) && ((Console_GetBuffer()[0] == 'Y') || (Console_GetBuffer()[0] == 'y'))))
   {
      printf("Generation aborted\n");
      return CK_FALSE;;
   }

   do
   {

      // generate a AES 256 session wrap key (use to encrypt clear key value)
      hWrapKey = P11_GenerateAESWrapKey(CK_FALSE, AES_256_KEY_LENGTH, "AES_KEY_WRAP_KEY_COMP");
      
      sKeyLength = sKeyGenTemplate->skeySize;

      // allocate a buffer for compoments generation
      pbCompoment = malloc(sKeyLength);

      // allocate a buffer for key
      pbKey = malloc(sKeyLength);

      // check memory allocation
      if (pbCompoment == NULL || pbKey == NULL || hWrapKey == 0)
      {
         break;
      }

      // fill the key buffer
      memset(pbKey, 0, sKeyLength);
   
      for (sLoop = 1; sLoop <= sCompomentNumber; sLoop++)
      {
         // generate compoment X value with random from HSM
         P11_GenerateRandom(pbCompoment, sKeyLength);

         // if des key, compute parity bit, checked by hsm when unwrapping the key
         if (sKeyGenTemplate->skeyType != CKK_AES)
         {
            str_ByteArrayComputeParityBit(pbCompoment, sKeyLength);
         }

         // Xor the key with component
         str_ByteArrayXOR(pbKey, pbCompoment, sKeyLength);

         // print compoment value
         printf("Clear component %i : ", sLoop);
         str_DisplayByteArraytoStringWithSpace(pbCompoment, sKeyLength, 2);

         // load key compoment in the HSM as session key (only needed to compute KCV)
         sKeyTemplate.sClass = sKeyGenTemplate->sClass;
         sKeyTemplate.skeyType = sKeyGenTemplate->skeyType;
         //sKeyTemplate.skeySize = sKeyGenTemplate->skeySize;
         sKeyTemplate.pKeyLabel = "";
         sKeyTemplate.bCKA_Sign = CK_TRUE;
         sKeyTemplate.bCKA_Verify = CK_TRUE;
         sKeyTemplate.bCKA_Encrypt = CK_TRUE;
         sKeyTemplate.bCKA_Decrypt = CK_TRUE;
         sKeyTemplate.bCKA_Token = CK_FALSE;
         sKeyTemplate.bCKA_Sensitive = CK_TRUE;
         sKeyTemplate.bCKA_Private = CK_TRUE;
         sKeyTemplate.hWrappingKey = hWrapKey;
         hKey = P11_ImportClearSymetricKey(&sKeyTemplate, pbCompoment, sKeyLength);

         // stop loop if error
         if (hKey == 0)
         {
            bError = CK_TRUE;
         }
         else
         {
            // compute KCV for component
            if (P11_ComputeKCV(KCV_PCI, hKey, &pKcvBuffer) == CK_TRUE)
            {
               printf("Key check value for component %i : ", sLoop);
               str_DisplayByteArraytoString("", pKcvBuffer, 3);
               printf("\n");

               // free kcv buffer
               free(pKcvBuffer);
            }
            else
            {
               bError = CK_TRUE;
            }

            // delete component key
            P11_DeleteObject(hKey);
            hKey = 0;

         }

         // check if an error happens during the process and stop
         if (bError == CK_TRUE)
         {
            break;
         }

         printf("Do you want to clear the console now (Y/N) : ");
         if ((Console_RequestString() == 1) && ((Console_GetBuffer()[0] == 'Y') || (Console_GetBuffer()[0] == 'y')))
         {
            // clear console
            Console_Clear();
         }
      }

      // import the key if no error
      if (bError != CK_TRUE)
      {

         sKeyTemplate.sClass = sKeyGenTemplate->sClass;
         sKeyTemplate.skeyType = sKeyGenTemplate->skeyType;
         sKeyTemplate.bCKA_Private = sKeyGenTemplate->bCKA_Private;
         sKeyTemplate.bCKA_Modifiable = sKeyGenTemplate->bCKA_Modifiable;
         sKeyTemplate.bCKA_Sign = sKeyGenTemplate->bCKA_Sign;
         sKeyTemplate.bCKA_Verify = sKeyGenTemplate->bCKA_Verify;
         sKeyTemplate.bCKA_Unwrap = sKeyGenTemplate->bCKA_Unwrap;
         sKeyTemplate.bCKA_Wrap = sKeyGenTemplate->bCKA_Wrap;
         sKeyTemplate.bCKA_Encrypt = sKeyGenTemplate->bCKA_Encrypt;
         sKeyTemplate.bCKA_Decrypt = sKeyGenTemplate->bCKA_Decrypt;
         sKeyTemplate.bCKA_Token = sKeyGenTemplate->bCKA_Token;
         sKeyTemplate.bCKA_Sensitive = sKeyGenTemplate->bCKA_Sensitive;
         sKeyTemplate.bCKA_Derive = sKeyGenTemplate->bCKA_Derive;
         sKeyTemplate.bCKA_Extractable = sKeyGenTemplate->bCKA_Extractable;
         sKeyTemplate.pKeyLabel = sKeyGenTemplate->pKeyLabel;
         sKeyTemplate.pCKA_ID = sKeyGenTemplate->pCKA_ID;
         sKeyTemplate.uCKA_ID_Length = sKeyGenTemplate->uCKA_ID_Length;
         sKeyTemplate.hWrappingKey = hWrapKey;

         // if des key, compute parity bit, checked by hsm when unwrapping the key
         if (sKeyGenTemplate->skeyType != CKK_AES)
         {
            str_ByteArrayComputeParityBit(pbKey, sKeyLength);
         }

         // import key (xor of all key components)
         hKey = P11_ImportClearSymetricKey(&sKeyTemplate, pbKey, sKeyLength);
         if (hKey != 0)
         {
            printf("Key successfully generated, handle is : %i, label is : %s \n", hKey, sKeyGenTemplate->pKeyLabel);

            // compute KCV for component
            if (P11_ComputeKCV(KCV_PCI, hKey, &pKcvBuffer) == CK_TRUE)
            {
               str_DisplayByteArraytoString("Key check value : ", pKcvBuffer, 3);
               printf("\n");

               // free kcv buffer
               free(pKcvBuffer);
            }
         }
      }
   } while (FALSE);

   // free memory
   free(pbCompoment);
   free(pbKey);

   // delete temp wrap key
   P11_DeleteObject(hWrapKey);
   hWrapKey = 0;

   if (bError != CK_TRUE)
   {
      return CK_TRUE;
   }

   printf("cmd_GenerateKeyByComponent error\n");
   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL cmd_ImportSecretKeyWithComponent(P11_UNWRAPTEMPLATE* sImportTemplate, CK_LONG sCompomentNumber)
*/
CK_BBOOL cmd_ImportSecretKeyWithComponent(P11_UNWRAPTEMPLATE* sImportTemplate, CK_LONG sCompomentNumber)
{
   CK_LONG sLoop;
   CK_LONG sKeyLength;
   CK_BYTE_PTR pbCompoment;
   CK_BYTE_PTR pbKey;
   P11_UNWRAPTEMPLATE sKeyCompTemplate = { 0 };
   CK_OBJECT_HANDLE  hWrapKey = 0;
   CK_OBJECT_HANDLE  hKey = 0;
   CK_BYTE_PTR pKcvBuffer;
   CK_BBOOL bError = CK_FALSE;
   CK_ULONG uLength;

   printf("This command imports key as several compoments and subject to security issues.\n");
   printf("This operation requires a specific security procedure to avoid key holder to see multiple key components\n");
   printf("The command will request to clear the console after importing each component\n");
   printf("Start to import the first key compoment enter (Y/N): ");

   if (!((Console_RequestString() == 1) && ((Console_GetBuffer()[0] == 'Y') || (Console_GetBuffer()[0] == 'y'))))
   {
      printf("Generation aborted\n");
      return CK_FALSE;;
   }

   do
   {
      // generate a AES 256 session wrap key (use to encrypt clear key value)
      hWrapKey = P11_GenerateAESWrapKey(CK_FALSE, AES_256_KEY_LENGTH, "AES_KEY_WRAP_KEY_COMP");

      sKeyLength = sImportTemplate->skeySize;

      // allocate a buffer for compoments
      pbCompoment = malloc(sKeyLength);

      // allocate a buffer for key
      pbKey = malloc(sKeyLength);

      // check memory allocation
      if (pbCompoment == NULL || pbKey == NULL || hWrapKey == 0)
      {
         break;
      }

      // fill the key buffer
      memset(pbKey, 0, sKeyLength);


      for (sLoop = 1; sLoop <= sCompomentNumber; sLoop++)
      {

         // print compoment value
         printf("Enter component %i : ", sLoop);

         // request component
         uLength = Console_RequestHexString(CK_TRUE);
         if (uLength == 0)
         {
            printf("\nwrong string value, not hexadecimal\n");
            
            //ask again for component
            sLoop--;
            continue;
         }

         // check the length of component match with the key size
         if (sKeyLength != uLength)
         {
            printf("The length of the compoment does not match with the key length\n");
            //ask again for component
            sLoop--;
            continue;
         }

         // Copy compoment from console to pbCompoment
         memcpy(pbCompoment, Console_GetBuffer(), uLength);

         // clear component in the console buffer (2 time the size of the component array)
         memset(Console_GetBuffer(), 0, (CK_ULONG)(uLength < 1));

         // if des key, compute parity bit, checked by hsm when unwrapping the key
         if (sImportTemplate->skeyType != CKK_AES)
         {
            str_ByteArrayComputeParityBit(pbCompoment, sKeyLength);
         }

         // Xor the key with component
         str_ByteArrayXOR(pbKey, pbCompoment, sKeyLength);

         // load key compoment in the HSM as session key (only needed to compute KCV)
         sKeyCompTemplate.sClass = sImportTemplate->sClass;
         sKeyCompTemplate.skeyType = sImportTemplate->skeyType;
         sKeyCompTemplate.skeySize = sImportTemplate->skeySize;
         sKeyCompTemplate.pKeyLabel = "";
         sKeyCompTemplate.bCKA_Sign = CK_TRUE;
         sKeyCompTemplate.bCKA_Verify = CK_TRUE;
         sKeyCompTemplate.bCKA_Token = CK_FALSE;
         sKeyCompTemplate.bCKA_Sensitive = CK_TRUE;
         sKeyCompTemplate.bCKA_Private = CK_TRUE;
         sKeyCompTemplate.hWrappingKey = hWrapKey;
         hKey = P11_ImportClearSymetricKey(&sKeyCompTemplate, pbCompoment, sKeyLength);

         // stop loop if error
         if (hKey == 0)
         {
            bError = CK_TRUE;
         }
         else
         {
            // compute KCV for component
            if (P11_ComputeKCV(KCV_PCI, hKey, &pKcvBuffer) == CK_TRUE)
            {
               printf("Key check value for component %i : ", sLoop);
               str_DisplayByteArraytoString("", pKcvBuffer, 3);
               printf("\n");

               // free kcv buffer
               free(pKcvBuffer);
            }
            else
            {
               bError = CK_TRUE;
            }

            // delete component key
            P11_DeleteObject(hKey);
            hKey = 0;
         }

         // check if an error happens during the process and stop
         if (bError == CK_TRUE)
         {
            break;
         }

         printf("KCV matches, Continue ? (Y/N) : ");
         if (!((Console_RequestString() == 1) && ((Console_GetBuffer()[0] == 'Y') || (Console_GetBuffer()[0] == 'y'))))
         {
            printf("Command aborted : KCV doesn't match \n");
            bError = CK_TRUE;
            break;
         }


         printf("Do you want to clear the console now (Y) : ");
         if ((Console_RequestString() == 1) && ((Console_GetBuffer()[0] == 'Y') || (Console_GetBuffer()[0] == 'y')))
         {
            // clear console
            Console_Clear();
         }
      }

      // import the key if no error
      if (bError != CK_TRUE)
      {
         sImportTemplate->hWrappingKey = hWrapKey;

         // import key (xor of all key components)
         hKey = P11_ImportClearSymetricKey(sImportTemplate, pbKey, sKeyLength);
         if (hKey != 0)
         {
            printf("Key successfully imported, handle is : %i, label is : %s \n", hKey, sImportTemplate->pKeyLabel);

            // compute KCV for component
            if (P11_ComputeKCV(KCV_PCI, hKey, &pKcvBuffer) == CK_TRUE)
            {
               str_DisplayByteArraytoString("Key check value : ", pKcvBuffer, 3);
               printf("\n");

               // free kcv buffer
               free(pKcvBuffer);
            }
         }
      }

   } while (FALSE);

   // free memory
   free(pbCompoment);
   free(pbKey);

   // delete temp wrap key
   P11_DeleteObject(hWrapKey);
   hWrapKey = 0;

   if (bError != CK_TRUE)
   {
      return CK_TRUE;
   }

   printf("cmd_ImportSecretKeyWithComponent error\n");
   return CK_FALSE;
}
