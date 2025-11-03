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

#define _TR31_C

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
#include "tr31.h"
#include "str.h"

#define TR31_DERIVATION_DATA_LENGTH       8

const CK_CHAR AES_128_ENC_DERIVATION_DATA1[TR31_DERIVATION_DATA_LENGTH] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80 };
const CK_CHAR AES_128_MAC_DERIVATION_DATA1[TR31_DERIVATION_DATA_LENGTH] = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x80 };
const CK_CHAR AES_192_ENC_DERIVATION_DATA1[TR31_DERIVATION_DATA_LENGTH] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0 };
const CK_CHAR AES_192_ENC_DERIVATION_DATA2[TR31_DERIVATION_DATA_LENGTH] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0 };
const CK_CHAR AES_192_MAC_DERIVATION_DATA1[TR31_DERIVATION_DATA_LENGTH] = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0 };
const CK_CHAR AES_192_MAC_DERIVATION_DATA2[TR31_DERIVATION_DATA_LENGTH] = { 0x02, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0 };
const CK_CHAR AES_256_ENC_DERIVATION_DATA1[TR31_DERIVATION_DATA_LENGTH] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00 };
const CK_CHAR AES_256_ENC_DERIVATION_DATA2[TR31_DERIVATION_DATA_LENGTH] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00 };
const CK_CHAR AES_256_MAC_DERIVATION_DATA1[TR31_DERIVATION_DATA_LENGTH] = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00 };
const CK_CHAR AES_256_MAC_DERIVATION_DATA2[TR31_DERIVATION_DATA_LENGTH] = { 0x02, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00 };


CK_CHAR  key[AES_256_KEY_LENGTH];

#define TR_31_HEADER_SIZE        16

#define TR_31_HEADER_KB_VERSION_OFFSET          0
#define TR_31_HEADER_LENGTH_OFFSET              TR_31_HEADER_KB_VERSION_OFFSET + TR_31_HEADER_KB_VERSION_SIZE
#define TR_31_HEADER_KEY_USAGE_OFFSET           TR_31_HEADER_LENGTH_OFFSET + TR_31_HEADER_LENGTH_SIZE
#define TR_31_HEADER_ALGO_OFFSET                TR_31_HEADER_KEY_USAGE_OFFSET + TR_31_HEADER_KEYUSAGE_SIZE
#define TR_31_HEADER_MODE_USE_OFFSET            TR_31_HEADER_ALGO_OFFSET + TR_31_HEADER_ALGO_SIZE
#define TR_31_HEADER_KEY_VERSION_OFFSET         TR_31_HEADER_MODE_USE_OFFSET + TR_31_HEADER_MODE_USE_SIZE
#define TR_31_HEADER_EXPORTABILITY_OFFSET       TR_31_HEADER_KEY_VERSION_OFFSET + TR_31_HEADER_KEY_VERSION_SIZE
#define TR_31_HEADER_NUMBER_OPT_BLOC_OFFSET     TR_31_HEADER_EXPORTABILITY_OFFSET + TR_31_HEADER_EXPORTABILITY_SIZE
#define TR_31_HEADER_RFU_OFFSET                 TR_31_HEADER_NUMBER_OPT_BLOC_OFFSET + TR_31_HEADER_NUMBER_OPT_BLOC_SIZE

#define TR_31_HEADER_KB_VERSION_SIZE            1
#define TR_31_HEADER_LENGTH_SIZE                4
#define TR_31_HEADER_KEYUSAGE_SIZE              2
#define TR_31_HEADER_ALGO_SIZE                  1
#define TR_31_HEADER_MODE_USE_SIZE              1
#define TR_31_HEADER_KEY_VERSION_SIZE           2
#define TR_31_HEADER_EXPORTABILITY_SIZE         1
#define TR_31_HEADER_NUMBER_OPT_BLOC_SIZE       2
#define TR_31_HEADER_RFU_SIZE                   2

#define TR_31_HEADER_KB_AES_DERIVATION_BINDING  'D'

#define TR_31_HEADER_KEY_USAGE_AES              'A'

#define TR_31_ENCRYPTED_KEY_AES_256_LENGTH       48



// import -slot=2 -password=12345678 -keyclass=secret -keytype=aes -inputfile=tmd-key.txt -format=tr31 -key=1138 -label=tmd-key-1
// import -slot=2 -password=12345678 -keyclass=secret -keytype=aes -inputfile=tr31-test-keyblock.txt -format=tr31 -key=1158 -label=tr31-testkey
/*
    FUNCTION:        TR31_UnwrapPrivateSecretKey(P11_UNWRAPTEMPLATE* sUnWrapTemplate, CK_CHAR_PTR pWrappedKey)
*/
CK_BBOOL TR31_UnwrapPrivateSecretKey(P11_UNWRAPTEMPLATE* sUnWrapTemplate, CK_CHAR_PTR pWrappedKey, CK_OBJECT_HANDLE* hKey)
{
   CK_ULONG uWrapkeyLength = 0;
   CK_CHAR sSize[5];
   CK_ULONG uHeaderLength = 0;
   CK_BYTE bKeyType = 0;
   CK_ULONG uEncKEyLength = 0;
   CK_ULONG uHeaderEncLength = 0;
   CK_CHAR_PTR sMac = NULL;
   CK_CHAR_PTR sEnc = NULL;
   CK_ULONG uEncMacLength;
   CK_OBJECT_HANDLE        hMacKey;
   CK_OBJECT_HANDLE        hEncKey;
   CK_BBOOL             bResult;

   do
   {
      // get the length of the buffer

      uWrapkeyLength = (CK_ULONG)strlen(pWrappedKey);

      // check the length is higher than header size
      if (uWrapkeyLength < TR_31_HEADER_SIZE)
      {
         printf("TR31 error:  block too small");
         break;
      }

      // support only AES for now
      if (pWrappedKey[TR_31_HEADER_KB_VERSION_OFFSET] != TR_31_HEADER_KB_AES_DERIVATION_BINDING)
      {
         printf("TR31 error : support only Key block protected using the AES Key Derivation Binding Method");
         break;
      }

      memcpy(sSize, &pWrappedKey[TR_31_HEADER_LENGTH_OFFSET], TR_31_HEADER_LENGTH_SIZE);
      sSize[4] = '\0';
      uHeaderLength = str_StringtoInteger(sSize);

      // if negative error
      if (uHeaderLength < 0)
      {
         break;
      }

      // check the string length and the length in the header match
      if (uHeaderLength != uWrapkeyLength)
      {
         printf("TR31 error:  header length does match file length");
         break;
      }
      // ignore key usage

      // support only AES for now
      bKeyType = pWrappedKey[TR_31_HEADER_ALGO_OFFSET];
      switch (bKeyType)
      {
      case TR_31_HEADER_KEY_USAGE_AES:
         break;
      default:
         printf("TR31 error: header Key usage : Key type not supported");
         return CK_FALSE;
      }

      // check mode of use (override value given in parameter)

      // set all attribute to false
      sUnWrapTemplate->bCKA_Decrypt = CK_FALSE;
      sUnWrapTemplate->bCKA_Encrypt = CK_FALSE;
      sUnWrapTemplate->bCKA_Sign = CK_FALSE;
      sUnWrapTemplate->bCKA_Verify = CK_FALSE;
      sUnWrapTemplate->bCKA_Wrap = CK_FALSE;
      sUnWrapTemplate->bCKA_Unwrap = CK_FALSE;
      sUnWrapTemplate->bCKA_Derive = CK_FALSE;

      // enable attribute according to mode of use
      switch(pWrappedKey[TR_31_HEADER_MODE_USE_OFFSET])
      { 
         case 'B':
            sUnWrapTemplate->bCKA_Encrypt = CK_TRUE;
            sUnWrapTemplate->bCKA_Decrypt = CK_TRUE;
            break;
         case 'C':
            sUnWrapTemplate->bCKA_Sign = CK_TRUE;
            sUnWrapTemplate->bCKA_Verify = CK_TRUE;
            break;
         case 'D':
            sUnWrapTemplate->bCKA_Decrypt = CK_TRUE;
            sUnWrapTemplate->bCKA_Unwrap = CK_TRUE;
            break;
         case 'E':
            sUnWrapTemplate->bCKA_Encrypt = CK_TRUE;
            sUnWrapTemplate->bCKA_Wrap = CK_TRUE;
            break;
         case 'G':
         case 'S':
            sUnWrapTemplate->bCKA_Sign = CK_TRUE;
            break;
         case 'N':
            sUnWrapTemplate->bCKA_Decrypt = CK_TRUE;
            sUnWrapTemplate->bCKA_Encrypt = CK_TRUE;
            sUnWrapTemplate->bCKA_Sign = CK_TRUE;
            sUnWrapTemplate->bCKA_Verify = CK_TRUE;
            sUnWrapTemplate->bCKA_Wrap = CK_TRUE;
            sUnWrapTemplate->bCKA_Unwrap = CK_TRUE;
            sUnWrapTemplate->bCKA_Derive = CK_TRUE;
         case 'T':
            sUnWrapTemplate->bCKA_Decrypt = CK_TRUE;
            sUnWrapTemplate->bCKA_Sign = CK_TRUE;
            break;
         case 'V':
            sUnWrapTemplate->bCKA_Verify = CK_TRUE;
            break;
         case 'X':
         case 'Y':
            sUnWrapTemplate->bCKA_Derive = CK_TRUE;
            break;
         default :
            printf("TR31 error: invalid key usage");
            return CK_FALSE;
      }

      // ignore key version


      // check exportability
      sUnWrapTemplate->bCKA_Extractable = CK_FALSE;
      switch (pWrappedKey[TR_31_HEADER_EXPORTABILITY_OFFSET])
      {
      case 'E':
      case 'S':
         sUnWrapTemplate->bCKA_Extractable = CK_TRUE;
         break;
      case 'N':
         break;
      default:
         printf("TR31 error: invalid exportability");
         return CK_FALSE;
      }

      // check optional block
      if (pWrappedKey[TR_31_HEADER_NUMBER_OPT_BLOC_OFFSET] != '0' && pWrappedKey[TR_31_HEADER_NUMBER_OPT_BLOC_OFFSET + 1] != '0')
      {
         printf("TR31 error: optional block not supported");
         break;
      }
      
      // check rfu
      if (pWrappedKey[TR_31_HEADER_RFU_OFFSET] != '0' && pWrappedKey[TR_31_HEADER_RFU_OFFSET + 1] != '0')
      {
         printf("TR31 error: RFU is not set to 00");
         break;
      }
      
      
      // convert the ascii string to hex exclude the tr31 header. Convert encrypted data and mac
      uEncMacLength = str_StringtoByteArray(&pWrappedKey[TR_31_HEADER_SIZE], uWrapkeyLength - TR_31_HEADER_SIZE);

      // get the length of the encrypted data
      uEncKEyLength = uEncMacLength - AES_CMAC_LENGTH;

      // get the length of the header and the encrypted block
      uHeaderEncLength = uEncKEyLength + TR_31_HEADER_SIZE;

      // get pointer on encrypted data
      sEnc = &pWrappedKey[TR_31_HEADER_SIZE];

      // get pointer on mac
      sMac = &pWrappedKey[TR_31_HEADER_SIZE + uEncKEyLength];

      // derive the encryption key
      hEncKey = TR31_DeriveKeyEnc(sUnWrapTemplate->hWrappingKey);
      if (hEncKey == CK_NULL_ELEMENT)
      {
         printf("TR31 error: encryption derivation key failed");
         break;
      }

      // decrypt the data
      bResult = TR31_DecryptKey(hEncKey, sEnc, uEncKEyLength, sMac);

      // delete derived encryption key
      P11_DeleteObject(hEncKey);

      // check if the decrpyption 
      if (bResult == CK_FALSE)
      {
         printf("TR31 error: decryption key failed");
         break;
      }
      // derive the encryption key
      hMacKey = TR31_DeriveKeyMac(sUnWrapTemplate->hWrappingKey);
      if (hMacKey == CK_NULL_ELEMENT)
      {
         printf("TR31 error: mac derivation key failed");
         break;
      }
      
      // check mac
      bResult = TR31_VerifyMAC(hMacKey, pWrappedKey, uHeaderEncLength, sMac, AES_CMAC_LENGTH);

      // delete object
      P11_DeleteObject(hMacKey);

      // check if the mac verification fails 
      if (bResult == CK_FALSE)
      {
         printf("TR31 error: mac verification key failed");
         break;
      }

      // import the key
      if (TR31_ImportKey(sUnWrapTemplate, bKeyType, sEnc, uEncKEyLength, hKey) == CK_FALSE)
      {
         printf("TR31 error: import key failed");
         break;
      }

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_OBJECT_HANDLE TR31_DeriveKeyMac(CK_OBJECT_HANDLE hWrappingKey)
*/
CK_OBJECT_HANDLE TR31_DeriveKeyMac(CK_OBJECT_HANDLE hWrappingKey)
{
   CK_KEY_TYPE             cKeyType;
   CK_OBJECT_CLASS         cKeyClass;
   CK_LONG                 lKeyLength;
   CK_CHAR_PTR             sInputPart1 = NULL;
   CK_CHAR_PTR             sInputPart2 = NULL;
   CK_RV                   retCode = CKR_DEVICE_ERROR;
   P11_SIGN_MECH           sSignMech;
   P11_ENCRYPTION_MECH     sEncryptionMech;
   CK_ULONG                sSigbDataLengh = AES_CMAC_LENGTH;
   CK_CHAR_PTR             pKeypart1 = &key[0];
   CK_CHAR_PTR             pKeypart2 = &key[AES_128_KEY_LENGTH];
   CK_CHAR_PTR             sWrapKey = NULL;
   CK_ULONG                sWrapKeyLength = 0;
   P11_SIGNATURE_TEMPLATE  sSignatureTemplate = {0};
   P11_ENCRYPT_TEMPLATE    sEncryptionTemplate = { 0 };
   P11_UNWRAPTEMPLATE      sUnWrapTemplate = { 0 };
   CK_OBJECT_HANDLE        hMacKey;
   do
   {
      cKeyType = P11_GetKeyType(hWrappingKey);
      cKeyClass = P11_GetObjectClass(hWrappingKey);

      if (cKeyType != CKK_AES)
      {
         break;
      }

      lKeyLength = P11_GetKeyLength(hWrappingKey);

      switch (lKeyLength)
      {
      case AES_256_KEY_LENGTH : 
         sInputPart1 = (CK_CHAR_PTR)AES_256_MAC_DERIVATION_DATA1;
         sInputPart2 = (CK_CHAR_PTR)AES_256_MAC_DERIVATION_DATA2;
         break;
      case AES_192_KEY_LENGTH:
         sInputPart1 = (CK_CHAR_PTR)AES_192_MAC_DERIVATION_DATA1;
         sInputPart2 = (CK_CHAR_PTR)AES_192_MAC_DERIVATION_DATA2;
         break;
      case AES_128_KEY_LENGTH:
         sInputPart1 = (CK_CHAR_PTR)AES_128_MAC_DERIVATION_DATA1;
         sInputPart2 = NULL;
         break;
      default :
         return CK_NULL_ELEMENT;
      }

      sSignatureTemplate.hSignatureKey = hWrappingKey;
      sSignatureTemplate.sClass = cKeyClass;
      sSignatureTemplate.skeyType = cKeyType;
      sSignatureTemplate.sInputData = sInputPart1;
      sSignatureTemplate.sInputDataLength = TR31_DERIVATION_DATA_LENGTH;
      sSignMech.aes_param.pIv = NULL;
      sSignMech.ckMechType = CKM_AES_CMAC;
      sSignatureTemplate.sign_mech = &sSignMech;

      if (P11_SignData(&sSignatureTemplate, &pKeypart1, &sSigbDataLengh) == FALSE)
      {
         break;
      }

      if (lKeyLength != AES_128_KEY_LENGTH)
      {
         sSignatureTemplate.sInputData = sInputPart2;
         sSignatureTemplate.sInputDataLength = TR31_DERIVATION_DATA_LENGTH;
         if (P11_SignData(&sSignatureTemplate, &pKeypart2, &sSigbDataLengh) == FALSE)
         {
            break;
         }
      }

      // use tr31 wrapping key
      sEncryptionTemplate.hEncyptiontKey = hWrappingKey;
      sEncryptionTemplate.sClass = cKeyClass;
      sEncryptionTemplate.skeyType = cKeyType;
      sEncryptionTemplate.sInputData = key;
      sEncryptionTemplate.sInputDataLength = lKeyLength;
      sEncryptionMech.ckMechType = CKM_AES_KWP;
      sEncryptionTemplate.encryption_mech = &sEncryptionMech;
      P11_EncryptData(&sEncryptionTemplate, &sWrapKey, &sWrapKeyLength);

      // clear the key buffer
      memset(key, 0, sizeof(key));

      // import key in the HSM as session key
      sUnWrapTemplate.bCKA_Private = CK_TRUE;
      sUnWrapTemplate.sClass = cKeyClass;
      sUnWrapTemplate.skeyType = cKeyType;
      sUnWrapTemplate.bCKA_Modifiable = CK_TRUE;
      sUnWrapTemplate.bCKA_Sign = CK_TRUE;
      sUnWrapTemplate.bCKA_Verify = CK_TRUE;
      sUnWrapTemplate.bCKA_Unwrap = CK_FALSE;
      sUnWrapTemplate.bCKA_Wrap = CK_FALSE;
      sUnWrapTemplate.bCKA_Encrypt = CK_FALSE;
      sUnWrapTemplate.bCKA_Decrypt = CK_FALSE;
      sUnWrapTemplate.bCKA_Token = CK_FALSE;
      sUnWrapTemplate.bCKA_Sensitive = CK_TRUE;
      sUnWrapTemplate.hWrappingKey = hWrappingKey;
      sUnWrapTemplate.pKeyLabel = "tr31_subkey-mac";
      sUnWrapTemplate.wrapmech = &sEncryptionMech;
      
      // import wrapped derived key
      P11_UnwrapPrivateSecretKey(&sUnWrapTemplate, sWrapKey, sWrapKeyLength, &hMacKey);

      // release the buffer
      free(sWrapKey);

      return hMacKey;

   } while (FALSE);



   return CK_NULL_ELEMENT;
}

/*
    FUNCTION:        CK_OBJECT_HANDLE TR31_DeriveKeyEnc(CK_OBJECT_HANDLE hWrappingKey)
*/
CK_OBJECT_HANDLE TR31_DeriveKeyEnc(CK_OBJECT_HANDLE hWrappingKey)
{
   CK_KEY_TYPE             cKeyType;
   CK_OBJECT_CLASS         cKeyClass;
   CK_LONG                 lKeyLength;
   CK_CHAR_PTR             sInputPart1 = NULL;
   CK_CHAR_PTR             sInputPart2 = NULL;
   CK_RV                   retCode = CKR_DEVICE_ERROR;
   P11_SIGN_MECH           sSignMech;
   P11_ENCRYPTION_MECH     sEncryptionMech;
   CK_ULONG                sSigbDataLengh = AES_CMAC_LENGTH;
   CK_CHAR_PTR             pKeypart1 = &key[0];
   CK_CHAR_PTR             pKeypart2 = &key[AES_128_KEY_LENGTH];
   CK_CHAR_PTR             sWrapKey = NULL;
   CK_ULONG                sWrapKeyLength = 0;
   P11_SIGNATURE_TEMPLATE  sSignatureTemplate = { 0 };
   P11_ENCRYPT_TEMPLATE    sEncryptionTemplate = { 0 };
   P11_UNWRAPTEMPLATE      sUnWrapTemplate = { 0 };
   CK_OBJECT_HANDLE        hEncKey;
   do
   {
      cKeyType = P11_GetKeyType(hWrappingKey);
      cKeyClass = P11_GetObjectClass(hWrappingKey);

      if (cKeyType != CKK_AES)
      {
         break;
      }

      lKeyLength = P11_GetKeyLength(hWrappingKey);

      switch (lKeyLength)
      {
      case AES_256_KEY_LENGTH:
         sInputPart1 = (CK_CHAR_PTR)AES_256_ENC_DERIVATION_DATA1;
         sInputPart2 = (CK_CHAR_PTR)AES_256_ENC_DERIVATION_DATA2;
         break;
      case AES_192_KEY_LENGTH:
         sInputPart1 = (CK_CHAR_PTR)AES_192_ENC_DERIVATION_DATA1;
         sInputPart2 = (CK_CHAR_PTR)AES_192_ENC_DERIVATION_DATA2;
         break;
      case AES_128_KEY_LENGTH:
         sInputPart1 = (CK_CHAR_PTR)AES_128_ENC_DERIVATION_DATA1;
         sInputPart2 = NULL;
         break;
      default:
         return CK_NULL_ELEMENT;
      }

      sSignatureTemplate.hSignatureKey = hWrappingKey;
      sSignatureTemplate.sClass = cKeyClass;
      sSignatureTemplate.skeyType = cKeyType;
      sSignatureTemplate.sInputData = sInputPart1;
      sSignatureTemplate.sInputDataLength = TR31_DERIVATION_DATA_LENGTH;
      sSignMech.aes_param.pIv = NULL;
      sSignMech.ckMechType = CKM_AES_CMAC;
      sSignatureTemplate.sign_mech = &sSignMech;

      if (P11_SignData(&sSignatureTemplate, &pKeypart1, &sSigbDataLengh) == FALSE)
      {
         break;
      }

      if (lKeyLength != AES_128_KEY_LENGTH)
      {
         sSignatureTemplate.sInputData = sInputPart2;
         sSignatureTemplate.sInputDataLength = TR31_DERIVATION_DATA_LENGTH;
         if (P11_SignData(&sSignatureTemplate, &pKeypart2, &sSigbDataLengh) == FALSE)
         {
            break;
         }
      }

      // use tr31 wrapping key
      sEncryptionTemplate.hEncyptiontKey = hWrappingKey;
      sEncryptionTemplate.sClass = cKeyClass;
      sEncryptionTemplate.skeyType = cKeyType;
      sEncryptionTemplate.sInputData = key;
      sEncryptionTemplate.sInputDataLength = lKeyLength;
      sEncryptionMech.ckMechType = CKM_AES_KWP;
      sEncryptionTemplate.encryption_mech = &sEncryptionMech;
      if(P11_EncryptData(&sEncryptionTemplate, &sWrapKey, &sWrapKeyLength) == CK_FALSE)
      {
         break;
      }
      // clear the key buffer
      memset(key, 0, sizeof(key));

      // import key in the HSM as session key
      sUnWrapTemplate.bCKA_Private = CK_TRUE;
      sUnWrapTemplate.sClass = cKeyClass;
      sUnWrapTemplate.skeyType = cKeyType;
      sUnWrapTemplate.bCKA_Modifiable = CK_FALSE;
      sUnWrapTemplate.bCKA_Sign = CK_FALSE;
      sUnWrapTemplate.bCKA_Verify = CK_FALSE;
      sUnWrapTemplate.bCKA_Unwrap = CK_TRUE;
      sUnWrapTemplate.bCKA_Wrap = CK_TRUE;
      sUnWrapTemplate.bCKA_Encrypt = CK_TRUE;
      sUnWrapTemplate.bCKA_Decrypt = CK_TRUE;
      sUnWrapTemplate.bCKA_Token = CK_FALSE;
      sUnWrapTemplate.bCKA_Sensitive = CK_TRUE;
      sUnWrapTemplate.hWrappingKey = hWrappingKey;
      sUnWrapTemplate.pKeyLabel = "tr31_subkey-enc";
      sUnWrapTemplate.wrapmech = &sEncryptionMech;

      // import wrapped derived key
      if(P11_UnwrapPrivateSecretKey(&sUnWrapTemplate, sWrapKey, sWrapKeyLength, &hEncKey) == CK_FALSE)
      {
         break;
      }

      // release the buffer
      free(sWrapKey);

      return hEncKey;

   } while (FALSE);

   return CK_NULL_ELEMENT;
}


/*
    FUNCTION:        CK_BBOOL TR31_VerifyMAC(CK_OBJECT_HANDLE hMacKey, CK_CHAR_PTR pHeader, CK_ULONG pHeaderLength, CK_CHAR_PTR pMac, CK_ULONG pMacLength)
*/
CK_BBOOL TR31_VerifyMAC(CK_OBJECT_HANDLE hMacKey, CK_CHAR_PTR pHeader, CK_ULONG pHeaderLength, CK_CHAR_PTR pMac, CK_ULONG pMacLength)
{

   CK_RV                   retCode = CKR_DEVICE_ERROR;
   P11_SIGN_MECH           sSignMech = {0};
   CK_ULONG                sSigbDataLengh = AES_CMAC_LENGTH;
   CK_CHAR_PTR             sSigbData = NULL;
   CK_ULONG                sWrapKeyLength = 0;
   P11_SIGNATURE_TEMPLATE  sSignatureTemplate = { 0 };
   CK_BBOOL                bResult;


   do
   {

      sSignatureTemplate.hSignatureKey = hMacKey;
      sSignatureTemplate.sClass = P11_GetObjectClass(hMacKey);
      sSignatureTemplate.skeyType = P11_GetKeyType(hMacKey);
      sSignatureTemplate.sInputData = pHeader;
      sSignatureTemplate.sInputDataLength = pHeaderLength;
      sSignMech.aes_param.pIv = NULL;
      sSignMech.ckMechType = CKM_AES_CMAC;
      sSignatureTemplate.sign_mech = &sSignMech;

      // sign data
      if (P11_SignData(&sSignatureTemplate, &sSigbData, &sSigbDataLengh) == CK_FALSE)
      {
         break;
      }

      // check signauture length is same
      if (sSigbDataLengh != pMacLength)
      {
         free(sSigbData);
         break;
      }

      // verify signature
      bResult = memcmp(pMac, sSigbData, sSigbDataLengh);

      // free memory
      free(sSigbData);

      // return true if comprisaon matches
      if (bResult == 0)
      {
         return CK_TRUE;
      }

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL TR31_VerifyMAC(CK_OBJECT_HANDLE hMacKey, CK_CHAR_PTR pHeader, CK_ULONG pHeaderLength, CK_CHAR_PTR pMac, CK_ULONG pMacLength)
*/
CK_BBOOL TR31_DecryptKey(CK_OBJECT_HANDLE hEncKey, CK_CHAR_PTR pEncryptedKey, CK_ULONG pEncryptedKEyLength, CK_CHAR_PTR pIV)
{

   P11_ENCRYPTION_MECH     sEncryptionMech;
   P11_ENCRYPT_TEMPLATE    sEncryptionTemplate = { 0 };
   CK_ULONG                sDecryptedKeyLen = 0;
   CK_CHAR_PTR             sDecryptedKey = NULL;

   do
   {

      sEncryptionTemplate.hEncyptiontKey = hEncKey;
      sEncryptionTemplate.sClass = P11_GetObjectClass(hEncKey);
      sEncryptionTemplate.skeyType = P11_GetKeyType(hEncKey);
      sEncryptionTemplate.sInputData = pEncryptedKey;
      sEncryptionTemplate.sInputDataLength = pEncryptedKEyLength;
      sEncryptionMech.ckMechType = CKM_AES_CBC;
      sEncryptionMech.aes_param.pIv = pIV;
      sEncryptionTemplate.encryption_mech = &sEncryptionMech;

      // decrypt the data
      if (P11_DecryptData(&sEncryptionTemplate, &sDecryptedKey, &sDecryptedKeyLen) == CK_FALSE)
      {
         break;
      }

      // check the size of encrypted and decrypted data are same
      if (pEncryptedKEyLength != sDecryptedKeyLen)
      {
         break;
      }

      memcpy(pEncryptedKey, sDecryptedKey, pEncryptedKEyLength);

      // clear the decrypted data
      memset(sDecryptedKey, 0, pEncryptedKEyLength);

      // free the buffer
      free(sDecryptedKey);

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL TR31_ImportKey(P11_UNWRAPTEMPLATE* sUnWrapTemplate, CK_BYTE bKeyType, CK_CHAR_PTR pKey, CK_ULONG uKeyLength)
*/
CK_BBOOL TR31_ImportKey(P11_UNWRAPTEMPLATE* sUnWrapTemplate, CK_BYTE bKeyType, CK_CHAR_PTR pKey, CK_ULONG uKeyLength, CK_OBJECT_HANDLE* hKey)
{

   P11_ENCRYPT_TEMPLATE    sEncryptionTemplate = { 0 };
   P11_ENCRYPTION_MECH     sEncryptionMech;
   CK_CHAR_PTR             sWrapKey = NULL;
   CK_ULONG                sWrapKeyLength = 0;
   CK_ULONG                sKeyLength = 0;

   do
   {
      // check the size of the key in the header
      switch (bKeyType)
      {
      case TR_31_HEADER_KEY_USAGE_AES:
         // convert the key length to hexa
         sKeyLength = (CK_ULONG)(pKey[0] << 8) + (CK_ULONG)pKey[1];
         sKeyLength >>= 3;

         // check the key length
         switch (sKeyLength)
         {
         case AES_128_KEY_LENGTH:
         case AES_192_KEY_LENGTH:
         case AES_256_KEY_LENGTH:
            break;
         default:
            return CK_FALSE;
         }

         // move the pointer to the key
         pKey += 2;

         break;
      default:
         return CK_FALSE;
      }

      // use tr31 wrapping key
      sEncryptionTemplate.hEncyptiontKey = sUnWrapTemplate->hWrappingKey;
      sEncryptionTemplate.sClass = sUnWrapTemplate->sClass;
      sEncryptionTemplate.skeyType = sUnWrapTemplate->skeyType;
      sEncryptionTemplate.sInputData = pKey;
      sEncryptionTemplate.sInputDataLength = sKeyLength;
      sEncryptionMech.ckMechType = CKM_AES_KWP;
      sEncryptionTemplate.encryption_mech = &sEncryptionMech;
      if (P11_EncryptData(&sEncryptionTemplate, &sWrapKey, &sWrapKeyLength) == CK_FALSE)
      {
         break;
      }

      // clear the key buffer
      memset(pKey, 0, uKeyLength);

      // import key in the HSM as session key
      sUnWrapTemplate->wrapmech = &sEncryptionMech;

      // import wrapped key
      if (P11_UnwrapPrivateSecretKey(sUnWrapTemplate, sWrapKey, sWrapKeyLength, hKey) == CK_FALSE)
      {
         break;
      }

      // release buffer
      free(sWrapKey);

      return CK_TRUE;
   } while (FALSE);

   return CK_FALSE;
}