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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "pkcs8.h"
#include "base64.h"
#include "asn1.h"

// constant
const CK_CHAR STR_BEGIN_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n";
const CK_CHAR STR_END_PUBLIC_KEY[] = "-----END PUBLIC KEY-----\n";
const CK_CHAR STR_BEGIN_ENCRYPTED_PRIVATE_KEY[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
const CK_CHAR STR_END_ENCRYPTED_PRIVATE_KEY[] = "-----END ENCRYPTED PRIVATE KEY-----\n";
const CK_CHAR STR_NEWLINE[] = "\n";

#define PKCS8_LINE_SIZE         0x40

// OID RSA encryption PKCS1 : 1.2.840.113549.1.1.1
const CK_CHAR OID_RSA_ENCRYPTION[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
// OID ecPublicKey 1.2.840.10045.2.1
const CK_CHAR OID_EC_PUBLICKEY[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };

const CK_CHAR OID_DSA_PUBLICKEY[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01 };



const CK_CHAR OID_DH_KEYAGREMENT_PKCS3[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x03, 0x01 };
const CK_CHAR OID_DH_PUBLICKEY[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01 };


// oid eddsasignature  id-Ed25519 1.3.101.112
const CK_CHAR OID_EDDSA_X25519_DOMAIN[] = { 0x0D, 0x04, 0x01, 0x03, 0x65, 0x6E };
const CK_CHAR OID_EDDSA_X448_DOMAIN[] = { 0x0D, 0x04, 0x01, 0x03, 0x65, 0x6F };
const CK_CHAR OID_EDDSA_ED25519_DOMAIN[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
const CK_CHAR OID_EDDSA_ED448_DOMAIN[] = { 0x0D, 0x04, 0x01, 0x03, 0x65, 0x71 };

const CK_CHAR OID_NIST_AES_128_CBC_PAD[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 };
const CK_CHAR OID_NIST_AES_192_CBC_PAD[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16 };
const CK_CHAR OID_NIST_AES_256_CBC_PAD[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A };


const CK_CHAR OID_HMAC_SHA1[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07 };
const CK_CHAR OID_HMAC_SHA224[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08 };
const CK_CHAR OID_HMAC_SHA256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09 };
const CK_CHAR OID_HMAC_SHA384[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A };
const CK_CHAR OID_HMAC_SHA512[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B };
const CK_CHAR OID_HMAC_SHA512_224[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0C };
const CK_CHAR OID_HMAC_SHA512_256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0D };

const CK_CHAR OID_PKCS5_PBKDF2[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C };
const CK_CHAR OID_PKCS5_PBES2[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D };

const CK_CHAR OID_ML_DSA_44[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
const CK_CHAR OID_ML_DSA_65[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
const CK_CHAR OID_ML_DSA_87[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };

const CK_CHAR OID_ML_KEM_512[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01 };
const CK_CHAR OID_ML_KEM_768[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02 };
const CK_CHAR OID_ML_KEM_1024[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03 };


const CK_CHAR OID_LMS_HSS_SIG[] = { 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x11 };

/*
   id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }
   id-X448      OBJECT IDENTIFIER ::= { 1 3 101 111 }
   id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
   id-Ed448     OBJECT IDENTIFIER ::= { 1 3 101 113 }
*/



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

/*
    FUNCTION:        CK_ULONG  pkcs8_DecodeEncryptedPrivateKeyFromPem(CK_CHAR_PTR sEncryptedPrivateKey, CK_ULONG sEncryptedPrivateKeyLength)
*/
CK_ULONG  pkcs8_DecodeEncryptedPrivateKeyFromPem(CK_CHAR_PTR sEncryptedPrivateKey, CK_ULONG sEncryptedPrivateKeyLength)
{

   CK_CHAR_PTR    sStringEndofFile = sEncryptedPrivateKey + sEncryptedPrivateKeyLength;
   CK_CHAR_PTR    sStringBeginOfLine;
   CK_CHAR_PTR    sStringEndPublicKey;
   CK_CHAR_PTR    sStringEndofLine;
   CK_CHAR_PTR    sStringBase64;
   CK_LONG        uSizeBase64 = 0;
   CK_LONG        uLineSize = 0;

   do
   {
      // search for begin public key string
      sStringBeginOfLine = strstr(sEncryptedPrivateKey, STR_BEGIN_ENCRYPTED_PRIVATE_KEY);
      if (sStringBeginOfLine == NULL)
      {
         break;
      }
      // check begin public key string is the first string of the file
      if (sStringBeginOfLine != sEncryptedPrivateKey)
      {
         break;
      }
      // search for end public key string
      sStringEndPublicKey = strstr(sEncryptedPrivateKey, STR_END_ENCRYPTED_PRIVATE_KEY);
      if (sStringEndPublicKey == NULL)
      {
         break;
      }

      // search for end public key string is the end of the file
      if ((sStringEndPublicKey + strlen(STR_END_ENCRYPTED_PRIVATE_KEY)) != sEncryptedPrivateKey + sEncryptedPrivateKeyLength)
      {
         break;
      }

      // allocate a buffer of the size of the string (will be always little be higher than expected)
      sStringBase64 = malloc(sEncryptedPrivateKeyLength);

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
      if (b64_decode(sStringBase64, (unsigned char*)sEncryptedPrivateKey, (size_t)sEncryptedPrivateKeyLength) == 0)
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
Publickeyinfo:: = SEQUENCE {
  algorithm       algorithmidentifier,
  publickey       BIT STRING
}

Algorithmidentifier:: = SEQUENCE {
  algorithm       OBJECT IDENTIFIER,
  parameters any      DEFINED by algorithm OPTIONAL
}

parameters = NULL

Rsapublickey:: = SEQUENCE {
    modulus           integer,  --n
    publicexponent    integer   --e
}

http://certificate.fyicenter.com/2145_FYIcenter_Public_Private_Key_Decoder_and_Viewer.html#Result
*/

/*
    FUNCTION:        CK_BBOOL pksc8_Build_PublicKeyInfoRSA(RSA_PUBLIC_KEY * sRsaPublicKey)
*/
CK_BBOOL pksc8_Build_PublicKeyInfoRSA(RSA_PUBLIC_KEY* sRsaPublicKey)
{
   CK_ULONG uTlvSize;

   // init asn1builder
   asn1_Build_Init();
   // Tag sequence for public exponant
   asn1_Build_tlv(TAG_INTEGER, sRsaPublicKey->sExponent, sRsaPublicKey->uExponentLength);
   // Tag sequence for modulus
   asn1_Build_tlv(TAG_INTEGER, sRsaPublicKey->sModulus, sRsaPublicKey->uModulusLength);
   // encapsulate in tag sequence
   asn1_Build_tl(TAG_SEQUENCE, asn1_GetBufferSize());
   // encapsulate in tag bitstring
   asn1_Build_tl(TAG_BITSTRING, asn1_GetBufferSize());

   // New tlv branch
   // push null tag (parameters empty for RSA public key)
   uTlvSize = asn1_Build_tl(TAG_NULL, 0);

   uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION));
   /*
   // push OID RSA encryption PKCS1
   uTlvSize += asn1_Build_tlv(TAG_OID, (CK_CHAR_PTR)OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION));
   */

   // encapsulate tag sequence in this tlv branch
   asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

   // encapsulate tag sequence to all buffer
   asn1_Build_tl(TAG_SEQUENCE, asn1_GetBufferSize());

   return CK_TRUE;
}
/*
     SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING
     }

Algorithmidentifier:: = SEQUENCE{
  algorithm       OBJECT IDENTIFIER,
  parameters any      DEFINED by algorithm OPTIONAL
}

     id-ecPublicKey OBJECT IDENTIFIER ::= {
       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }

       id-Ed25519 OBJECT IDENTIFIER ::= {
       {iso(1) identified-organization(3) thawte(101) id-Ed25519(112)}

ECParameters :: = CHOICE{
  namedCurve         OBJECT IDENTIFIER
  -- implicitCurve   NULL
  -- specifiedCurve  SpecifiedECDomain
}

subjectPublicKey
ECPoint :: = OCTET STRING

// eddsa : parameters is absent
https://datatracker.ietf.org/doc/html/rfc8410#page-4

*/
/*
    FUNCTION:        CK_BBOOL pksc8_Build_PublicKeyInfoEC(EC_PUBLIC_KEY* sEcPublicKey, CK_KEY_TYPE ckKeyType)
*/
CK_BBOOL pksc8_Build_PublicKeyInfoEC(EC_PUBLIC_KEY* sEcPublicKey, CK_KEY_TYPE ckKeyType)
{
   CK_ULONG uTlvSize = 0;

   // init asn1builder
   asn1_Build_Init();

   // Tag bitstring for public point
   asn1_Build_tlv(TAG_BITSTRING, sEcPublicKey->sPublicPoint, sEcPublicKey->uPublicPointLength);

   // check the key type
   switch (ckKeyType)
   {
   case CKK_ECDSA:
   case CKK_SM2:

      // New tlv branch
      // push domain OID
      uTlvSize = asn1_Build_t(sEcPublicKey->sOid, sEcPublicKey->uOidSize);

      // push ecPublicKey OID for ECDSA and SM2
      uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_EC_PUBLICKEY, sizeof(OID_EC_PUBLICKEY));
      break;
   case CKK_EC_EDWARDS:
   case CKK_EC_EDWARDS_OLD:
   case CKK_EC_MONTGOMERY:
   case CKK_EC_MONTGOMERY_OLD:
      /*
      // push null tag ????
      uTlvSize = asn1_Build_tl(TAG_NULL, 0);
      */
      // TODO check sEcPublicKey->sOid and push oid depending of the oid
      // New tlv branch
      // push eddsasignature OID id-Ed25519
      uTlvSize = asn1_Build_t(sEcPublicKey->sOid, sEcPublicKey->uOidSize);
      break;
   }

   // encapsulate tag sequence in this tlv branch
   asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

   // encapsulate tag sequence to all buffer
   asn1_Build_tl(TAG_SEQUENCE, asn1_GetBufferSize());

   return CK_TRUE;
}

/*
https://datatracker.ietf.org/doc/html/rfc5912

DSA public key

The steps to dump a DSA public key are identical to that of RSA. DSA's OID is 1.2.840.10040.4.1. DSA will include DSS domain parameters in the optional parameters.

PublicKeyInfo ::= SEQUENCE {
  algorithm AlgorithmIdentifier,
  PublicKey BIT STRING
}

DSA
   id-dsa OBJECT IDENTIFIER ::= {
    iso(1) member-body(2) us(840) x9-57(10040) x9algorithm(4) 1 }

AlgorithmIdentifier ::= SEQUENCE {
  algorithm ALGORITHM.id,
  parameters Dss-Parms
}

Dss-Parms ::= SEQUENCE {
  p INTEGER,
  q INTEGER,
  g INTEGER
}

   DSAPublicKey ::= INTEGER --  public key, y

/*
    FUNCTION:        CK_BBOOL pksc8_Build_PublicKeyInfoDSA(DSA_PUBLIC_KEY* sDSAPublicKey)
*/
CK_BBOOL pksc8_Build_PublicKeyInfoDSA(DSA_PUBLIC_KEY* sDSAPublicKey)
{
   CK_ULONG uTlvSize;

   // init asn1builder
   asn1_Build_Init();
   // Tag sequence for public key
   asn1_Build_tlv(TAG_INTEGER, sDSAPublicKey->sPublicKey, sDSAPublicKey->uPublicKeyLength);

   // encapsulate in tag bitstring
   asn1_Build_tl(TAG_BITSTRING, asn1_GetBufferSize());

   // Tag sequence for base g in new branch
   uTlvSize = asn1_Build_tlv(TAG_INTEGER, sDSAPublicKey->sDomain.sBase, sDSAPublicKey->sDomain.uBaseLength);

   // Tag sequence for sub prime q
   uTlvSize += asn1_Build_tlv(TAG_INTEGER, sDSAPublicKey->sDomain.sSubPrime, sDSAPublicKey->sDomain.uSubPrimeLength);

   // Tag sequence for prime p
   uTlvSize += asn1_Build_tlv(TAG_INTEGER, sDSAPublicKey->sDomain.sPrime, sDSAPublicKey->sDomain.uPrimeLength);
   sDSAPublicKey->sDomain.bIsSubPrime = CK_TRUE;

   // encapsulate in tag sequence
   uTlvSize += asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

   // Tag oid for dsa
   uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_DSA_PUBLICKEY, sizeof(OID_DSA_PUBLICKEY));

   // encapsulate in tag sequence
   asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

   // encapsulate tag sequence to all buffer
   asn1_Build_tl(TAG_SEQUENCE, asn1_GetBufferSize());

   return CK_TRUE;
}

/*
   -- Diffie-Hellman PK Algorithm, Parameters, and Keys

PublicKeyInfo ::= SEQUENCE {
  algorithm AlgorithmIdentifier,
  PublicKey BIT STRING
}

pkcs key ???
   dhpublicnumber OBJECT IDENTIFIER ::= {
    iso(1) member-body(2) us(840) ansi-x942(10046)
    number-type(3) 1 }

    x9.42 key
   dhpublicnumber OBJECT IDENTIFIER ::= {
    iso(1) member-body(2) us(840) ansi-x942(10046)
    number-type(2) 1 }

    PKCS3
    DHParameter ::= SEQUENCE {
  prime INTEGER, -- p
  base INTEGER, -- g
  privateValueLength INTEGER OPTIONAL }

  X9.42
   DomainParameters ::= SEQUENCE {
    p                INTEGER,           -- odd prime, p=jq +1
    g                INTEGER,           -- generator, g
    q                INTEGER,           -- factor of p-1
    j                INTEGER OPTIONAL,  -- subgroup factor, j>= 2
    validationParams  ValidationParams OPTIONAL
   }

   ValidationParams ::= SEQUENCE {
    seed         BIT STRING,
    pgenCounter  INTEGER
   }

   DHPublicKey ::= INTEGER  -- public key, y = g^x mod p

   https://www.ietf.org/rfc/rfc3279.txt

   -----BEGIN PRIVATE KEY-----
MIICZAIBADCCAjkGByqGSM4+AgEwggIsAoIBAQCHqOYdtLZmPP+70ZxlGVmZjO72
CGYN0PJdLO7UQ147AOAN+PHWGVfU+vffRWGyqjAWw9kRNAlvqjv0KW2DDpp8IJ4M
ZJdRer1aip0wa89n7ZH55nJbR1jAIuCx70J1v3tsW/wR1F+QiLlB9U6x5Zu4vDmg
vxIwf1xP23DFgbI/drY6yuHKpreQLVJSZzVIig7xPG2aUb+kqzrYNHeWUk2O9qFn
taQYJdln4UTlFAVkJRzKy4PmtIb2s8o/eXFQYCbAuFf2iZYoVt7UAQq9C+Yhw6OW
ClTnEMN18mN11wFBA6S1QzDBmK8SYRbSJ24RcV9pOHf61+8JytsJSukeGhWXAoIB
AD+zLJtzE00LLndQZmDtvUhMp7GPIe8gVAf0eToaC6ElENvBUHe+Rj//T+1KrAu1
Vb46bBsMa0exvDdzv36Mb2KQEij4woy7GKVa4xNBAAplAZb5Mcd6V/Ld9GPl6ewU
S3d95iqquKhiisN20oLW7Thk5nmCQo68gx0UNI9vL5GTtQRa8nZxZOHfyWfB+z8u
VaS9G//oO5yA0FK5hdGC6grbKjtzE9P+FMhISx4FJYi5t9K70t8BYZns0G4VV80J
FbM1O7tk4Ow3f9AoNw35K1LHiRQozcZ+thhLUj0dskbDL2MHhJDwDvjWR9FI1HlU
UV4jJ8/vmMWCZktMD2zEFlkCIQCM+DZCpwmgl7RHmXZAEp2imbGkfR6zdQujCLD+
ZPX70wQiAiBvWQZVf0vXQPl+ovrzFwbia4oDGbPwYtQ83yaLtFo0hw==
-----END PRIVATE KEY-----


   -----BEGIN PUBLIC KEY-----
MIIBHzCBlQYJKoZIhvcNAQMBMIGHAoGBALzizRYfhhdc1miJMXG88tKCCdLOSIG7
G2Fsh27ec41AP+pExiT781P/JjnLmy85Niy9OhTZDkiSnAqNiWO+DC/3elIKjHfx
QgBMMd+57MCduH9MEOVEQKb/drJkPFeCBShJlM+KyoNCpLfV0Tu/icb/KTQAUdiQ
A0cehBtTNmwzAgECA4GEAAKBgCoDjDV/cvxDi0PC9h8iiqD+i5gzQNnoe3jd77RK
HW2pZ39jDvYEGtfgWsg8TAw2vyNCKZcxP3ho2BRMF4X7J7PTwijMFMHQbcGzyY1R
WmcCO4UfkRYVN65NtiA3zmu7hBaiIYF4VgpoFcOlUcsUlNceaRS6zc5ua0GGNMpA
DThf
-----END PUBLIC KEY-----

*/

/*
    FUNCTION:        CK_BBOOL pksc8_Build_PublicKeyInfoDSA(DSA_PUBLIC_KEY* sDSAPublicKey)
*/
CK_BBOOL pksc8_Build_PublicKeyInfoDH(DH_PUBLIC_KEY* sDHPublicKey)
{
   CK_ULONG uTlvSize = 0;
   CK_BBOOL bIsSubPrime = CK_TRUE;

   if (sDHPublicKey->sDomain.sSubPrime == NULL)
   {
      bIsSubPrime = CK_FALSE;
   }

   // init asn1builder
   asn1_Build_Init();
   // Tag sequence for public key
   asn1_Build_tlv(TAG_INTEGER, sDHPublicKey->sPublicKey, sDHPublicKey->uPublicKeyLength);

   // encapsulate in tag bitstring
   asn1_Build_tl(TAG_BITSTRING, asn1_GetBufferSize());

   if (bIsSubPrime == CK_TRUE)
   {
      // Tag sequence for sub prime q
      uTlvSize = asn1_Build_tlv(TAG_INTEGER, sDHPublicKey->sDomain.sSubPrime, sDHPublicKey->sDomain.uSubPrimeLength);
   }

   // Tag sequence for base g in new branch
   uTlvSize += asn1_Build_tlv(TAG_INTEGER, sDHPublicKey->sDomain.sBase, sDHPublicKey->sDomain.uBaseLength);

   // Tag sequence for prime p
   uTlvSize += asn1_Build_tlv(TAG_INTEGER, sDHPublicKey->sDomain.sPrime, sDHPublicKey->sDomain.uPrimeLength);

   // encapsulate in tag sequence
   uTlvSize += asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

   // if sub prime is absent, cannot use oid dh public key from x942 because q is mandatory, use old oid dh key agreement from pkcs3 instead where q is optionnal
   if (bIsSubPrime == CK_TRUE)
   {
      // Tag oid for dh
      uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_DH_PUBLICKEY, sizeof(OID_DH_PUBLICKEY));
   }
   else
   {
      // Tag oid for dh key agreement from pkcs3
      uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_DH_KEYAGREMENT_PKCS3, sizeof(OID_DH_KEYAGREMENT_PKCS3));
   }

   // encapsulate in tag sequence
   asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

   // encapsulate tag sequence to all buffer
   asn1_Build_tl(TAG_SEQUENCE, asn1_GetBufferSize());

   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL pksc8_Build_PublicKeyInfoMLDSA(ML_DSA_PUBLIC_KEY* sMLKEMPublicKey)
*/
CK_BBOOL pksc8_Build_PublicKeyInfoMLDSA(ML_DSA_PUBLIC_KEY* sMLDSAPublicKey)
{
   CK_ULONG uTlvSize = 0;

   // init asn1builder
   asn1_Build_Init();

   // Tag bitstring for public point
   asn1_Build_tlv(TAG_BITSTRING, sMLDSAPublicKey->sPublicKey, sMLDSAPublicKey->uPublicKeyLength);


   switch (sMLDSAPublicKey->uML_DSA_Parameter_Set)
   {
   case CKP_ML_DSA_44:

      // New tlv branch
      // push OID
      uTlvSize = asn1_Build_t((CK_CHAR_PTR)OID_ML_DSA_44, sizeof(OID_ML_DSA_44));
      break;
   case CKP_ML_DSA_65:

      // New tlv branch
      // push OID
      uTlvSize = asn1_Build_t((CK_CHAR_PTR)OID_ML_DSA_65, sizeof(OID_ML_DSA_65));
      break;
   case CKP_ML_DSA_87:

      // New tlv branch
      // push OID
      uTlvSize = asn1_Build_t((CK_CHAR_PTR)OID_ML_DSA_87, sizeof(OID_ML_DSA_87));
      break;
   default:
      return CK_FALSE;

   }

   // encapsulate tag sequence in this tlv branch
   asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

   // encapsulate tag sequence to all buffer
   asn1_Build_tl(TAG_SEQUENCE, asn1_GetBufferSize());

   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL pksc8_Build_PublicKeyInfoMLKEM(ML_KEM_PUBLIC_KEY* sMLKEMPublicKey)
*/
CK_BBOOL pksc8_Build_PublicKeyInfoMLKEM(ML_KEM_PUBLIC_KEY* sMLKEMPublicKey)
{
   CK_ULONG uTlvSize = 0;

   // init asn1builder
   asn1_Build_Init();

   // Tag bitstring for public point
   asn1_Build_tlv(TAG_BITSTRING, sMLKEMPublicKey->sPublicKey, sMLKEMPublicKey->uPublicKeyLength);


   switch (sMLKEMPublicKey->uML_KEM_Parameter_Set)
   {
   case CKP_ML_KEM_512:

      // New tlv branch
      // push OID
      uTlvSize = asn1_Build_t((CK_CHAR_PTR)OID_ML_KEM_512, sizeof(OID_ML_KEM_512));
      break;
   case CKP_ML_KEM_768:

      // New tlv branch
      // push OID
      uTlvSize = asn1_Build_t((CK_CHAR_PTR)OID_ML_KEM_768, sizeof(OID_ML_KEM_768));
      break;
   case CKP_ML_KEM_1024:

      // New tlv branch
      // push OID
      uTlvSize = asn1_Build_t((CK_CHAR_PTR)OID_ML_KEM_1024, sizeof(OID_ML_KEM_1024));
      break;
   default:
      return CK_FALSE;

   }

   // encapsulate tag sequence in this tlv branch
   asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

   // encapsulate tag sequence to all buffer
   asn1_Build_tl(TAG_SEQUENCE, asn1_GetBufferSize());

   return CK_TRUE;
}

/* 
https://datatracker.ietf.org/doc/html/rfc8708#name-leighton-micali-one-time-si
https://mirrors.ircam.fr/pub/rfc/rfc8708.html
https://www.rfc-editor.org/rfc/rfc9802.html

   pk-HSS-LMS-HashSig PUBLIC-KEY ::= {
       IDENTIFIER id-alg-hss-lms-hashsig
       KEY HSS-LMS-HashSig-PublicKey
       PARAMS ARE absent
       CERT-KEY-USAGE
         { digitalSignature, nonRepudiation, keyCertSign, cRLSign } }

   HSS-LMS-HashSig-PublicKey ::= OCTET STRING


    id-alg-hss-lms-hashsig OBJECT IDENTIFIER ::= { iso(1)
       member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
       smime(16) alg(3) 17 }


*/
/*
    FUNCTION:        CK_BBOOL pksc8_Build_PublicKeyInfoLMS(LMS_PUBLIC_KEY* sMLKEMPublicKey)
*/
CK_BBOOL pksc8_Build_PublicKeyInfoLMS(LMS_PUBLIC_KEY* sLmspublickey)
{

   CK_ULONG uTlvSize = 0;

   // init asn1builder
   asn1_Build_Init();

   // Tag bitstring for public point
   asn1_Build_tlv(TAG_BITSTRING, sLmspublickey->sPublicKey, sLmspublickey->uPublicKeyLength);

   uTlvSize = asn1_Build_t((CK_CHAR_PTR)OID_LMS_HSS_SIG, sizeof(OID_LMS_HSS_SIG));
   
   // encapsulate tag sequence in this tlv branch
   asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

   // encapsulate tag sequence to all buffer
   asn1_Build_tl(TAG_SEQUENCE, asn1_GetBufferSize());
   
   return CK_TRUE;
}



/*
https://www.ietf.org/rfc/rfc5208.txt

EncryptedPrivateKeyInfo ::= SEQUENCE {
    encryptionAlgorithm AlgorithmIdentifier {{KeyEncryptionAlgorithms}},
    encryptedData EncryptedData
}

https://datatracker.ietf.org/doc/html/rfc2898#appendix-A.4

id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13}

   AlgorithmIdentifier { ALGORITHM-IDENTIFIER:InfoObjectSet } ::=
     SEQUENCE {
       algorithm ALGORITHM-IDENTIFIER.&id({InfoObjectSet}),
       parameters ALGORITHM-IDENTIFIER.&Type({InfoObjectSet}
       {@algorithm}) OPTIONAL
   }


parameters = PBES2-params ::= SEQUENCE {
       keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
       encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }


       id-PBKDF2 OBJECT IDENTIFIER ::= {pkcs-5 12}

keyDerivationFunc=
   PBKDF2Algorithms ALGORITHM-IDENTIFIER ::= {
      {PBKDF2-params IDENTIFIED BY id-PBKDF2},
      ...
   }


      PBKDF2-params ::= SEQUENCE {
       salt CHOICE {
           specified OCTET STRING,
           otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
       },
       iterationCount INTEGER (1..MAX),
       keyLength INTEGER (1..MAX) OPTIONAL,
       prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
       algid-hmacWithSHA1 }


 prf =
 PBKDF2-PRFs ALGORITHM-IDENTIFIER ::= {
     {NULL IDENTIFIED BY id-hmacWithSHA1},
     {NULL IDENTIFIED BY id-hmacWithSHA224},
     {NULL IDENTIFIED BY id-hmacWithSHA256},
     {NULL IDENTIFIED BY id-hmacWithSHA384},
     {NULL IDENTIFIED BY id-hmacWithSHA512},
     {NULL IDENTIFIED BY id-hmacWithSHA512-224},
     {NULL IDENTIFIED BY id-hmacWithSHA512-256},
     ...
   }


https://www.rfc-editor.org/rfc/rfc8018.html#appendix-C

encryptionScheme =

   SupportingAlgorithms ALGORITHM-IDENTIFIER ::= {
      {NULL IDENTIFIED BY id-hmacWithSHA1}                   |
      {OCTET STRING (SIZE(8)) IDENTIFIED BY desCBC}          |
      {OCTET STRING (SIZE(8)) IDENTIFIED BY des-EDE3-CBC}    |
      {RC2-CBC-Parameter IDENTIFIED BY rc2CBC}               |
      {RC5-CBC-Parameters IDENTIFIED BY rc5-CBC-PAD},        |
      {OCTET STRING (SIZE(16)) IDENTIFIED BY aes128-CBC-PAD} |
      {OCTET STRING (SIZE(16)) IDENTIFIED BY aes192-CBC-PAD} |
      {OCTET STRING (SIZE(16)) IDENTIFIED BY aes256-CBC-PAD},
       ...
   }

The AES object identifier is defined in Appendix C.

   The parameters field associated with this OID in an
   AlgorithmIdentifier shall have type OCTET STRING (SIZE(16)),
   specifying the initialization vector for CBC mode.

   AES-CBC-ALGORITHM-IDENTIFIER ::= SEQUENCE {
       ALGORITHM-IDENTIFIER,
       iv OCTET STRING (SIZE(16))
   }

*/

/*
    FUNCTION:        CK_BBOOL pksc8_Build_EncryptedPrivateKeyInfoPbe(P11_PBE_ENC_PARAMS* sPbe)
*/
CK_BBOOL pksc8_Build_EncryptedPrivateKeyInfoPbe(P11_PBE_ENC_PARAMS* sPbe)
{
   CK_ULONG uTlvEncryptedDataSize = 0;
   CK_ULONG uTlvEncryptedAlgoSize = 0;
   CK_ULONG uTlvSize = 0;
   CK_ULONG uSize = 0;

   // init asn1builder
   asn1_Build_Init();

   // new branch (encryptedData)
   // Tag octect string for encrypted private key
   uTlvEncryptedDataSize = asn1_Build_tlv(TAG_OCTECTSTRING, sPbe->pWrappedKey, sPbe->ulWrappedKeyLen);


   if (sPbe->ckPbeMechType == CKM_PKCS5_PBKD2)
   {
      // new branch (encryptionScheme AES-CBC-ALGORITHM-IDENTIFIER)
      // Puth IV in tag octect string
      uTlvSize = asn1_Build_tlv(TAG_OCTECTSTRING, sPbe->pIv, sPbe->ulIvLen);

      // Puth OID
      switch (sPbe->ckEncMechType)
      {
      case CKM_AES_CBC_PAD:
         if (sPbe->sEnckeySize == AES_128_KEY_LENGTH)
         {
            uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_NIST_AES_128_CBC_PAD, sizeof(OID_NIST_AES_128_CBC_PAD));
         }
         else if (sPbe->sEnckeySize == AES_192_KEY_LENGTH)
         {
            uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_NIST_AES_192_CBC_PAD, sizeof(OID_NIST_AES_192_CBC_PAD));
         }
         else if (sPbe->sEnckeySize == AES_256_KEY_LENGTH)
         {
            uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_NIST_AES_256_CBC_PAD, sizeof(OID_NIST_AES_256_CBC_PAD));
         }
         else
         {
            return CK_FALSE;
         }
         break;
      default:
         return CK_FALSE;
      }

      // encapsulate in tag sequence
      uTlvSize += asn1_Build_tl(TAG_SEQUENCE, uTlvSize);
      uTlvEncryptedAlgoSize = uTlvSize;

      // new branch (keyDerivationFunc PBKDF2Algorithms)
      uTlvSize = 0;

      switch (sPbe->pbkdf2.pbfkd2_param.prf)
      {
      case CKP_PKCS5_PBKD2_HMAC_SHA1:
         break;
      case CKP_PKCS5_PBKD2_HMAC_SHA224:
         uTlvSize += asn1_Build_tl(TAG_NULL, 0);
         uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_HMAC_SHA224, sizeof(OID_HMAC_SHA224));
         break;
      case CKP_PKCS5_PBKD2_HMAC_SHA256:
         uTlvSize += asn1_Build_tl(TAG_NULL, 0);
         uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_HMAC_SHA256, sizeof(OID_HMAC_SHA256));
         break;
      case CKP_PKCS5_PBKD2_HMAC_SHA384:
         uTlvSize += asn1_Build_tl(TAG_NULL, 0);
         uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_HMAC_SHA384, sizeof(OID_HMAC_SHA384));
         break;
      case CKP_PKCS5_PBKD2_HMAC_SHA512:
         uTlvSize += asn1_Build_tl(TAG_NULL, 0);
         uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_HMAC_SHA512, sizeof(OID_HMAC_SHA512));
         break;
      case CKP_PKCS5_PBKD2_HMAC_SHA512_224:
         uTlvSize += asn1_Build_tl(TAG_NULL, 0);
         uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_HMAC_SHA512_224, sizeof(OID_HMAC_SHA512_224));
         break;
      case CKP_PKCS5_PBKD2_HMAC_SHA512_256:
         uTlvSize += asn1_Build_tl(TAG_NULL, 0);
         uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_HMAC_SHA512_256, sizeof(OID_HMAC_SHA512_256));
         break;
      default:
         return CK_FALSE;
      }

      if (sPbe->pbkdf2.pbfkd2_param.prf != CKP_PKCS5_PBKD2_HMAC_SHA1)
      {
         uTlvSize += asn1_Build_tl(TAG_SEQUENCE, uTlvSize);
      }

      // Push ierations
      uTlvSize += asn1_Build_tlv_Long(TAG_INTEGER, sPbe->pbkdf2.pbfkd2_param.iterations);

      // Push salt value
      uTlvSize += asn1_Build_tlv(TAG_OCTECTSTRING, sPbe->pbkdf2.pbfkd2_param.pSaltSourceData, sPbe->pbkdf2.pbfkd2_param.ulSaltSourceDataLen);

      // encapsulate in sequence
      uTlvSize += asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

      // push oid pbkdf2
      uTlvSize += asn1_Build_t((CK_CHAR_PTR)OID_PKCS5_PBKDF2, sizeof(OID_PKCS5_PBKDF2));

      // encapsulate in sequence
      uTlvSize += asn1_Build_tl(TAG_SEQUENCE, uTlvSize);

      // encapsulate in sequence (keyDerivationFunc + encryptionScheme)
      uTlvEncryptedAlgoSize = uTlvEncryptedAlgoSize + uTlvSize + asn1_Build_tl(TAG_SEQUENCE, uTlvSize + uTlvEncryptedAlgoSize);

      // push oid pbes2
      uTlvEncryptedAlgoSize += asn1_Build_t((CK_CHAR_PTR)OID_PKCS5_PBES2, sizeof(OID_PKCS5_PBES2));

      // encapsulate in tag sequence
      uTlvEncryptedAlgoSize += asn1_Build_tl(TAG_SEQUENCE, uTlvEncryptedAlgoSize);

      // encapsulate in sequence (encryptionAlgorithm + encryptedData)
      asn1_Build_tl(TAG_SEQUENCE, uTlvEncryptedAlgoSize + uTlvEncryptedDataSize);
   }
   else
   {
      // other pbe format not yet supported
      return CK_FALSE;
   }

   return CK_TRUE;
}

/*
    FUNCTION:        pksc8_Check_PublicKeyInfoRSA(RSA_PUBLIC_KEY* sRsaPublicKey, CK_CHAR_PTR data, CK_ULONG size)
*/
CK_BBOOL pksc8_Check_PublicKeyInfoRSA(RSA_PUBLIC_KEY* sRsaPublicKey, CK_CHAR_PTR data, CK_ULONG size)
{
   do
   {
      // init settlv
      asn1_Check_SetTlv(data, size);

      // Check tag Sequence
      if (asn1_Check_tl(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag Sequence
      if (asn1_Check_t(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag OID
      if (asn1_Check_t(TAG_OID) == CK_FALSE)
      {
         break;
      }
      // Check OID is RSA encryption PKCS1
      if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_RSA_ENCRYPTION, asn1_Check_GetCurrentTlvLen()) != 0)
      {
         break;
      }

      // Check tag null
      if (asn1_Check_Next(TAG_NULL) == CK_FALSE)
      {
         break;
      }
      // check tag null len is zero
      if (asn1_Check_GetCurrentValueLen() != 0)
      {
         break;
      }

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // Check tag bit string
      if (asn1_Check_Next(TAG_BITSTRING) == CK_FALSE)
      {
         break;
      }

      // step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }

      // Check tag Sequence
      if (asn1_Check_t(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag Integer
      if (asn1_Check_t(TAG_INTEGER) == CK_FALSE)
      {
         break;
      }
      // set modulus
      sRsaPublicKey->sModulus = asn1_Check_GetCurrentValueBuffer();
      sRsaPublicKey->uModulusLength = asn1_Check_GetCurrentValueLen();

      // Check tag Integer
      if (asn1_Check_Next(TAG_INTEGER) == CK_FALSE)
      {
         break;
      }
      // set public exponent
      sRsaPublicKey->sExponent = asn1_Check_GetCurrentValueBuffer();
      sRsaPublicKey->uExponentLength = asn1_Check_GetCurrentValueLen();

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }
      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL pksc8_Check_PublicKeyInfoEC(EC_PUBLIC_KEY* sECPublicKey, CK_CHAR_PTR data, CK_ULONG size, CK_KEY_TYPE ckKeyType)
*/
CK_BBOOL pksc8_Check_PublicKeyInfoEC(EC_PUBLIC_KEY* sECPublicKey, CK_CHAR_PTR data, CK_ULONG size, CK_KEY_TYPE ckKeyType)
{
   CK_LONG sResult = -1;
   do
   {
      // init settlv
      asn1_Check_SetTlv(data, size);

      // Check tag Sequence
      if (asn1_Check_tl(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag Sequence
      if (asn1_Check_t(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag OID
      if (asn1_Check_t(TAG_OID) == CK_FALSE)
      {
         break;
      }

      // check the key type
      switch (ckKeyType)
      {
      case CKK_ECDSA:
      case CKK_SM2:
         // Check OID is ecPublicKey
         sResult = memcmp(asn1_Check_GetCurrentTagBuffer(), OID_EC_PUBLICKEY, asn1_Check_GetCurrentTlvLen());

         // check if oid match
         if (sResult != 0)
         {
            return CK_FALSE;
         }

         // Check tag null
         if (asn1_Check_Next(TAG_OID) == CK_FALSE)
         {
            break;
         }

         // Get OID
         sECPublicKey->sOid = asn1_Check_GetCurrentTagBuffer();
         sECPublicKey->uOidSize = asn1_Check_GetCurrentTlvLen();
         break;
      case CKK_EC_EDWARDS:
      case CKK_EC_EDWARDS_OLD:
      case CKK_EC_MONTGOMERY:
      case CKK_EC_MONTGOMERY_OLD:
         // Get OID 
         // Warning. The oid in public key is not the same accepted by HSM. Conversion is done later
         sECPublicKey->sOid = asn1_Check_GetCurrentTagBuffer();
         sECPublicKey->uOidSize = asn1_Check_GetCurrentTlvLen();

         // no tag tlv for domain ID
      }
      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // Check tag bit string
      if (asn1_Check_Next(TAG_BITSTRING) == CK_FALSE)
      {
         break;
      }

      // get public key in uncompressed format
      sECPublicKey->sPublicPoint = asn1_Check_GetCurrentValueBuffer();
      sECPublicKey->uPublicPointLength = asn1_Check_GetCurrentValueLen();

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      return CK_TRUE;
   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        pksc8_Check_PublicKeyInfoRSA(DSA_PUBLIC_KEY* sDsaPublicKey, CK_CHAR_PTR data, CK_ULONG size)
*/
CK_BBOOL pksc8_Check_PublicKeyInfoDSA(DSA_PUBLIC_KEY* sDsaPublicKey, CK_CHAR_PTR data, CK_ULONG size)
{
   do
   {
      // init settlv
      asn1_Check_SetTlv(data, size);

      // Check tag Sequence
      if (asn1_Check_tl(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag Sequence
      if (asn1_Check_t(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag OID
      if (asn1_Check_t(TAG_OID) == CK_FALSE)
      {
         break;
      }
      // Check OID is DSA public PKCS1
      if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_DSA_PUBLICKEY, asn1_Check_GetCurrentTlvLen()) != 0)
      {
         break;
      }

      // Check tag sequence
      if (asn1_Check_Next(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }

      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }

      // Check tag integer (prime)
      if (asn1_Check_t(TAG_INTEGER) == CK_FALSE)
      {
         break;
      }
      sDsaPublicKey->sDomain.sPrime = asn1_Check_GetCurrentValueBuffer();
      sDsaPublicKey->sDomain.uPrimeLength = asn1_Check_GetCurrentValueLen();


      // Check tag sequence (sub-prime)
      if (asn1_Check_Next(TAG_INTEGER) == CK_FALSE)
      {
         break;
      }

      sDsaPublicKey->sDomain.sSubPrime = asn1_Check_GetCurrentValueBuffer();
      sDsaPublicKey->sDomain.uSubPrimeLength = asn1_Check_GetCurrentValueLen();
      sDsaPublicKey->sDomain.bIsSubPrime = CK_TRUE;

      // Check tag sequence (base)
      if (asn1_Check_Next(TAG_INTEGER) == CK_FALSE)
      {
         break;
      }

      sDsaPublicKey->sDomain.sBase = asn1_Check_GetCurrentValueBuffer();
      sDsaPublicKey->sDomain.uBaseLength = asn1_Check_GetCurrentValueLen();

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // Check tag bit string
      if (asn1_Check_Next(TAG_BITSTRING) == CK_FALSE)
      {
         break;
      }

      // step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }

      // Check tag Sequence
      if (asn1_Check_t(TAG_INTEGER) == CK_FALSE)
      {
         break;
      }

      // set public key
      sDsaPublicKey->sPublicKey = asn1_Check_GetCurrentValueBuffer();
      sDsaPublicKey->uPublicKeyLength = asn1_Check_GetCurrentValueLen();


      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        pksc8_Check_PublicKeyInfoDH(DH_PUBLIC_KEY* sDhPublicKey, CK_CHAR_PTR data, CK_ULONG size)
*/
CK_BBOOL pksc8_Check_PublicKeyInfoDH(DH_PUBLIC_KEY* sDhPublicKey, CK_CHAR_PTR data, CK_ULONG size)
{
   CK_LONG lResult;
   do
   {
      // init settlv
      asn1_Check_SetTlv(data, size);

      // Check tag Sequence
      if (asn1_Check_tl(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag Sequence
      if (asn1_Check_t(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag OID
      if (asn1_Check_t(TAG_OID) == CK_FALSE)
      {
         break;
      }
      // Check OID is DH public key
      lResult = memcmp(asn1_Check_GetCurrentTagBuffer(), OID_DH_PUBLICKEY, asn1_Check_GetCurrentTlvLen());

      // if OID dh public key match, set
      if (lResult == 0)
      {
         sDhPublicKey->sDomain.bIsSubPrime = CK_TRUE;
      }
      else
      {
         // Check OID is DH public key
         lResult = memcmp(asn1_Check_GetCurrentTagBuffer(), OID_DH_KEYAGREMENT_PKCS3, asn1_Check_GetCurrentTlvLen());

         if (lResult == 0)
         {
            sDhPublicKey->sDomain.bIsSubPrime = CK_FALSE;
         }
         else
         {
            // error, not valid OID
            break;
         }
      }

      // Check tag sequence
      if (asn1_Check_Next(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }

      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }

      // Check tag integer (prime)
      if (asn1_Check_t(TAG_INTEGER) == CK_FALSE)
      {
         break;
      }
      sDhPublicKey->sDomain.sPrime = asn1_Check_GetCurrentValueBuffer();
      sDhPublicKey->sDomain.uPrimeLength = asn1_Check_GetCurrentValueLen();

      // Check tag sequence (base)
      if (asn1_Check_Next(TAG_INTEGER) == CK_FALSE)
      {
         break;
      }

      sDhPublicKey->sDomain.sBase = asn1_Check_GetCurrentValueBuffer();
      sDhPublicKey->sDomain.uBaseLength = asn1_Check_GetCurrentValueLen();

      // get the sub prime if dh x942 oid
      if (sDhPublicKey->sDomain.bIsSubPrime == CK_TRUE)
      {
         // Check tag sequence (sub-prime)
         if (asn1_Check_Next(TAG_INTEGER) == CK_FALSE)
         {
            break;
         }

         sDhPublicKey->sDomain.sSubPrime = asn1_Check_GetCurrentValueBuffer();
         sDhPublicKey->sDomain.uSubPrimeLength = asn1_Check_GetCurrentValueLen();
      }

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // Check tag bit string
      if (asn1_Check_Next(TAG_BITSTRING) == CK_FALSE)
      {
         break;
      }

      // step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }

      // Check tag Sequence
      if (asn1_Check_t(TAG_INTEGER) == CK_FALSE)
      {
         break;
      }

      // set public key
      sDhPublicKey->sPublicKey = asn1_Check_GetCurrentValueBuffer();
      sDhPublicKey->uPublicKeyLength = asn1_Check_GetCurrentValueLen();

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL pksc8_Check_PublicKeyInfoMLDSA(ML_DSA_PUBLIC_KEY* sMlKemPublicKey, CK_ML_DSA_PARAMETER_SET_TYPE pParameterSet, CK_CHAR_PTR data, CK_ULONG size)
*/
CK_BBOOL pksc8_Check_PublicKeyInfoMLDSA(ML_DSA_PUBLIC_KEY* sMlDsaPublicKey, CK_CHAR_PTR data, CK_ULONG size)
{
   do
   {
      // init settlv
      asn1_Check_SetTlv(data, size);

      // Check tag Sequence
      if (asn1_Check_tl(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag Sequence
      if (asn1_Check_t(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag OID
      if (asn1_Check_t(TAG_OID) == CK_FALSE)
      {
         break;
      }

      // Check OID is DSA public PKCS1
      if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_ML_DSA_44, asn1_Check_GetCurrentTlvLen()) == 0)
      {
         sMlDsaPublicKey->uML_DSA_Parameter_Set = CKP_ML_DSA_44;
      }
      else if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_ML_DSA_65, asn1_Check_GetCurrentTlvLen()) == 0)
      {
         sMlDsaPublicKey->uML_DSA_Parameter_Set = CKP_ML_DSA_65;
      }
      else if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_ML_DSA_87, asn1_Check_GetCurrentTlvLen()) == 0)
      {
         sMlDsaPublicKey->uML_DSA_Parameter_Set = CKP_ML_DSA_87;
      }
      else
      {
         break;
      }

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // Check tag bit string
      if (asn1_Check_Next(TAG_BITSTRING) == CK_FALSE)
      {
         break;
      }

      // get public key in uncompressed format
      sMlDsaPublicKey->sPublicKey = asn1_Check_GetCurrentValueBuffer();
      sMlDsaPublicKey->uPublicKeyLength = asn1_Check_GetCurrentValueLen();

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      return CK_TRUE;
   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL pksc8_Check_PublicKeyInfoMLKEM(ML_KEM_PUBLIC_KEY* sMlKemPublicKey, CK_CHAR_PTR data, CK_ULONG size)
*/
CK_BBOOL pksc8_Check_PublicKeyInfoMLKEM(ML_KEM_PUBLIC_KEY* sMlKemPublicKey, CK_CHAR_PTR data, CK_ULONG size)
{

   do
   {
      // init settlv
      asn1_Check_SetTlv(data, size);

      // Check tag Sequence
      if (asn1_Check_tl(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag Sequence
      if (asn1_Check_t(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag OID
      if (asn1_Check_t(TAG_OID) == CK_FALSE)
      {
         break;
      }

      // Check OID is DSA public PKCS1
      if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_ML_KEM_512, asn1_Check_GetCurrentTlvLen()) == 0)
      {
         sMlKemPublicKey->uML_KEM_Parameter_Set = CKP_ML_KEM_512;
      }
      else if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_ML_KEM_768, asn1_Check_GetCurrentTlvLen()) == 0)
      {
         sMlKemPublicKey->uML_KEM_Parameter_Set = CKP_ML_KEM_768;
      }
      else if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_ML_KEM_1024, asn1_Check_GetCurrentTlvLen()) == 0)
      {
         sMlKemPublicKey->uML_KEM_Parameter_Set = CKP_ML_KEM_1024;
      }
      else
      {
         break;
      }

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // Check tag bit string
      if (asn1_Check_Next(TAG_BITSTRING) == CK_FALSE)
      {
         break;
      }

      // get public key in uncompressed format
      sMlKemPublicKey->sPublicKey = asn1_Check_GetCurrentValueBuffer();
      sMlKemPublicKey->uPublicKeyLength = asn1_Check_GetCurrentValueLen();

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      return CK_TRUE;
   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL pksc8_Check_PublicKeyInfoLMS(LMS_PUBLIC_KEY* sMlKemPublicKey, CK_CHAR_PTR data, CK_ULONG size)
*/
CK_BBOOL pksc8_Check_PublicKeyInfoLMS(LMS_PUBLIC_KEY* sMlKemPublicKey, CK_CHAR_PTR data, CK_ULONG size)
{

   do
   {
      // init settlv
      asn1_Check_SetTlv(data, size);

      // Check tag Sequence
      if (asn1_Check_tl(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag Sequence
      if (asn1_Check_t(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag OID
      if (asn1_Check_t(TAG_OID) == CK_FALSE)
      {
         break;
      }

      // Check OID is DSA public PKCS1
      if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_LMS_HSS_SIG, asn1_Check_GetCurrentTlvLen()) != 0)
      {
         break;
      }


      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      // Check tag bit string
      if (asn1_Check_Next(TAG_BITSTRING) == CK_FALSE)
      {
         break;
      }

      // get public key in uncompressed format
      sMlKemPublicKey->sPublicKey = asn1_Check_GetCurrentValueBuffer();
      sMlKemPublicKey->uPublicKeyLength = asn1_Check_GetCurrentValueLen();

      // Get LMS details from public key. 
      // subjectpublickey migth be reworked
      sMlKemPublicKey->uHSS_Levels = sMlKemPublicKey->sPublicKey[3];
      sMlKemPublicKey->uLmsType = sMlKemPublicKey->sPublicKey[7];
      sMlKemPublicKey->uLmotsType = sMlKemPublicKey->sPublicKey[11];

      // check no other tlv after
      if (asn1_Check_NoNextTlv() == CK_FALSE)
      {
         break;
      }

      // step out
      if (asn1_Check_StepOut() == CK_FALSE)
      {
         break;
      }

      return CK_TRUE;
   } while (FALSE);

   return CK_FALSE;

}

/*
    FUNCTION:        CK_BBOOL pkcs8_Check_EncryptedPrivateKeyInfoPbe(P11_PBE_ENC_PARAMS* sPbe, CK_CHAR_PTR data, CK_ULONG size)
*/
CK_BBOOL pkcs8_Check_EncryptedPrivateKeyInfoPbe(P11_PBE_ENC_PARAMS* sPbe, CK_CHAR_PTR data, CK_ULONG size)
{
   CK_LONG sResult = -1;
   do
   {
      // init settlv
      asn1_Check_SetTlv(data, size);

      // Check tag Sequence
      if (asn1_Check_tl(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag Sequence
      if (asn1_Check_t(TAG_SEQUENCE) == CK_FALSE)
      {
         break;
      }
      // Step in
      if (asn1_Check_StepIn() == CK_FALSE)
      {
         break;
      }
      // Check tag OID
      if (asn1_Check_t(TAG_OID) == CK_FALSE)
      {
         break;
      }

      // Check OID is DSA public PKCS1
      if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_PKCS5_PBES2, asn1_Check_GetCurrentTlvLen()) == 0)
      {

         // Check tag sequence
         if (asn1_Check_Next(TAG_SEQUENCE) == CK_FALSE)
         {
            break;
         }

         // Step in
         if (asn1_Check_StepIn() == CK_FALSE)
         {
            break;
         }

         // Check tag sequence
         if (asn1_Check_t(TAG_SEQUENCE) == CK_FALSE)
         {
            break;
         }

         // Step in
         if (asn1_Check_StepIn() == CK_FALSE)
         {
            break;
         }

         // Check tag OID
         if (asn1_Check_t(TAG_OID) == CK_FALSE)
         {
            break;
         }

         if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_PKCS5_PBKDF2, asn1_Check_GetCurrentTlvLen()) == 0)
         {
            sPbe->ckPbeMechType = CKM_PKCS5_PBKD2;


            // Check tag sequence
            if (asn1_Check_Next(TAG_SEQUENCE) == CK_FALSE)
            {
               break;
            }

            // Step in
            if (asn1_Check_StepIn() == CK_FALSE)
            {
               break;
            }

            // Check tag octect string
            if (asn1_Check_t(TAG_OCTECTSTRING) == CK_FALSE)
            {
               break;
            }

            sPbe->pbkdf2.pbfkd2_param.pSaltSourceData = asn1_Check_GetCurrentValueBuffer();
            sPbe->pbkdf2.pbfkd2_param.ulSaltSourceDataLen = asn1_Check_GetCurrentValueLen();
            sPbe->pbkdf2.pbfkd2_param.saltSource = CKZ_SALT_SPECIFIED;

            // Check tag integer
            if (asn1_Check_Next(TAG_INTEGER) == CK_FALSE)
            {
               break;
            }

            // get iterations value
            if (asn1_Check_GetCurrentValueLong(&sPbe->pbkdf2.pbfkd2_param.iterations) == CK_FALSE)
            {
               break;
            }


            // check no other tlv after
            if (asn1_Check_NoNextTlv() == CK_TRUE)
            {
               sPbe->pbkdf2.pbfkd2_param.prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
            }
            else
            {
               // Check tag NULL
               if (asn1_Check_Next(TAG_NULL) == CK_FALSE)
               {
                  break;
               }

               // Check tag OID
               if (asn1_Check_Next(TAG_OID) == CK_FALSE)
               {
                  break;
               }

               if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_HMAC_SHA224, asn1_Check_GetCurrentTlvLen()) == 0)
               {
                  sPbe->pbkdf2.pbfkd2_param.prf = CKP_PKCS5_PBKD2_HMAC_SHA224;
               }
               else if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_HMAC_SHA256, asn1_Check_GetCurrentTlvLen()) == 0)
               {
                  sPbe->pbkdf2.pbfkd2_param.prf = CKP_PKCS5_PBKD2_HMAC_SHA256;
               }
               else if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_HMAC_SHA384, asn1_Check_GetCurrentTlvLen()) == 0)
               {
                  sPbe->pbkdf2.pbfkd2_param.prf = CKP_PKCS5_PBKD2_HMAC_SHA384;
               }
               else if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_HMAC_SHA512, asn1_Check_GetCurrentTlvLen()) == 0)
               {
                  sPbe->pbkdf2.pbfkd2_param.prf = CKP_PKCS5_PBKD2_HMAC_SHA512;
               }

               // check no other tlv after
               if (asn1_Check_NoNextTlv() == CK_FALSE)
               {
                  break;
               }
            }

            // step out
            if (asn1_Check_StepOut() == CK_FALSE)
            {
               break;
            }

            // check no other tlv after
            if (asn1_Check_NoNextTlv() == CK_FALSE)
            {
               break;
            }

            // step out
            if (asn1_Check_StepOut() == CK_FALSE)
            {
               break;
            }

            // Check tag sequence
            if (asn1_Check_Next(TAG_SEQUENCE) == CK_FALSE)
            {
               break;
            }

            // Step in
            if (asn1_Check_StepIn() == CK_FALSE)
            {
               break;
            }

            // Check tag OID
            if (asn1_Check_t(TAG_OID) == CK_FALSE)
            {
               break;
            }

            // check OID
            if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_NIST_AES_128_CBC_PAD, asn1_Check_GetCurrentTlvLen()) == 0)
            {
               sPbe->sEnckeyType = CKK_AES;
               sPbe->sEncClass = CKO_SECRET_KEY;
               sPbe->ckEncMechType = CKM_AES_CBC_PAD;
               sPbe->sEnckeySize = AES_128_KEY_LENGTH;
            }
            else if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_NIST_AES_192_CBC_PAD, asn1_Check_GetCurrentTlvLen()) == 0)
            {
               sPbe->sEnckeyType = CKK_AES;
               sPbe->sEncClass = CKO_SECRET_KEY;
               sPbe->ckEncMechType = CKM_AES_CBC_PAD;
               sPbe->sEnckeySize = AES_192_KEY_LENGTH;
            }
            else if (memcmp(asn1_Check_GetCurrentTagBuffer(), OID_NIST_AES_256_CBC_PAD, asn1_Check_GetCurrentTlvLen()) == 0)
            {
               sPbe->sEnckeyType = CKK_AES;
               sPbe->sEncClass = CKO_SECRET_KEY;
               sPbe->ckEncMechType = CKM_AES_CBC_PAD;
               sPbe->sEnckeySize = AES_256_KEY_LENGTH;
            }
            else
            {
               break;
            }

            // Check tag octect string
            if (asn1_Check_Next(TAG_OCTECTSTRING) == CK_FALSE)
            {
               break;
            }

            sPbe->pIv = asn1_Check_GetCurrentValueBuffer();
            sPbe->ulIvLen = asn1_Check_GetCurrentValueLen();

            // check no other tlv after
            if (asn1_Check_NoNextTlv() == CK_FALSE)
            {
               break;
            }

            // step out
            if (asn1_Check_StepOut() == CK_FALSE)
            {
               break;
            }

            // check no other tlv after
            if (asn1_Check_NoNextTlv() == CK_FALSE)
            {
               break;
            }

            // step out
            if (asn1_Check_StepOut() == CK_FALSE)
            {
               break;
            }

            // check no other tlv after
            if (asn1_Check_NoNextTlv() == CK_FALSE)
            {
               break;
            }

            // step out
            if (asn1_Check_StepOut() == CK_FALSE)
            {
               break;
            }


            // Check tag octect string
            if (asn1_Check_Next(TAG_OCTECTSTRING) == CK_FALSE)
            {
               break;
            }

            sPbe->pWrappedKey = asn1_Check_GetCurrentValueBuffer();
            sPbe->ulWrappedKeyLen = asn1_Check_GetCurrentValueLen();

            // check no other tlv after
            if (asn1_Check_NoNextTlv() == CK_FALSE)
            {
               break;
            }

            // step out
            if (asn1_Check_StepOut() == CK_FALSE)
            {
               break;
            }

            // check no other tlv after
            if (asn1_Check_NoNextTlv() == CK_FALSE)
            {
               break;
            }

         }
         else
         {
            break;
         }

      }
      else
      {
         // not other oid supported
         break;
      }


      return CK_TRUE;
   } while (FALSE);

   return CK_FALSE;
}