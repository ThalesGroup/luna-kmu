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

#define _PKCS_11_C

#ifdef OS_WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "str.h"
#include "p11util.h"
#include "asn1.h"


#ifdef _WIN32
HINSTANCE   LibHandle = NULL;
#else
void* LibHandle = NULL;
#endif

const char p11_libvar[] = "ChrystokiConfigurationPath";
#ifdef _WIN32
#ifdef _KMU_DEBUG
const char p11_luna_library[] = "cklog201.dll";
#else
const char p11_luna_library[] = "cryptoki.dll";
#endif
const char p11_entension[] = ".dll";
#else
#ifdef _KMU_DEBUG
const char p11_luna_library[] = "libcklog2.so";
#else
const char p11_luna_library[] = "libCryptoki2_64.so";
#endif
const char p11_entension[] = ".so";
#endif

CK_SESSION_HANDLE hSession;

//CK_SLOT_ID  ckSlot;
CK_CHAR        LibPath[4096];

// Temp buffer 
#define MAX_COMPONENT_SIZE          1024 // max RSA 8k with ASN1 TLV
#define MAX_CERTIFICATE_SIZE        10240
#define TEMP_BUFFER_SIZE            (2*MAX_CERTIFICATE_SIZE)
#define TEMP_BUFFER_OFFSET_CMP_1    0
#define TEMP_BUFFER_OFFSET_CMP_2    TEMP_BUFFER_OFFSET_CMP_1 + MAX_COMPONENT_SIZE
#define TEMP_BUFFER_OFFSET_CMP_3    TEMP_BUFFER_OFFSET_CMP_2 + MAX_COMPONENT_SIZE
#define TEMP_BUFFER_OFFSET_CMP_4    TEMP_BUFFER_OFFSET_CMP_3 + MAX_COMPONENT_SIZE

#define TEMP_BUFFER_OFFSET_MODULUS  TEMP_BUFFER_OFFSET_CMP_1
#define TEMP_BUFFER_OFFSET_PUBEXP   TEMP_BUFFER_OFFSET_CMP_2

#define TEMP_BUFFER_OFFSET_PRIME    TEMP_BUFFER_OFFSET_CMP_1
#define TEMP_BUFFER_OFFSET_BASE     TEMP_BUFFER_OFFSET_CMP_2
#define TEMP_BUFFER_OFFSET_SUBPRIME TEMP_BUFFER_OFFSET_CMP_3
#define TEMP_BUFFER_OFFSET_PUBKEY   TEMP_BUFFER_OFFSET_CMP_4

#define TEMP_BUFFER_OFFSET_ECPUBKEY TEMP_BUFFER_OFFSET_CMP_1
#define TEMP_BUFFER_OFFSET_EC_OID   TEMP_BUFFER_OFFSET_CMP_2

#define TEMP_BUFFER_OFFSET_CERT_1    0
#define TEMP_BUFFER_OFFSET_CERT_2    MAX_CERTIFICATE_SIZE



CK_CHAR           pTempBuffer[TEMP_BUFFER_SIZE];

CK_SLOT_ID_PTR pSlotList = NULL;
CK_ULONG uSlotCount = 0;
CK_BBOOL bIsLoginPasswordRequired;

CK_FUNCTION_LIST* P11Functions;
CK_SFNT_CA_FUNCTION_LIST* SfntFunctions;


/*
    FUNCTION:        CK_BBOOL P11_GetLibrary()
*/
void P11_Init()
{
   P11Functions = NULL;
   SfntFunctions = NULL;
   LibHandle = NULL;
   hSession = 0;
   pSlotList = NULL;
   uSlotCount;
   bIsLoginPasswordRequired = CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_LoadLibrary()
*/
CK_BBOOL P11_LoadLibrary()
{
   do
   {
      P11Functions = NULL;
      SfntFunctions = NULL;
      LibHandle = NULL;
      hSession = 0;

      if (P11_LoadFunctions() == CK_FALSE)
      {
         printf("Failed to load PKCS11 library!\n");
         break;
      }

      if (P11_LoadSfntExtensionFunctions() == CK_FALSE)
      {
         printf("Failed to load SafeNet extension functions!\n");
         break;
      }

      return CK_TRUE;


   } while (FALSE);


   return CK_FALSE;
}

/*
    FUNCTION:        void P11_Terminate()
*/
void P11_Terminate()
{
#ifdef _KMU_DEBUG
   printf("DEBUG : before C_Logout\n");
#endif

   // CLose P11 session
   P11_Logout();

   // call C_Finalize
   if (P11Functions != NULL)
   {
      P11Functions->C_Finalize(NULL);
   }


#ifdef _KMU_DEBUG
   printf("DEBUG : before FreeLibrary\n");
   //printf("DEBUG : Handle %i\n", LibHandle);
#endif
   if (LibHandle != NULL)
   {
#ifdef _KMU_DEBUG
      printf("DEBUG : C_Finalize\n");
#endif


#ifdef OS_WIN32
      FreeLibrary(LibHandle);
#ifdef _KMU_DEBUG
      printf("DEBUG : FreeLibrary\n");
#endif

#else
      dlclose(LibHandle);
#endif
      LibHandle = NULL;
      P11Functions = NULL;
      SfntFunctions = NULL;
   }
}

/*
    FUNCTION:        CK_BBOOL P11_GetLibrary()
*/
CK_BBOOL P11_GetLibrary()
{
   CK_BBOOL myRC = CK_FALSE;
   CK_BBOOL bConcatenate = CK_TRUE;
   char* pPath = NULL;
   CK_ULONG    uLengh;

   // gen ChrystokiConfigurationPath path
   pPath = getenv(p11_libvar);

   if (pPath == NULL)
   {
      printf("Failed to get %s\n", p11_libvar);
      printf("Please specify an environment variable named \"%s\" that points to the full path of the pkcs11 library.\n", p11_libvar);
      
      printf("\t- if environment variable specifies a path, kmu appends \"%s\" to the environment variable (Thales luna HSM)\n", p11_luna_library);
      printf("\t- otherwise specify environment variable containing full path of pkcs11 library.(ie c:\\pkcs11tool\\pkcs11.dll) ");

      return CK_FALSE;
   }

   // copy string to LibPath
   memset(LibPath, 0, sizeof(LibPath));
   strcpy(LibPath, pPath);

   uLengh = (CK_ULONG)strlen(LibPath);

   do
   {

#ifdef OS_WIN32
      // check if the path in the env variable include "\" or not in the last character or contains ".dll" as last characters 
      if (uLengh != 0)
      {
         CK_ULONG    uLenghExtenson = (CK_ULONG)strlen(p11_entension);
         // check if last 4 bytes is .dll
         if (uLengh >= uLenghExtenson)
         {
            if (strcmp(&LibPath[uLengh - uLenghExtenson], p11_entension) == 0)
            {
               // if .dll, take the env variable as it is
               bConcatenate = CK_FALSE;
               break;
            }
            else
            {
               bConcatenate = CK_TRUE;
            }
         }

         // check if \ in last character
         uLengh--;
         if (LibPath[uLengh] != strBackSlashString[0])
         {
            // add "\"
            strcat(&LibPath[0], (CK_CHAR_PTR)strBackSlashString);
         }
      }
      else
      {
         // if path is empty, add "\"
         strcat(&LibPath[0], (CK_CHAR_PTR)strBackSlashString);
      }
#else
      // to do
#endif

   } while (FALSE);

   if (bConcatenate == CK_TRUE)
   {
      // concatenate path with dll
      pPath = strcat(LibPath, p11_luna_library);
   }

   myRC = CK_TRUE;

#ifdef _KMU_DEBUG
   printf("%s", pPath);
#endif

   return myRC;
}

/*
    FUNCTION:        CK_BBOOL P11_LoadFunctions()
*/
CK_BBOOL P11_LoadFunctions()
{
   CK_C_GetFunctionList C_GetFunctionList = NULL;
   CK_RV rv = CKR_TOKEN_NOT_PRESENT;

   do
   {
      if (P11_GetLibrary() == CK_FALSE)
         break;

#ifdef OS_WIN32


      LibHandle = LoadLibrary(LibPath);

#ifdef _KMU_DEBUG
      //printf("Handle %i\n", LibHandle);
#endif

      //  LibHandle = LoadLibrary(L"C:\\lunaclient\\cryptoki.dll");
      if (LibHandle)
      {
         C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(LibHandle, "C_GetFunctionList");
      }
      else
      {
         DWORD err = GetLastError();
         char buffer[256];
         memset(buffer, 0, sizeof(buffer));

         FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            err,
            0,
            buffer,
            sizeof(buffer) - 1,
            NULL
         );
         printf("LoadLibrary failed: Err: 0x%X, Str: %s\n", err, buffer);
         break;
      }
#else
      LibHandle = dlopen(LibPath, RTLD_NOW);
      if (LibHandle)
      {
         C_GetFunctionList = (CK_C_GetFunctionList)dlsym(LibHandle, "C_GetFunctionList");
      }
#endif

      if (!LibHandle)
      {
         printf("failed to load %s\n", LibPath);
      }

      if (C_GetFunctionList)
      {
         rv = C_GetFunctionList(&P11Functions);
      }

      if (P11Functions)
      {
         rv = P11Functions->C_Initialize(NULL_PTR);
      }

      if (rv == CKR_OK)
      {
         return CK_TRUE;
      }

   } while (FALSE);

   return CK_FALSE;
}


/*
    FUNCTION:        CK_BBOOL LoadSfntExtensionFunctions()
*/
CK_BBOOL P11_LoadSfntExtensionFunctions()
{
   CK_BBOOL myRC = CK_FALSE;
   CK_CA_GetFunctionList CA_GetFunctionList = NULL;
   CK_RV rv = CKR_TOKEN_NOT_PRESENT;
   int iErr = -1;

   do
   {

#ifdef OS_WIN32
      CA_GetFunctionList = (CK_CA_GetFunctionList)GetProcAddress(LibHandle, "CA_GetFunctionList");
#else
      CA_GetFunctionList = (CK_CA_GetFunctionList)dlsym(LibHandle, "CA_GetFunctionList");
#endif

      if (CA_GetFunctionList)
      {
         rv = CA_GetFunctionList(&SfntFunctions);
      }

      if (SfntFunctions)
      {
         return CK_TRUE;
      }
   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_SLOT_ID P11_ListStot()
*/
CK_LONG P11_ListStot()
{
   CK_RV retCode = CKR_OK;
   unsigned char bloop;
   CK_TOKEN_INFO sTokenInfo = { 0 };
   CK_SLOT_INFO sSlotInfo = { 0 };

   do
   {
      if (P11Functions == NULL)
      {
         break;
      }

      // Get slot list number
      retCode = P11Functions->C_GetSlotList(CK_TRUE, NULL, &uSlotCount);
      if (retCode != CKR_OK)
         break;

      if (uSlotCount == 0)
         break;

      // alloc buffer in memory of the size of the slot count
      pSlotList = (CK_SLOT_ID_PTR)calloc(uSlotCount, sizeof(CK_SLOT_ID));
      if (pSlotList == NULL)
         break;

      // get the slot list
      retCode = P11Functions->C_GetSlotList(CK_TRUE, pSlotList, &uSlotCount);
      if (retCode != CKR_OK)
         break;

      printf("Slot list : \n");

      CK_SLOT_ID_PTR pList = pSlotList;
      // Loop all token info slot
      for (bloop = 0; bloop < uSlotCount; bloop++)
      {

         // get token info on the slot
         retCode = P11Functions->C_GetTokenInfo(pList[0], &sTokenInfo);

         // truncate string
         str_TruncateString(sTokenInfo.label, sizeof(sTokenInfo.label));

         // prinft the slot number in decimal
         printf("[%d]", pList[0]);

         // add space depending of slot size value for allignement in the console
         if (pList[0] < 10)
         {
            printf("  ");
         }
         else if (pList[0] < 100)
         {
            printf(" ");
         }
         // print label value
         printf(": % s\n", sTokenInfo.label);

         pList++;
      }


   } while (FALSE);

   return uSlotCount;
}

/*
    FUNCTION:        CK_RV P11_SelectStot()
*/
CK_SLOT_ID P11_SelectStot(CK_SLOT_ID u32_SlotList)
{
   // CK_SLOT_ID pSlotList[10] = {0};
   CK_RV retCode = CKR_OK;
   unsigned char bloop;
   CK_TOKEN_INFO sTokenInfo = { 0 };
   CK_SLOT_INFO sSlotInfo = { 0 };
   CK_BBOOL bFound = CK_FALSE;
   CK_SLOT_ID u32_SlotID = CK_NULL_ELEMENT;
   /*
   CK_MECHANISM_TYPE_PTR pMechanismList;
   CK_MECHANISM_INFO info;
   */

   do
   {

      if(pSlotList == NULL)
      { 
         retCode = P11Functions->C_GetSlotList(CK_TRUE, NULL, &uSlotCount);
         if (retCode != CKR_OK)
            break;

         if (uSlotCount == 0)
            break;

         pSlotList = (CK_SLOT_ID_PTR)calloc(uSlotCount, sizeof(CK_SLOT_ID));
         if (pSlotList == NULL)
            break;

         retCode = P11Functions->C_GetSlotList(CK_TRUE, pSlotList, &uSlotCount);
         if (retCode != CKR_OK)
            break;

      }
      /*
      retCode = P11Functions->C_GetMechanismList(u32_SlotID, NULL_PTR, &uSlotCount);

      pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(uSlotCount * sizeof(CK_MECHANISM_TYPE));

      retCode = P11Functions->C_GetMechanismList(u32_SlotID, pMechanismList, &uSlotCount);
      
      retCode = P11Functions->C_GetMechanismInfo(u32_SlotID, CKM_SHA3_256, &info);
      */
      
      if (u32_SlotList == SLOT_MODE_LIST)
      {
         printf("Slot list : \n");
      }
      CK_SLOT_ID_PTR pList = pSlotList;
      // Loop all token info slot
      for (bloop = 0; bloop < uSlotCount; bloop++)
      {
         if (u32_SlotList == *pList)
         {
            // get token info
            retCode = P11Functions->C_GetTokenInfo(pList[0], &sTokenInfo);
            // struncate string
            str_TruncateString(sTokenInfo.label, sizeof(sTokenInfo.label));

            // check if the slot password is required
            if ((sTokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) == CKF_PROTECTED_AUTHENTICATION_PATH)
            {
               bIsLoginPasswordRequired = CK_FALSE;
            }
            else
            {
               bIsLoginPasswordRequired = CK_TRUE;
            }
            
            printf("Authentication with slot [%X] : %s ... ", pList[0], sTokenInfo.label);
            u32_SlotID = u32_SlotList;
            bFound = CK_TRUE;
            break;
         }

         pList++;
      }


   } while (FALSE);


   if (bFound == CK_FALSE)
   {
      printf("Slot not found : %i\n", u32_SlotList);
   }

   if (pSlotList)
   {
      free(pSlotList);
      pSlotList = NULL;
   }
   return u32_SlotID;
}

/*
    FUNCTION:        CK_BBOOL P11_IsLoginPasswordRequired(void)
*/
CK_BBOOL P11_IsLoginPasswordRequired(void)
{
   return bIsLoginPasswordRequired;
}

/*
    FUNCTION:        CK_RV P11_Login(CK_SLOT_ID ckSlot, CK_CHAR_PTR sPassword, CK_BBOOL bISCryptoUser)
*/
CK_RV P11_Login(CK_SLOT_ID ckSlot, CK_CHAR_PTR sPassword, CK_BBOOL bISCryptoUser)
{
   CK_RV rv = CKR_TOKEN_NOT_PRESENT;
   CK_USER_TYPE      userType;

   // check if login with crypto user or crypto officer
   if (bISCryptoUser == CK_TRUE)
   {
      userType = CKU_CRYPTO_USER;
   }
   else
   {
      userType = CKU_USER;
   }
   

   if (hSession != CK_INVALID_HANDLE)
   {
      printf("Already loggin to a slot. Please logout first\n");
      return CK_FALSE;
   }

   // Open P11 Session
   rv = P11Functions->C_OpenSession(ckSlot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);

   if (rv == CKR_OK)
   {

      if (sPassword == NULL)
      {
         rv = P11Functions->C_Login(hSession, userType, NULL, 0);
      }
      else
      {      
         // P11 Login
         rv = P11Functions->C_Login(hSession, userType, sPassword, (CK_ULONG)strlen((char*)sPassword));

      }

      if (rv != CKR_OK)
      {
         P11_Logout();
         printf("\nC_Login error code : %s \n", P11Util_DisplayErrorName(rv));
      }
      else
      {
         printf("Success");

         if (bISCryptoUser == CK_TRUE)
         {
            printf(" -> Connected as Crypto User");
         }
         else
         {
            printf(" -> Connected as Crypto Officer");
         }

         printf("\n\n");
      }
   }
   return rv;
}

/*
    FUNCTION:        CK_BBOOL P11_IsLoggedIn()
*/
CK_BBOOL P11_IsLoggedIn()
{
   // Check if handle is valid
   if (hSession == CK_INVALID_HANDLE)
   {
      // in case of invalid handle, return false
      return CK_FALSE;
   }
   // return true
   return CK_TRUE;
}

/*
    FUNCTION:        CK_RV P11_Logout()
*/
CK_RV P11_Logout()
{

   CK_RV rv = CKR_TOKEN_NOT_PRESENT;

   if (P11Functions != NULL)
   {
      // Logout
      rv = P11Functions->C_Logout(hSession);

      // Close session
      rv = P11Functions->C_CloseSession(hSession);

      // Clear handle
      hSession = CK_INVALID_HANDLE;
   }

   return rv;

}

/*
    FUNCTION:        CK_RV P11_FindAllObjects()
*/
CK_BBOOL P11_FindAllObjects()
{
   CK_ATTRIBUTE_PTR  pTemplate = NULL;
   CK_ULONG          usTemplateLen = 0;
   CK_RV             retCode = CKR_OK;
   CK_ULONG          usCount = 1;
   CK_ULONG          TotalObject = 0;
   CK_OBJECT_CLASS   ckclass = 0;
   CK_OBJECT_HANDLE  hAry[1] = { 0 };

   CK_ATTRIBUTE  sAttributeTemplate[] = {
      {CKA_CLASS, &ckclass, sizeof(CK_OBJECT_CLASS)},
      {CKA_LABEL, pTempBuffer, TEMP_BUFFER_SIZE},
   };

   // Search for all objects
   // TODO add filter on search
   retCode = P11Functions->C_FindObjectsInit(hSession, NULL, 0);

   // Loop while searching objects
   while ((retCode == CKR_OK) && (usCount == 1))
   {

      // get the list of objects
      retCode = P11Functions->C_FindObjects(hSession, hAry, 1, &usCount);

      // if error returned or not object returned, stop the loop
      if ((retCode != CKR_OK) || (usCount == 0))
      {
         break;
      }

      // increment TotalObject
      TotalObject++;

      // reinit template length
      pTempBuffer[0] = 0;
      sAttributeTemplate[0].usValueLen = sizeof(CK_OBJECT_CLASS);
      sAttributeTemplate[1].usValueLen = TEMP_BUFFER_SIZE;

      // Get object attribute (CLASS and Label)
      retCode = P11Functions->C_GetAttributeValue(hSession, hAry[0], &sAttributeTemplate[0], 2);

      if (retCode != CKR_OK)
      {
         break;
      }
      // print objects handle, class and label
      printf("handle=%u\t ", hAry[0]);
      printf("Class=%s\t", P11Util_DisplayClassName(ckclass));
      if (sAttributeTemplate[1].usValueLen < TEMP_BUFFER_SIZE)
      {
         pTempBuffer[sAttributeTemplate[1].usValueLen] = 0;
      }
      printf("Label=%s\n", pTempBuffer);

   }


   // in case of error, print the error
   if (retCode != CKR_OK)
   {
      printf("Search error : error code : %i\n", retCode);
      return CK_FALSE;
   }

   // print the number of objects found
   if (TotalObject != 0)
   {
      if (TotalObject == 1)
      {
         printf("\n %i object found\n", TotalObject);
      }
      else
      {
         printf("\n %i objects found\n", TotalObject);
      }

   }
   else
   {
      printf("\n no object found\n");
   }

   return CK_TRUE;
}


/*
    FUNCTION:        CK_OBJECT_CLASS   P11_GetObjectClass(CK_OBJECT_HANDLE Handle)
*/
CK_BBOOL   P11_DeleteObject(CK_OBJECT_HANDLE Handle)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;

   do
   {

      // Get object attribute (CLASS and Label)
      retCode = P11Functions->C_DestroyObject(hSession, Handle);

      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_DestroyObject error code : %s \n", P11Util_DisplayErrorName(retCode));
         //printf("Object with handle %i not found\n", Handle);
         break;
      }

      //printf("Object with handle %i deleted\n", Handle);
      // return true
      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_OBJECT_CLASS   P11_GetObjectClass(CK_OBJECT_HANDLE Handle)
*/
CK_OBJECT_CLASS   P11_GetObjectClass(CK_OBJECT_HANDLE Handle)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;
   CK_OBJECT_CLASS      sClass = 0;
   CK_ATTRIBUTE sAttributeGeneric[] = {
      {CKA_CLASS,             &sClass,             sizeof(CK_OBJECT_CLASS)},
   };

   do
   {

      // Get object attribute CLASS
      pTempBuffer[0] = 0;
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, sAttributeGeneric, DIM(sAttributeGeneric));

      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_GetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      // return class value
      return sClass;

   } while (FALSE);

   return CK_NULL_ELEMENT;
}

/*
    FUNCTION:        CK_KEY_TYPE P11_GetKeyType(CK_OBJECT_HANDLE Handle)
*/
CK_KEY_TYPE P11_GetKeyType(CK_OBJECT_HANDLE Handle)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;
   CK_KEY_TYPE          sKeyType = 0;
   CK_ATTRIBUTE sAttributeGeneric[] = {
      {CKA_KEY_TYPE,             &sKeyType,             sizeof(CK_KEY_TYPE)},
   };

   do
   {

      // Get object attribute key type
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, sAttributeGeneric, DIM(sAttributeGeneric));

      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_GetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      // return class value
      return sKeyType;

   } while (FALSE);

   return -1;
}


/*
    FUNCTION:        CK_BBOOL P11_FindObject(CK_OBJECT_HANDLE Handle)
*/
CK_BBOOL P11_FindObject(CK_OBJECT_HANDLE Handle)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;
   CK_OBJECT_CLASS      sClass = 0;
   CK_ATTRIBUTE sAttributeGeneric[] = {
      {CKA_CLASS,             &sClass,             sizeof(CK_OBJECT_CLASS)},
   };

   do
   {

      // call this function. Required if slot is HA, otherwise getattribute return error. 
      retCode = P11Functions->C_FindObjectsInit(hSession, NULL, 0);

      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_FindObjectsInit error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL P11_FindKeyObject(CK_OBJECT_HANDLE Handle)
*/
CK_BBOOL P11_FindKeyObject(CK_OBJECT_HANDLE Handle)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;
   CK_OBJECT_CLASS      sClass = 0;

   do
   {
      // find object
      if (P11_FindObject(Handle) != CK_TRUE)
      {
         break;
      }

      // Get object class
      sClass = P11_GetObjectClass(Handle);

      // check object is a key
      if((sClass == CKO_PUBLIC_KEY) || (sClass == CKO_PRIVATE_KEY) || (sClass == CKO_SECRET_KEY))
      {
         return CK_TRUE;
      }

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL P11_GetBooleanAttribute(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute)
*/
CK_BBOOL P11_GetBooleanAttribute(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;
   CK_BBOOL             bCKA_Attribute = CK_FALSE;
   CK_ATTRIBUTE sAttributeGeneric[] = {
      {cAttribute,             &bCKA_Attribute,             sizeof(CK_BBOOL)},
   };

   do
   {
      // Get object attribute (CLASS and Label)
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, sAttributeGeneric, DIM(sAttributeGeneric));

      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_GetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      return bCKA_Attribute;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_LONG P11_GetObjectSize(CK_OBJECT_HANDLE Handle)
*/
CK_LONG P11_GetObjectSize(CK_OBJECT_HANDLE Handle)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;
   CK_LONG              ObjectSize = 0;

   do
   {
      // Get object attribute (CLASS and Label)
      retCode = P11Functions->C_GetObjectSize(hSession, Handle, &ObjectSize);

      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_GetObjectSize error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      return ObjectSize;

   } while (FALSE);

   return 0;
}

/*
    FUNCTION:        CK_LONG P11_GetKeyLength(CK_OBJECT_HANDLE Handle)
*/
CK_LONG P11_GetKeyLength(CK_OBJECT_HANDLE Handle)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;
   CK_LONG              keySize = 0;
   CK_ATTRIBUTE sAttributeGeneric[] = {
      {CKA_VALUE_LEN,             &keySize,             sizeof(CK_OBJECT_CLASS)},
   };

   do
   {

      // Get object attribute key type
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, sAttributeGeneric, DIM(sAttributeGeneric));

      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_GetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      // return class value
      return keySize;

   } while (FALSE);

   return 0;
}

/*
    FUNCTION:        CK_BBOOL P11_GetDsaPublicKey(CK_OBJECT_HANDLE Handle, DSA_PUBLIC_KEY sRsaPublicKey)
*/
CK_BBOOL P11_GetDsaPublicKey(CK_OBJECT_HANDLE Handle,DSA_PUBLIC_KEY* dsapublickey)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;

   CK_ATTRIBUTE pubDSATemplate[] = {
   {CKA_PRIME,          &pTempBuffer[TEMP_BUFFER_OFFSET_PRIME],      MAX_COMPONENT_SIZE},
   {CKA_BASE,           &pTempBuffer[TEMP_BUFFER_OFFSET_BASE],       MAX_COMPONENT_SIZE},
   {CKA_VALUE,          &pTempBuffer[TEMP_BUFFER_OFFSET_PUBKEY],     MAX_COMPONENT_SIZE},
   {CKA_SUBPRIME,       &pTempBuffer[TEMP_BUFFER_OFFSET_SUBPRIME],   MAX_COMPONENT_SIZE},
   };

   do
   {
      /* get and display dsa domain key attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, pubDSATemplate, DIM(pubDSATemplate));

      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_GetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      // get base
      dsapublickey->sDomain.sBase = &pTempBuffer[TEMP_BUFFER_OFFSET_PRIME];
      dsapublickey->sDomain.uBaseLength = pubDSATemplate[1].usValueLen;

      // get prime
      dsapublickey->sDomain.sPrime = &pTempBuffer[TEMP_BUFFER_OFFSET_PRIME];
      dsapublickey->sDomain.uPrimeLength = pubDSATemplate[0].usValueLen;

      // get sub prime
      dsapublickey->sDomain.sSubPrime = &pTempBuffer[TEMP_BUFFER_OFFSET_SUBPRIME];
      dsapublickey->sDomain.uSubPrimeLength = pubDSATemplate[3].usValueLen;

      // get public key
      dsapublickey->sPublicKey = &pTempBuffer[TEMP_BUFFER_OFFSET_PUBKEY]; 
      dsapublickey->uPublicKeyLength = pubDSATemplate[2].usValueLen;

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL P11_GetDsaPublicKey(CK_KEY_TYPE skeyType, CK_OBJECT_HANDLE Handle, DH_PUBLIC_KEY dhpublickey)
*/
CK_BBOOL P11_GetDHPublicKey(CK_OBJECT_HANDLE Handle, DH_PUBLIC_KEY* dhpublickey, CK_KEY_TYPE skeyType)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;
   CK_LONG              uTemplateSize;

   CK_ATTRIBUTE pubDSATemplate[] = {
   {CKA_PRIME,          &pTempBuffer[TEMP_BUFFER_OFFSET_PRIME],      MAX_COMPONENT_SIZE},
   {CKA_BASE,           &pTempBuffer[TEMP_BUFFER_OFFSET_BASE],       MAX_COMPONENT_SIZE},
   {CKA_VALUE,          &pTempBuffer[TEMP_BUFFER_OFFSET_PUBKEY],     MAX_COMPONENT_SIZE},
   {CKA_SUBPRIME,       &pTempBuffer[TEMP_BUFFER_OFFSET_SUBPRIME],   MAX_COMPONENT_SIZE},
   };

   do
   {
      uTemplateSize = DIM(pubDSATemplate);

      // if key DH, don't request CKA_SUBPRIME
      if (skeyType == CKK_DH)
      {
         uTemplateSize--;
      }

      /* get dh domain key attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, pubDSATemplate, uTemplateSize);

      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_GetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      // get base
      dhpublickey->sDomain.sBase = &pTempBuffer[TEMP_BUFFER_OFFSET_BASE];
      dhpublickey->sDomain.uBaseLength = pubDSATemplate[1].usValueLen;

      // get prime
      dhpublickey->sDomain.sPrime = &pTempBuffer[TEMP_BUFFER_OFFSET_PRIME];
      dhpublickey->sDomain.uPrimeLength = pubDSATemplate[0].usValueLen;

      // get public key
      dhpublickey->sPublicKey = &pTempBuffer[TEMP_BUFFER_OFFSET_PUBKEY];
      dhpublickey->uPublicKeyLength = pubDSATemplate[2].usValueLen;
      
      // if key DH, get sub prime
      if (skeyType != CKK_DH)
      {
         dhpublickey->sDomain.sSubPrime = &pTempBuffer[TEMP_BUFFER_OFFSET_SUBPRIME];
         dhpublickey->sDomain.uSubPrimeLength = pubDSATemplate[3].usValueLen; 
      }
      else
      {
         dhpublickey->sDomain.sSubPrime = NULL;
         dhpublickey->sDomain.uSubPrimeLength = 0;
      }

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}


/*
    FUNCTION:        CK_BBOOL P11_GetRsaPublicKey(CK_OBJECT_HANDLE Handle, RSA_PUBLIC_KEY sRsaPublicKey)
*/
CK_BBOOL P11_GetRsaPublicKey(CK_OBJECT_HANDLE Handle, RSA_PUBLIC_KEY * rsapublickey)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;
   CK_ATTRIBUTE pubRsaTemplate[] = {
      {CKA_MODULUS,           &pTempBuffer[TEMP_BUFFER_OFFSET_MODULUS],       MAX_COMPONENT_SIZE},
      {CKA_PUBLIC_EXPONENT,   &pTempBuffer[TEMP_BUFFER_OFFSET_PUBEXP],        MAX_COMPONENT_SIZE},
   };

   do
   {
      // call this function. Required if slot is HA, otherwise getattribute return error. 
      retCode = P11Functions->C_FindObjectsInit(hSession, NULL, 0);

      // Get object attribute (modulus and public exponant)
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, pubRsaTemplate, DIM(pubRsaTemplate));
      
      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_GetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      // update rsapublickey
      rsapublickey->sModulus = &pTempBuffer[TEMP_BUFFER_OFFSET_MODULUS];
      rsapublickey->sExponent = &pTempBuffer[TEMP_BUFFER_OFFSET_PUBEXP];
      rsapublickey->uModulusLength = pubRsaTemplate[0].usValueLen;
      rsapublickey->uExponentLength = pubRsaTemplate[1].usValueLen;
      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL P11_GetEccPublicKey(CK_OBJECT_HANDLE Handle, EC_PUBLIC_KEY* eccpublickey)
*/
CK_BBOOL P11_GetEccPublicKey(CK_OBJECT_HANDLE Handle, EC_PUBLIC_KEY* eccpublickey, CK_KEY_TYPE ckTypeEc)
{
   CK_RV                retCode = CKR_SESSION_CLOSED;
   P11_EDDSA_OID_CONVERT* eddsa_oid_convert;
   CK_ATTRIBUTE pubEccTemplate[] = {
      {CKA_ECDSA_PARAMS,      &pTempBuffer[TEMP_BUFFER_OFFSET_EC_OID],        TEMP_BUFFER_SIZE},
      {CKA_EC_POINT,          &pTempBuffer[TEMP_BUFFER_OFFSET_ECPUBKEY],       TEMP_BUFFER_SIZE},
   };

   do
   {
      // call this function. Required if slot is HA, otherwise getattribute return error. 
      retCode = P11Functions->C_FindObjectsInit(hSession, NULL, 0);

      // Get object attribute (modulus and public exponant)
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, pubEccTemplate, DIM(pubEccTemplate));

      // check if error. 
      if (retCode != CKR_OK)
      {
         printf("C_GetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      switch (ckTypeEc)
      {
      case CKK_ECDSA:
      case CKK_SM2:
         // Push oid in eccpublickey
         eccpublickey->sOid = &pTempBuffer[TEMP_BUFFER_OFFSET_EC_OID];
         eccpublickey->uOidSize = pubEccTemplate[0].usValueLen;
         break;
      case CKK_EC_EDWARDS:
      case CKK_EC_EDWARDS_OLD:
      case CKK_EC_MONTGOMERY:
      case CKK_EC_MONTGOMERY_OLD:
         // Warning EDDSA : oid mismatch between hsm oid and standart oid in public key
         eddsa_oid_convert = P11Util_EddsaConvertOidToStd(&pTempBuffer[TEMP_BUFFER_OFFSET_EC_OID], pubEccTemplate[0].usValueLen);

         if (eddsa_oid_convert == NULL)
         {
            printf("P11_GetEccPublicKey : invalid OID");
            return CK_FALSE;
         }
         // Push oid in eccpublickey
         eccpublickey->sOid = eddsa_oid_convert->sOidStd;
         eccpublickey->uOidSize = eddsa_oid_convert->uOidStdLength;
      default:
         break;
      }

      // public point is encapuslated in tag 0x04, why ????
      // remove this TLV and get the key in uncompressed format
      asn1_Check_SetTlv(&pTempBuffer[TEMP_BUFFER_OFFSET_ECPUBKEY], pubEccTemplate[1].usValueLen);

      // Check tag Sequence
      if (asn1_Check_tl(0x04) == CK_FALSE)
      {
         break;
      }

      // Push public key in uncompressed format in eccpublickey
      eccpublickey->sPublicPoint = asn1_Check_GetCurrentValueBuffer();
      eccpublickey->uPublicPointLength = asn1_Check_GetCurrentValueLen();

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        void P11_DisplayCertificate(CK_KEY_TYPE  skeyType)
*/
void P11_DisplayCertificate(CK_OBJECT_HANDLE Handle)
{
   CK_RV                retCode = CKR_OK;
   CK_CERTIFICATE_TYPE  certType = 0;

   CK_ATTRIBUTE sAttributeGenericCertAttribute[] = {
   {CKA_CERTIFICATE_TYPE,  &certType,           sizeof(CK_CERTIFICATE_TYPE)},
   };

   /* get and display cert attributes */
   retCode = P11Functions->C_GetAttributeValue(hSession, Handle, sAttributeGenericCertAttribute, DIM(sAttributeGenericCertAttribute));

   if (certType == CKC_X_509)
   {
      CK_ATTRIBUTE CertObject[] = {
         {CKA_SUBJECT,              &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_1],     MAX_CERTIFICATE_SIZE},
         {CKA_ISSUER,               &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_2],     MAX_CERTIFICATE_SIZE},
      };

      /* get and display cert key attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, CertObject, DIM(CertObject));

      printf("CertificateType=X.509\n");
      str_DisplayByteArraytoString("Subject=", &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_1], CertObject[0].usValueLen);
      str_DisplayByteArraytoString("Issuer=", &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_2], CertObject[1].usValueLen);

      CertObject[0].type = CKA_SERIAL_NUMBER;
      CertObject[0].usValueLen = MAX_CERTIFICATE_SIZE;
      CertObject[1].type = CKA_ID;
      CertObject[1].usValueLen = MAX_CERTIFICATE_SIZE;

      /* get and display cert attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, CertObject, DIM(CertObject));

      str_DisplayByteArraytoString("SerialNumber=", &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_1], CertObject[0].usValueLen);
      str_DisplayByteArraytoString("Id=", &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_2], CertObject[1].usValueLen);

      CertObject[0].type = CKA_VALUE;
      CertObject[0].usValueLen = TEMP_BUFFER_SIZE;

      /* get and display cert attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, CertObject, 1);

      str_DisplayByteArraytoString("Value=", &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_1], CertObject[0].usValueLen);
   }
}

/*
    FUNCTION:        void P11_DisplayDataObject(CK_KEY_TYPE  skeyType)
*/
void P11_DisplayDataObject(CK_OBJECT_HANDLE Handle)
{
   CK_RV                retCode = CKR_OK;

   CK_ATTRIBUTE DataObject[] = {
   {CKA_APPLICATION,       &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_1],       MAX_CERTIFICATE_SIZE},
   {CKA_VALUE,             &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_2],       MAX_CERTIFICATE_SIZE},
   };

   /* get and display do attributes */
   retCode = P11Functions->C_GetAttributeValue(hSession, Handle, &DataObject[0], DIM(DataObject));

   // Set the end of string to the end of buffer
   if (DataObject[0].usValueLen >= MAX_CERTIFICATE_SIZE)
   {
      printf("Application= Cannot print value, size too big, you can use readattribute command instead\n");
   }
   else
   {
      pTempBuffer[DataObject[0].usValueLen] = 0;
      printf("Application=%s\n", pTempBuffer);
   }

   if (DataObject[1].usValueLen >= MAX_CERTIFICATE_SIZE)
   {
      printf("Value= Cannot print value, size too big, you can use readattribute command instead\n");
   }
   else
   {
      str_DisplayByteArraytoString("Value=", &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_2], DataObject[1].usValueLen);
   }

}

/*
    FUNCTION:        void P11_DisplaySecretKey(CK_KEY_TYPE  skeyType)
*/
void P11_DisplayProprietaryKeyAttribute(CK_OBJECT_HANDLE Handle, CK_OBJECT_CLASS sClass)
{
   CK_RV                retCode = CKR_OK;
   CK_KEY_STATUS        sKeyStatus = {0};
   CK_BBOOL             bCKA_CcmPrivate = CK_FALSE;
   CK_BBOOL             bCKA_Assigned = CK_FALSE;
   CK_ULONG             sKeyFlagCount = 0;
   CK_ULONG             sTemplateSize = 9;


#define TEMP_BUFFER_OFFSET_SHA1_FINGERPRINT        0
#define TEMP_BUFFER_OFFSET_SHA256_FINGERPRINT      (CK_ULONG)(TEMP_BUFFER_OFFSET_SHA1_FINGERPRINT + (CK_ULONG)100)
#define TEMP_BUFFER_OFFSET_OUID                    (CK_ULONG)(TEMP_BUFFER_OFFSET_SHA256_FINGERPRINT + (CK_ULONG)100)
#define TEMP_BUFFER_EKM_UID                        (CK_ULONG)(TEMP_BUFFER_OFFSET_OUID + (CK_ULONG)100)
#define TEMP_BUFFER_GENERIC1                       (CK_ULONG)(TEMP_BUFFER_EKM_UID + (CK_ULONG)100)
#define TEMP_BUFFER_GENERIC2                       (CK_ULONG)(TEMP_BUFFER_GENERIC1 + (CK_ULONG)100)
#define TEMP_BUFFER_GENERIC3                       (CK_ULONG)(TEMP_BUFFER_GENERIC2 + (CK_ULONG)100)

   CK_ATTRIBUTE LunaTemplate[] = {
      {CKA_CCM_PRIVATE,             &bCKA_CcmPrivate,       sizeof(CK_BBOOL)},
      {CKA_FINGERPRINT_SHA1,        &pTempBuffer[TEMP_BUFFER_OFFSET_SHA1_FINGERPRINT],       20},
      {CKA_FINGERPRINT_SHA256,      &pTempBuffer[TEMP_BUFFER_OFFSET_SHA256_FINGERPRINT],     32},
      {CKA_OUID,                    &pTempBuffer[TEMP_BUFFER_OFFSET_OUID],                   100},
      {CKA_EKM_UID,                 &pTempBuffer[TEMP_BUFFER_EKM_UID],                       100},
      {CKA_GENERIC_1,               &pTempBuffer[TEMP_BUFFER_GENERIC1],                      100},
      {CKA_GENERIC_2,               &pTempBuffer[TEMP_BUFFER_GENERIC2],                      100},
      {CKA_GENERIC_3,               &pTempBuffer[TEMP_BUFFER_GENERIC3],                      100},
      {CKA_KEY_STATUS,              &sKeyStatus,                                             sizeof(CK_KEY_STATUS)},
      // to exclude for public key
      {CKA_ASSIGNED,                &bCKA_Assigned,                                          sizeof(CK_BBOOL)},
      {CKA_FAILED_KEY_AUTH_COUNT,   &sKeyFlagCount,                                          sizeof(CK_ULONG)},
   };

   // exclude for public key the 2 last attributes in the array
   if (sClass != CKO_PUBLIC_KEY)
   {
      sTemplateSize = DIM(LunaTemplate);
   }

   /* get attributes */
   retCode = P11Functions->C_GetAttributeValue(hSession, Handle, LunaTemplate, sTemplateSize);

   printf("\nProprietary Attributes :\n");

   printf("ccm_private=%s\n", P11Util_DisplayBooleanName(bCKA_CcmPrivate));
   if (sClass != CKO_PUBLIC_KEY)
   {
      printf("Assigned=%s\n", P11Util_DisplayBooleanName(bCKA_Assigned));
   }
   // display attributes
   str_DisplayByteArraytoString("Sha1FingerPrint=", &pTempBuffer[TEMP_BUFFER_OFFSET_SHA1_FINGERPRINT], LunaTemplate[1].usValueLen);
   str_DisplayByteArraytoString("Sha256FingerPrint=", &pTempBuffer[TEMP_BUFFER_OFFSET_SHA256_FINGERPRINT], LunaTemplate[2].usValueLen);
   str_DisplayByteArraytoString("ouid=", &pTempBuffer[TEMP_BUFFER_OFFSET_OUID], LunaTemplate[3].usValueLen);
   str_DisplayByteArraytoString("ekm_uid=", &pTempBuffer[TEMP_BUFFER_EKM_UID], LunaTemplate[4].usValueLen);
   str_DisplayByteArraytoString("generic1=", &pTempBuffer[TEMP_BUFFER_GENERIC1], LunaTemplate[5].usValueLen);
   str_DisplayByteArraytoString("generic2=", &pTempBuffer[TEMP_BUFFER_GENERIC2], LunaTemplate[6].usValueLen);
   str_DisplayByteArraytoString("generic3=", &pTempBuffer[TEMP_BUFFER_GENERIC3], LunaTemplate[7].usValueLen);

   printf("KeyStatus\n\tFlag=%02X\n\tKeyStatus Failed Key Authorization Limit=%i\n", sKeyStatus.flags, sKeyStatus.failedAuthCountLimit);

   if (sClass != CKO_PUBLIC_KEY)
   {
      printf("FailedKeyAuthCount=%04X\n", sKeyFlagCount);
   }
}
/*
    FUNCTION:        void P11_DisplaySecretKey(CK_KEY_TYPE  skeyType)
*/
void P11_DisplaySecretKey(CK_OBJECT_HANDLE Handle, CK_KEY_TYPE  skeyType)
{
   CK_RV                retCode = CKR_OK;
   CK_LONG              skeySize = 0;
   CK_BBOOL             bCKA_Sensitive = CK_FALSE;
   CK_BBOOL             bCKA_AlwaysSensitive = CK_FALSE;
   CK_BBOOL             bCKA_Encrypt = CK_FALSE;
   CK_BBOOL             bCKA_Decrypt = CK_FALSE;
   CK_BBOOL             bCKA_Sign = CK_FALSE;
   CK_BBOOL             bCKA_Verify = CK_FALSE;
   CK_BBOOL             bCKA_Derive = CK_FALSE;
   CK_BBOOL             bCKA_Wrap = CK_FALSE;
   CK_BBOOL             bCKA_Unwrap = CK_FALSE;
   CK_BBOOL             bCKA_Extractable = CK_FALSE;
   CK_BBOOL             bCKA_NeverExtractable = CK_FALSE;

   CK_ATTRIBUTE SymTemplate[] = {
   {CKA_ENCRYPT,           &bCKA_Encrypt,          sizeof(CK_BBOOL)},
   {CKA_SENSITIVE,         &bCKA_Sensitive,        sizeof(CK_BBOOL)},
   {CKA_ALWAYS_SENSITIVE,  &bCKA_AlwaysSensitive,  sizeof(CK_BBOOL)},
   {CKA_DECRYPT,           &bCKA_Decrypt,          sizeof(CK_BBOOL)},
   {CKA_SIGN,              &bCKA_Sign,             sizeof(CK_BBOOL)},
   {CKA_VERIFY,            &bCKA_Verify,           sizeof(CK_BBOOL)},
   {CKA_WRAP,              &bCKA_Wrap,             sizeof(CK_BBOOL)},
   {CKA_UNWRAP,            &bCKA_Unwrap,           sizeof(CK_BBOOL)},
   {CKA_DERIVE,            &bCKA_Derive,           sizeof(CK_BBOOL)},
   {CKA_EXTRACTABLE,       &bCKA_Extractable,      sizeof(CK_BBOOL)},
   {CKA_NEVER_EXTRACTABLE, &bCKA_NeverExtractable, sizeof(CK_BBOOL)},
   {CKA_VALUE_LEN,         &skeySize,              sizeof(CK_LONG) },
   {CKA_CHECK_VALUE,       &pTempBuffer[0],        TEMP_BUFFER_SIZE},
   };

   /* get and display RSA public key attributes */
   retCode = P11Functions->C_GetAttributeValue(hSession, Handle, SymTemplate, DIM(SymTemplate));

   printf("Sensitive=%s\n", P11Util_DisplayBooleanName(bCKA_Sensitive));
   printf("AlwaysSensitive=%s\n", P11Util_DisplayBooleanName(bCKA_AlwaysSensitive));
   printf("Extractable=%s\n", P11Util_DisplayBooleanName(bCKA_Extractable));
   printf("NeverExtractable=%s\n", P11Util_DisplayBooleanName(bCKA_NeverExtractable));
   printf("Encrypt=%s\n", P11Util_DisplayBooleanName(bCKA_Encrypt));
   printf("Decrypt=%s\n", P11Util_DisplayBooleanName(bCKA_Decrypt));
   printf("Sign=%s\n", P11Util_DisplayBooleanName(bCKA_Sign));
   printf("Verify=%s\n", P11Util_DisplayBooleanName(bCKA_Verify));
   printf("Derive=%s\n", P11Util_DisplayBooleanName(bCKA_Derive));
   printf("Wrap=%s\n", P11Util_DisplayBooleanName(bCKA_Wrap));
   printf("Unwrap=%s\n", P11Util_DisplayBooleanName(bCKA_Unwrap));
   printf("KeyLength=%i\n", skeySize);
   str_DisplayByteArraytoString("KeyCheckValue=", pTempBuffer, SymTemplate[12].usValueLen);

   // display proprietary key attributes
   P11_DisplayProprietaryKeyAttribute(Handle, CKO_SECRET_KEY);
}

/*
    FUNCTION:        void P11_DisplayPrivateKey(CK_KEY_TYPE  skeyType)
*/
void P11_DisplayPrivateKey(CK_OBJECT_HANDLE Handle, CK_KEY_TYPE  skeyType)
{
   CK_RV                retCode = CKR_OK;
   CK_LONG              skeySize = 0;
   CK_BBOOL             bCKA_Sensitive = CK_FALSE;
   CK_BBOOL             bCKA_AlwaysSensitive = CK_FALSE;
   CK_BBOOL             bCKA_Decrypt = CK_FALSE;
   CK_BBOOL             bCKA_Sign = CK_FALSE;
   CK_BBOOL             bCKA_Unwrap = CK_FALSE;
   CK_BBOOL             bCKA_Extractable = CK_FALSE;
   CK_BBOOL             bCKA_NeverExtractable = CK_FALSE;

   CK_ATTRIBUTE privTemplate[] = {
   {CKA_SENSITIVE,         &bCKA_Sensitive,        sizeof(CK_BBOOL)},
   {CKA_ALWAYS_SENSITIVE,  &bCKA_AlwaysSensitive,  sizeof(CK_BBOOL)},
   {CKA_SIGN,              &bCKA_Sign,             sizeof(CK_BBOOL)},
   {CKA_EXTRACTABLE,       &bCKA_Extractable,      sizeof(CK_BBOOL)},
   {CKA_NEVER_EXTRACTABLE, &bCKA_NeverExtractable, sizeof(CK_BBOOL)},
   {CKA_DECRYPT,           &bCKA_Decrypt,          sizeof(CK_BBOOL)},
   {CKA_UNWRAP,            &bCKA_Unwrap,           sizeof(CK_BBOOL)},
   };
   /* get and display private public key attributes */
   retCode = P11Functions->C_GetAttributeValue(hSession, Handle, privTemplate, DIM(privTemplate));
   printf("Sensitive=%s\n", P11Util_DisplayBooleanName(bCKA_Sensitive));
   printf("AlwaysSensitive=%s\n", P11Util_DisplayBooleanName(bCKA_AlwaysSensitive));
   printf("Extractable=%s\n", P11Util_DisplayBooleanName(bCKA_Extractable));
   printf("NeverExtractable=%s\n", P11Util_DisplayBooleanName(bCKA_NeverExtractable));
   printf("Sign=%s\n", P11Util_DisplayBooleanName(bCKA_Sign));
   printf("Decrypt=%s\n", P11Util_DisplayBooleanName(bCKA_Decrypt));
   printf("Unwrap=%s\n", P11Util_DisplayBooleanName(bCKA_Unwrap));

   switch (skeyType)
   {
      // ecc keys
   case CKK_ECDSA:
   case CKK_SM2:
   case CKK_EC_EDWARDS:
   case CKK_EC_EDWARDS_OLD:
   case CKK_EC_MONTGOMERY:
   case CKK_EC_MONTGOMERY_OLD:
   {
      // if ecdsa private
      CK_ATTRIBUTE pubEcdsaTemplate[] = {
         {CKA_ECDSA_PARAMS,      &pTempBuffer[TEMP_BUFFER_OFFSET_EC_OID],        MAX_COMPONENT_SIZE},
         {CKA_EC_POINT,          &pTempBuffer[TEMP_BUFFER_OFFSET_ECPUBKEY],      MAX_COMPONENT_SIZE},
      };

      /* get and display ECDSA public key attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, pubEcdsaTemplate, DIM(pubEcdsaTemplate));
      str_DisplayByteArraytoString("CurveOID=", &pTempBuffer[TEMP_BUFFER_OFFSET_EC_OID], pubEcdsaTemplate[0].usValueLen);
      P11Util_DisplayOIDName(&pTempBuffer[TEMP_BUFFER_OFFSET_EC_OID], (CK_BYTE)pubEcdsaTemplate[0].usValueLen);
      str_DisplayByteArraytoString("PublicPoint=", &pTempBuffer[TEMP_BUFFER_OFFSET_ECPUBKEY], pubEcdsaTemplate[1].usValueLen);
      break;
   }
   case CKK_RSA:
      // if rsa private
   {
      CK_ATTRIBUTE privRsaTemplate[] = {
         {CKA_MODULUS,           &pTempBuffer[TEMP_BUFFER_OFFSET_MODULUS],    MAX_COMPONENT_SIZE},
         {CKA_PUBLIC_EXPONENT,   &pTempBuffer[TEMP_BUFFER_OFFSET_PUBEXP],     MAX_COMPONENT_SIZE},
         {CKA_MODULUS_BITS,      &skeySize,           sizeof(CK_LONG)},
      };

      /* get and display RSA public key attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, privRsaTemplate, DIM(privRsaTemplate));
      printf("ModulusSize=%i\n", skeySize);
      str_DisplayByteArraytoString("Modulus=", &pTempBuffer[TEMP_BUFFER_OFFSET_MODULUS], privRsaTemplate[0].usValueLen);
      str_DisplayByteArraytoString("PublicExpnonant=", &pTempBuffer[TEMP_BUFFER_OFFSET_PUBEXP], privRsaTemplate[1].usValueLen);
      break;
   }
   // if dh private
   case CKK_DH:
   case CKK_X9_42_DH:
   case CKK_DSA:
   {
      CK_ATTRIBUTE pubDHTemplate[] = {
         {CKA_PRIME,          &pTempBuffer[TEMP_BUFFER_OFFSET_PRIME],      MAX_COMPONENT_SIZE},
         {CKA_BASE,           &pTempBuffer[TEMP_BUFFER_OFFSET_BASE],       MAX_COMPONENT_SIZE},
         {CKA_SUBPRIME,       &pTempBuffer[TEMP_BUFFER_OFFSET_SUBPRIME],   MAX_COMPONENT_SIZE},
      };

      /* get and display dh domain key attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, pubDHTemplate, 2);

      // if x9 42 key, get the sub prime
      if ((skeyType == CKK_X9_42_DH) || (skeyType == CKK_DSA))
      {
         // get and display the subprime
         retCode = P11Functions->C_GetAttributeValue(hSession, Handle, &pubDHTemplate[2], 1);
      }
      printf("KeySize=%i\n", pubDHTemplate[0].usValueLen << 3);
      str_DisplayByteArraytoString("Prime=", &pTempBuffer[TEMP_BUFFER_OFFSET_PRIME], pubDHTemplate[0].usValueLen);
      printf("\n");
      str_DisplayByteArraytoString("Base=", &pTempBuffer[TEMP_BUFFER_OFFSET_BASE], pubDHTemplate[1].usValueLen);
      printf("\n");
      if ((skeyType == CKK_X9_42_DH) || (skeyType == CKK_DSA))
      {
         str_DisplayByteArraytoString("SubPrime=", &pTempBuffer[TEMP_BUFFER_OFFSET_SUBPRIME], pubDHTemplate[2].usValueLen);
      }

      break;
   default:
      break;
   }
   }
   // display proprietary key attributes
   P11_DisplayProprietaryKeyAttribute(Handle, CKO_PRIVATE_KEY);
}

/*
    FUNCTION:        void P11_DisplayPublicKey(CK_KEY_TYPE  skeyType)
*/
void P11_DisplayPublicKey(CK_OBJECT_HANDLE Handle, CK_KEY_TYPE  skeyType)
{
   CK_RV                retCode = CKR_OK;
   CK_LONG              skeySize = 0;
   CK_BBOOL             bCKA_Encrypt = CK_FALSE;
   CK_BBOOL             bCKA_Verify = CK_FALSE;
   CK_BBOOL             bCKA_Wrap = CK_FALSE;

   CK_ATTRIBUTE pubTemplate[] = {
   {CKA_VERIFY,            &bCKA_Verify,        sizeof(CK_BBOOL)},
   {CKA_ENCRYPT,           &bCKA_Encrypt,       sizeof(CK_BBOOL)},
   {CKA_WRAP,              &bCKA_Wrap,          sizeof(CK_BBOOL)},
   };

   /* get and display generic public key attributes */
   retCode = P11Functions->C_GetAttributeValue(hSession, Handle, pubTemplate, DIM(pubTemplate));
   printf("Verify=%s\n", P11Util_DisplayBooleanName(bCKA_Verify));
   printf("Encrypt=%s\n", P11Util_DisplayBooleanName(bCKA_Encrypt));
   printf("Wrap=%s\n", P11Util_DisplayBooleanName(bCKA_Wrap));

   switch (skeyType)
   {
      // ecc keys
   case CKK_ECDSA:
   case CKK_SM2:
   case CKK_EC_EDWARDS:
   case CKK_EC_EDWARDS_OLD:
   case CKK_EC_MONTGOMERY:
   case CKK_EC_MONTGOMERY_OLD:
   {
      // if ecdsa public
      CK_ATTRIBUTE pubEcdsaTemplate[] = {
         {CKA_ECDSA_PARAMS,      &pTempBuffer[TEMP_BUFFER_OFFSET_EC_OID],        MAX_COMPONENT_SIZE},
         {CKA_EC_POINT,          &pTempBuffer[TEMP_BUFFER_OFFSET_ECPUBKEY],      MAX_COMPONENT_SIZE},
      };

      /* get and display ECDSA public key attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, pubEcdsaTemplate, DIM(pubEcdsaTemplate));
      str_DisplayByteArraytoString("CurveOID=", &pTempBuffer[TEMP_BUFFER_OFFSET_EC_OID], pubEcdsaTemplate[0].usValueLen);
      P11Util_DisplayOIDName(&pTempBuffer[TEMP_BUFFER_OFFSET_EC_OID], (CK_BYTE)pubEcdsaTemplate[0].usValueLen);
      str_DisplayByteArraytoString("PublicPoint=", &pTempBuffer[TEMP_BUFFER_OFFSET_ECPUBKEY], pubEcdsaTemplate[1].usValueLen);
      break;

   }
      // if rsa public
   case CKK_RSA:
   {
      CK_ATTRIBUTE pubRsaTemplate[] = {
         {CKA_MODULUS,           &pTempBuffer[TEMP_BUFFER_OFFSET_MODULUS],    MAX_COMPONENT_SIZE},
         {CKA_PUBLIC_EXPONENT,   &pTempBuffer[TEMP_BUFFER_OFFSET_PUBEXP],     MAX_COMPONENT_SIZE},
         {CKA_MODULUS_BITS,      &skeySize,           sizeof(CK_LONG)},
      };

      /* get and display RSA public key attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, pubRsaTemplate, DIM(pubRsaTemplate));
      printf("ModulusSize=%i\n", skeySize);
      str_DisplayByteArraytoString("Modulus=", &pTempBuffer[TEMP_BUFFER_OFFSET_MODULUS], pubRsaTemplate[0].usValueLen);
      str_DisplayByteArraytoString("PublicExpnonant=", &pTempBuffer[TEMP_BUFFER_OFFSET_PUBEXP], pubRsaTemplate[1].usValueLen);
      break;
   }
   // if dh public
   case CKK_DH:
   case CKK_X9_42_DH:
   case CKK_DSA:
   {
      CK_ATTRIBUTE pubDHTemplate[] = {
         {CKA_PRIME,          &pTempBuffer[TEMP_BUFFER_OFFSET_PRIME],      MAX_COMPONENT_SIZE},
         {CKA_BASE,           &pTempBuffer[TEMP_BUFFER_OFFSET_BASE],       MAX_COMPONENT_SIZE},
         {CKA_VALUE,          &pTempBuffer[TEMP_BUFFER_OFFSET_PUBKEY],     MAX_COMPONENT_SIZE},
         {CKA_SUBPRIME,       &pTempBuffer[TEMP_BUFFER_OFFSET_SUBPRIME],   MAX_COMPONENT_SIZE},
      };

      /* get and display dh domain key attributes */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, pubDHTemplate, 3);

      // if x9 42 key, get the sub prime
      if ((skeyType == CKK_X9_42_DH) || (skeyType == CKK_DSA))
      {
         // get and display the subprime
         retCode = P11Functions->C_GetAttributeValue(hSession, Handle, &pubDHTemplate[3], 1);
      }
      printf("KeySize=%i\n", pubDHTemplate[0].usValueLen << 3);
      str_DisplayByteArraytoString("Prime=", &pTempBuffer[TEMP_BUFFER_OFFSET_PRIME], pubDHTemplate[0].usValueLen);
      printf("\n");
      str_DisplayByteArraytoString("Base=", &pTempBuffer[TEMP_BUFFER_OFFSET_BASE], pubDHTemplate[1].usValueLen);
      printf("\n");
      if ((skeyType == CKK_X9_42_DH) || (skeyType == CKK_DSA))
      {
         str_DisplayByteArraytoString("SubPrime=", &pTempBuffer[TEMP_BUFFER_OFFSET_SUBPRIME], pubDHTemplate[3].usValueLen);
         printf("\n");
      }
      str_DisplayByteArraytoString("PublicKey=", &pTempBuffer[TEMP_BUFFER_OFFSET_PUBKEY], pubDHTemplate[2].usValueLen);
      break;
   }
   default:
      break;
   }

   // display proprietary key attributes
   P11_DisplayProprietaryKeyAttribute(Handle, CKO_PUBLIC_KEY);
}

/*
    FUNCTION:        CK_RV P11_GetAttributes(CK_OBJECT_HANDLE Handle)
*/
CK_BBOOL P11_GetAttributes(CK_OBJECT_HANDLE Handle)
{

   CK_RV                retCode = CKR_OK;
   CK_OBJECT_CLASS      sClass = 0;
   CK_KEY_TYPE          skeyType = 0;
   CK_LONG              skeySize = 0;
   CK_LONG              sObjectSize = 0;
   CK_BBOOL             bCKA_Token = CK_FALSE;
   CK_BBOOL             bCKA_Private = CK_FALSE;
   CK_BBOOL             bCKA_Sensitive = CK_FALSE;
   CK_BBOOL             bCKA_AlwaysSensitive = CK_FALSE;
   CK_BBOOL             bCKA_Local = CK_FALSE;
   CK_BBOOL             bCKA_Derive = CK_FALSE;
   CK_BBOOL             bCKA_Modifiable = CK_FALSE;
   CK_DATE              StartDate = { 0 };
   CK_DATE              EndDate = { 0 };

   CK_ATTRIBUTE sAttributeGeneric[] = {
   {CKA_CLASS,             &sClass,             sizeof(CK_OBJECT_CLASS)},
   {CKA_TOKEN,             &bCKA_Token,         sizeof(CK_BBOOL)},
   {CKA_PRIVATE,           &bCKA_Private,       sizeof(CK_BBOOL)},
   {CKA_MODIFIABLE,        &bCKA_Modifiable,    sizeof(CK_BBOOL)},
   {CKA_LABEL,             &pTempBuffer,        TEMP_BUFFER_SIZE}
   };

   do
   {
      // call this function. Required if slot is HA, otherwise getattribute return error. 
      retCode = P11Functions->C_FindObjectsInit(hSession, NULL, 0);

      // Get object attribute (CLASS and Label)
      pTempBuffer[0] = 0;
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, sAttributeGeneric, DIM(sAttributeGeneric));
      // in case of error, print the error

      if (retCode != CKR_OK)
      {

         // TODO : common function to get error
         if (retCode == CKR_OBJECT_HANDLE_INVALID)
         {
            printf("Object not found : CKR_OBJECT_HANDLE_INVALID \n");
         }
         else
         {
            printf("C_GetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));
         }
         break;
      }

      printf("\nThe list of attributes for handle %i are :\n\n", Handle);
      printf("Class=%s\n", P11Util_DisplayClassName(sClass));
      printf("Token=%s\n", P11Util_DisplayBooleanName(bCKA_Token));
      printf("Private=%s\n", P11Util_DisplayBooleanName(bCKA_Private));
      printf("Modifiable=%s\n", P11Util_DisplayBooleanName(bCKA_Modifiable));
      
      // Set the end of string to the end of buffer
      pTempBuffer[sAttributeGeneric[4].usValueLen] = 0;
      printf("Label=%s\n", pTempBuffer);

      // get and display object size
      sObjectSize = P11_GetObjectSize(Handle);
      printf("ObjectSize=%i bytes\n", sObjectSize);

      switch (sClass)
      {
      case CKO_PUBLIC_KEY:
      case CKO_PRIVATE_KEY:
      case CKO_SECRET_KEY:
      {
         CK_ATTRIBUTE sAttributeGenericKey[] = {
            {CKA_KEY_TYPE,          &skeyType,                                sizeof(CK_KEY_TYPE)},
            {CKA_START_DATE,        &StartDate,                               sizeof(CK_DATE)},
            {CKA_END_DATE,          &EndDate,                                 sizeof(CK_DATE)},
            {CKA_DERIVE,            &bCKA_Derive,                             sizeof(CK_BBOOL)},
            {CKA_LOCAL,             &bCKA_Local,                              sizeof(CK_BBOOL)},
            {CKA_ID,                &pTempBuffer[TEMP_BUFFER_OFFSET_CERT_1],  MAX_CERTIFICATE_SIZE},
         };

         /* get and display generic key attributes */
         pTempBuffer[0] = 0;
         retCode = P11Functions->C_GetAttributeValue(hSession, Handle, sAttributeGenericKey, DIM(sAttributeGenericKey));
         printf("KeyType=%s (0x%08X)\n", P11Util_DisplayKeyTypeName(skeyType), skeyType);

         // check if buffer too big
         if (sAttributeGenericKey[5].usValueLen >= MAX_CERTIFICATE_SIZE)
         {
            printf("id= Cannot print value, size too big, you can use readattribute command instead\n");
         }
         else
         {
            str_DisplayByteArraytoString("id=", pTempBuffer, sAttributeGenericKey[5].usValueLen);
         }
         P11Util_DisplayDate("StartDate=", &StartDate, sAttributeGenericKey[1].usValueLen);
         P11Util_DisplayDate("EndDate=", &EndDate, sAttributeGenericKey[2].usValueLen);
         printf("Local=%s\n", P11Util_DisplayBooleanName(bCKA_Local));
         printf("Derive=%s\n", P11Util_DisplayBooleanName(bCKA_Derive));

         // if public key
         if (sClass == CKO_PUBLIC_KEY)
         {
            P11_DisplayPublicKey(Handle, skeyType);
         }
         // if private key
         else if (sClass == CKO_PRIVATE_KEY)
         {
            P11_DisplayPrivateKey(Handle, skeyType);
         }
         // if secret key
         else if (sClass == CKO_SECRET_KEY)
         {
            P11_DisplaySecretKey(Handle, skeyType);
         }
         break;
      }
      // data object
      case CKO_DATA:
         P11_DisplayDataObject(Handle);
         break;
      // certificate object
      case CKO_CERTIFICATE:
         P11_DisplayCertificate(Handle);
         break;
      default:
         break;
      }

   } while (FALSE);

   return CK_FALSE;
}


/*
    FUNCTION:        CK_BBOOL P11_GetAttributesArray(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute, CK_CHAR_PTR * pArray, CK_ULONG_PTR pArrayLength)
*/
CK_BBOOL P11_GetAttributesArray(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute, CK_CHAR_PTR * pArray, CK_ULONG_PTR pArrayLength)
{
   CK_RV                retCode = CKR_GENERAL_ERROR;
   CK_ULONG             uExpectedAttrSize = 0;
   CK_ATTRIBUTE sAttribute[] = {
         {cAttribute,  NULL, 0},
   };

   do
   {
      /* get attributes size */
      retCode = P11Functions->C_GetAttributeValue(hSession, Handle, &sAttribute[0], 1);

      if (retCode == CKR_OK)
      {
         // get attribute size
         uExpectedAttrSize = sAttribute[0].usValueLen;

         // Allocate Buffer of the size of data
         *pArray = malloc(uExpectedAttrSize);

         // check if allocation is ok
         if (*pArray == NULL)
         {
            break;
         }

         sAttribute[0].pValue = *pArray;

         retCode = P11Functions->C_GetAttributeValue(hSession, Handle, &sAttribute[0], 1);

         if (retCode == CKR_OK)
         {
            // set the output size
            *pArrayLength = uExpectedAttrSize;
            return CK_TRUE;
         }

         // free memory
         free(*pArray);
      }

   } while (FALSE);

   printf("C_GetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL P11_SetAttributeBoolean(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute, CK_BBOOL bValue)
*/
CK_BBOOL P11_SetAttributeBoolean(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute, CK_BBOOL bValue)
{
   CK_RV                retCode = CKR_OK;
   CK_ATTRIBUTE sAttribute[] = {
         {cAttribute,  &bValue, sizeof(CK_BBOOL)},
   };

   do
   {
      // Set attribute value
      retCode = P11Functions->C_SetAttributeValue(hSession, Handle, sAttribute, 1);

      if (retCode == CKR_OK)
      {
         return CK_TRUE;
      }
       printf("C_SetAttributeValue error code : %s \n", P11Util_DisplayErrorName(retCode));

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL P11_SetAttributeArray(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE ctype)
*/
CK_BBOOL P11_SetAttributeArray(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute, CK_CHAR_PTR sStringValue, CK_ULONG uStringLength)
{
   CK_RV                retCode = CKR_OK;
   CK_ATTRIBUTE sAttribute[] = {
         {cAttribute,  &sStringValue[0], uStringLength},
   };

   do
   {
      if (sStringValue == NULL)
      {
         break;
      }

      printf("Updating attribute %s ... ", P11Util_DisplayAttributeName(cAttribute));

      // Set attribute value
      retCode = P11Functions->C_SetAttributeValue(hSession, Handle, sAttribute, 1);

      if (retCode == CKR_OK)
      {
         // display attribute updated
         printf("Success.\n");
         return CK_TRUE;
      }

      printf("Error \nC_SetAttributeValue Error code : %s \n", P11Util_DisplayErrorName(retCode));

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL P11_SetAttributeString(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE ctype)
*/
CK_BBOOL P11_SetAttributeString(CK_OBJECT_HANDLE Handle, CK_ATTRIBUTE_TYPE cAttribute, CK_CHAR_PTR sStringValue)
{
   CK_ULONG uLength = 0;
   CK_RV                retCode = CKR_OK;

   if (sStringValue != NULL)
   {
      uLength = (CK_ULONG)strlen(sStringValue);
   }
   CK_ATTRIBUTE sAttribute[] = {
         {cAttribute,  &sStringValue[0], uLength},
   };

   do
   {
      printf("Updating attribute %s ... ", P11Util_DisplayAttributeName(cAttribute));

      // Set attribute value
      retCode = P11Functions->C_SetAttributeValue(hSession, Handle, sAttribute, 1);

      if (retCode == CKR_OK)
      {
         printf("Success. Value = %s\n", sStringValue);
         return CK_TRUE;
      }

      printf("Error \nC_SetAttributeValue Error code : %s \n", P11Util_DisplayErrorName(retCode));

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL P11_GenerateKey(P11_KEYGENTEMPLATE* sKeyTemplate, CK_OBJECT_HANDLE_PTR hKey, CK_BBOOL bDisplay)
*/
CK_BBOOL P11_GenerateKey(P11_KEYGENTEMPLATE* sKeyGenTemplate, CK_OBJECT_HANDLE_PTR hKey, CK_BBOOL bDisplay)
{
   CK_ULONG          u32labelsize = 0;
   CK_RV             retCode = CKR_GENERAL_ERROR;
   CK_OBJECT_HANDLE  hSymKey = 0;
   CK_MECHANISM      sKeygenMech = { 0 };
   CK_LONG           sSimTemplateSize = 16;

   if (sKeyGenTemplate->pKeyLabel != NULL)
   {
      u32labelsize = (CK_ULONG)strlen(sKeyGenTemplate->pKeyLabel);
   }

   // init with common attribute for all symetric keys
   CK_ATTRIBUTE SymKeyTemplate[17] = {
   {CKA_CLASS,             &sKeyGenTemplate->sClass,           sizeof(CK_OBJECT_CLASS)},
   {CKA_KEY_TYPE,          &sKeyGenTemplate->skeyType,         sizeof(CK_KEY_TYPE)},
   {CKA_TOKEN,             &sKeyGenTemplate->bCKA_Token,       sizeof(CK_BBOOL)},
   {CKA_SENSITIVE,         &sKeyGenTemplate->bCKA_Sensitive,   sizeof(CK_BBOOL)},
   {CKA_PRIVATE,           &sKeyGenTemplate->bCKA_Private,     sizeof(CK_BBOOL)},
   {CKA_SIGN,              &sKeyGenTemplate->bCKA_Sign,        sizeof(CK_BBOOL)},
   {CKA_VERIFY,            &sKeyGenTemplate->bCKA_Verify,      sizeof(CK_BBOOL)},
   {CKA_ENCRYPT,           &sKeyGenTemplate->bCKA_Encrypt,     sizeof(CK_BBOOL)},
   {CKA_DECRYPT,           &sKeyGenTemplate->bCKA_Decrypt,     sizeof(CK_BBOOL)},
   {CKA_WRAP,              &sKeyGenTemplate->bCKA_Wrap,        sizeof(CK_BBOOL)},
   {CKA_UNWRAP,            &sKeyGenTemplate->bCKA_Unwrap,      sizeof(CK_BBOOL)},
   {CKA_DERIVE,            &sKeyGenTemplate->bCKA_Derive,      sizeof(CK_BBOOL)},
   {CKA_EXTRACTABLE,       &sKeyGenTemplate->bCKA_Extractable, sizeof(CK_BBOOL)},
   {CKA_MODIFIABLE,        &sKeyGenTemplate->bCKA_Modifiable,  sizeof(CK_BBOOL)},
   {CKA_VALUE_LEN,         &sKeyGenTemplate->skeySize,         sizeof(CK_LONG) },
   {CKA_LABEL,             sKeyGenTemplate->pKeyLabel,         (CK_ULONG)u32labelsize},
   };

   // Check if CKA id is given in parameter
   if (sKeyGenTemplate->pCKA_ID != NULL)
   {
      // push CKA id in PubTemplate
      SymKeyTemplate[sSimTemplateSize].type = CKA_ID;
      SymKeyTemplate[sSimTemplateSize].pValue = sKeyGenTemplate->pCKA_ID;
      SymKeyTemplate[sSimTemplateSize].usValueLen = sKeyGenTemplate->uCKA_ID_Length;
      sSimTemplateSize++;
   }

   switch (sKeyGenTemplate->skeyType)
   {
   case CKK_AES:
      if ((sKeyGenTemplate->skeySize == AES_128_KEY_LENGTH) || (sKeyGenTemplate->skeySize == AES_192_KEY_LENGTH) || (sKeyGenTemplate->skeySize == AES_256_KEY_LENGTH))
      {
         // Build AES genkey mechanism
         sKeygenMech.mechanism = CKM_AES_KEY_GEN;
         break;
      }
      printf("Key size for AES must be 16, 24 or 32 bytes \n");
      return CK_FALSE;
   case CKK_DES:
      if (sKeyGenTemplate->skeySize == DES_KEY_LENGTH)
      {
         // Build DES genkey mechanism
         sKeygenMech.mechanism = CKM_DES_KEY_GEN;
         sKeyGenTemplate->skeyType = CKK_DES;
         break;
      }
      else if (sKeyGenTemplate->skeySize == DES2_KEY_LENGTH)
      {
         // Build DES genkey mechanism
         sKeygenMech.mechanism = CKM_DES2_KEY_GEN;
         sKeyGenTemplate->skeyType = CKK_DES2;
         break;
      }
      else if (sKeyGenTemplate->skeySize == DES3_KEY_LENGTH)
      {
         // Build DES genkey mechanism
         sKeygenMech.mechanism = CKM_DES3_KEY_GEN;
         sKeyGenTemplate->skeyType = CKK_DES3;
         break;
      }
      printf("Key size for DES must be 8, 16 or 24 bytes \n");
      return CK_FALSE;
   case CKK_GENERIC_SECRET:
      if ((sKeyGenTemplate->skeySize >= GENERIC_KEY_MINIMUM_LENGTH) || (sKeyGenTemplate->skeySize <= GENERIC_KEY__MAXIMUM_LENGTH))
      {
         // Build generic genkey mechanism
         sKeygenMech.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
         break;
      }
      printf("Key size for generic key must be between 1 to 512 bytes\n");
      return CK_FALSE;
   case CKK_SM4:
      // Build SM4 genkey mechanism
      sKeygenMech.mechanism = CKM_SM4_KEY_GEN;
      break;

   default:
      printf("Invalid key gen request \n");
      return CK_FALSE;
   }

   // generate key
   retCode = P11Functions->C_GenerateKey(hSession,
      &sKeygenMech,
      SymKeyTemplate,
      sSimTemplateSize,
      &hSymKey);

   if (retCode == CKR_OK)
   {
      if (bDisplay == TRUE)
      {
         printf("Key successfully generated, handle is : %i, label is : %s \n", hSymKey, sKeyGenTemplate->pKeyLabel);
      }

      // if the handle pointer is not null, return the key handle value
      if (hKey != NULL)
      {
         *hKey = hSymKey;
      }

      return CK_TRUE;
   }

   printf("C_GenerateKey error code : %s \n", P11Util_DisplayErrorName(retCode));
   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL P11_GenerateKeyPbkdf2(P11_KEYGENTEMPLATE* sKeyTemplate, CK_PKCS5_PBKD2_ENC_PARAMS2_PTR pbkdf2_param, CK_BBOOL bDisplay)
*/
CK_BBOOL P11_GenerateKeyPbkdf2(P11_KEYGENTEMPLATE* sKeyGenTemplate, CK_OBJECT_HANDLE_PTR hKey, CK_PKCS5_PBKD2_ENC_PARAMS2_PTR pbkdf2_param, CK_BBOOL bDisplay)
{
   CK_ULONG          u32labelsize = 0;
   CK_RV             retCode = CKR_GENERAL_ERROR;
   CK_OBJECT_HANDLE  hSymKey = 0;
   CK_MECHANISM      sKeygenMech = { 0 };
   CK_LONG           sSimTemplateSize = 16;

   if (sKeyGenTemplate->pKeyLabel != NULL)
   {
      u32labelsize = (CK_ULONG)strlen(sKeyGenTemplate->pKeyLabel);
   }

   // init with common attribute for all symetric keys
   CK_ATTRIBUTE SymKeyTemplate[17] = {
   {CKA_CLASS,             &sKeyGenTemplate->sClass,           sizeof(CK_OBJECT_CLASS)},
   {CKA_KEY_TYPE,          &sKeyGenTemplate->skeyType,         sizeof(CK_KEY_TYPE)},
   {CKA_TOKEN,             &sKeyGenTemplate->bCKA_Token,       sizeof(CK_BBOOL)},
   {CKA_SENSITIVE,         &sKeyGenTemplate->bCKA_Sensitive,   sizeof(CK_BBOOL)},
   {CKA_PRIVATE,           &sKeyGenTemplate->bCKA_Private,     sizeof(CK_BBOOL)},
   {CKA_SIGN,              &sKeyGenTemplate->bCKA_Sign,        sizeof(CK_BBOOL)},
   {CKA_VERIFY,            &sKeyGenTemplate->bCKA_Verify,      sizeof(CK_BBOOL)},
   {CKA_ENCRYPT,           &sKeyGenTemplate->bCKA_Encrypt,     sizeof(CK_BBOOL)},
   {CKA_DECRYPT,           &sKeyGenTemplate->bCKA_Decrypt,     sizeof(CK_BBOOL)},
   {CKA_WRAP,              &sKeyGenTemplate->bCKA_Wrap,        sizeof(CK_BBOOL)},
   {CKA_UNWRAP,            &sKeyGenTemplate->bCKA_Unwrap,      sizeof(CK_BBOOL)},
   {CKA_DERIVE,            &sKeyGenTemplate->bCKA_Derive,      sizeof(CK_BBOOL)},
   {CKA_EXTRACTABLE,       &sKeyGenTemplate->bCKA_Extractable, sizeof(CK_BBOOL)},
   {CKA_MODIFIABLE,        &sKeyGenTemplate->bCKA_Modifiable,  sizeof(CK_BBOOL)},
   {CKA_VALUE_LEN,         &sKeyGenTemplate->skeySize,         sizeof(CK_LONG) },
   {CKA_LABEL,             sKeyGenTemplate->pKeyLabel,         (CK_ULONG)u32labelsize},
   };

   // Check if CKA id is given in parameter
   if (sKeyGenTemplate->pCKA_ID != NULL)
   {
      // push CKA id in PubTemplate
      SymKeyTemplate[sSimTemplateSize].type = CKA_ID;
      SymKeyTemplate[sSimTemplateSize].pValue = sKeyGenTemplate->pCKA_ID;
      SymKeyTemplate[sSimTemplateSize].usValueLen = sKeyGenTemplate->uCKA_ID_Length;
      sSimTemplateSize++;
   }

   sKeygenMech.mechanism = CKM_PKCS5_PBKD2;
   sKeygenMech.pParameter = (CK_ATTRIBUTE_PTR)&pbkdf2_param->pbfkd2_param;
   sKeygenMech.usParameterLen = sizeof(pbkdf2_param->pbfkd2_param);

   
   // generate key
   retCode = P11Functions->C_GenerateKey(hSession,
      &sKeygenMech,
      SymKeyTemplate,
      sSimTemplateSize,
      &hSymKey);

   if (retCode == CKR_OK)
   {
      if (bDisplay == TRUE)
      {
         printf("Key successfully generated, handle is : %i, label is : %s \n", hSymKey, sKeyGenTemplate->pKeyLabel);
      }

      // if the handle pointer is not null, return the key handle value
      if (hKey != NULL)
      {
         *hKey = hSymKey;
      }

      return CK_TRUE;
   }


   printf("P11_GenerateKeyPbe error code : %s \n", P11Util_DisplayErrorName(retCode));
   return CK_FALSE;
}

/*
    FUNCTION:        CK_OBJECT_HANDLE P11_GenerateAESWrapKey(CK_BBOOL bTokenKey, CK_LONG skeySize, CK_CHAR_PTR pLabel)
*/
CK_OBJECT_HANDLE P11_ImportClearSymetricKey(P11_UNWRAPTEMPLATE* sKeyTemplate, CK_CHAR_PTR pbClearKey, CK_ULONG lKeyLength)
{
   CK_KEY_TYPE             cKeyType;
   CK_OBJECT_CLASS         cKeyClass;
   P11_ENCRYPT_TEMPLATE    sEncryptionTemplate = { 0 };
   P11_UNWRAPTEMPLATE      sUnWrapTemplate = { 0 };
   P11_ENCRYPTION_MECH     sEncryptionMech = { 0 };
   CK_CHAR_PTR             sWrapKey = NULL;
   CK_ULONG                sWrapKeyLength = 0;
   CK_OBJECT_HANDLE        hKey = 0;
   CK_OBJECT_HANDLE        hWrapKey = sKeyTemplate->hWrappingKey;

   do
   {

      cKeyType = P11_GetKeyType(hWrapKey);
      cKeyClass = P11_GetObjectClass(hWrapKey);

      // only import with AES wrap key is supported
      if (cKeyType != CKK_AES)
      {
         break;
      }

      // use tr31 wrapping key
      sEncryptionTemplate.hEncyptiontKey = hWrapKey;
      sEncryptionTemplate.sClass = cKeyClass;
      sEncryptionTemplate.skeyType = cKeyType;
      sEncryptionTemplate.sInputData = pbClearKey;
      sEncryptionTemplate.sInputDataLength = lKeyLength;
      sEncryptionMech.ckMechType = CKM_AES_KWP;
      sEncryptionTemplate.encryption_mech = &sEncryptionMech;
      if (P11_EncryptData(&sEncryptionTemplate, &sWrapKey, &sWrapKeyLength) == CK_FALSE)
      {
         break;
      }
      // clear the key buffer
      memset(pbClearKey, 0, lKeyLength);

      // import key in the HSM as session key
      sKeyTemplate->wrapmech = &sEncryptionMech;

      // import wrapped derived key
      if (P11_UnwrapPrivateSecretKey(sKeyTemplate, sWrapKey, sWrapKeyLength, &hKey) == CK_FALSE)
      {
         break;
      }

      // release the buffer
      free(sWrapKey);
   } while (FALSE);

   sKeyTemplate->wrapmech = NULL;

   return hKey;
}

/*
    FUNCTION:        CK_OBJECT_HANDLE P11_GenerateAESWrapKey(CK_BBOOL bTokenKey, CK_LONG skeySize, CK_CHAR_PTR pLabel)
*/
CK_OBJECT_HANDLE P11_GenerateAESWrapKey(CK_BBOOL bTokenKey, CK_LONG skeySize, CK_CHAR_PTR pLabel)
{
   P11_KEYGENTEMPLATE sKeyGenTemplateWrapKey = { 0 };
   CK_OBJECT_HANDLE  hWrapKey = 0;

   // generate a AES 256 session wrap key (use to encrypt clear key value)
   sKeyGenTemplateWrapKey.bCKA_Token = bTokenKey;
   sKeyGenTemplateWrapKey.bCKA_Sensitive = CK_TRUE;
   sKeyGenTemplateWrapKey.bCKA_Private = CK_TRUE;
   sKeyGenTemplateWrapKey.bCKA_Encrypt = CK_TRUE;
   sKeyGenTemplateWrapKey.bCKA_Decrypt = CK_TRUE;
   sKeyGenTemplateWrapKey.bCKA_Wrap = CK_TRUE;
   sKeyGenTemplateWrapKey.bCKA_Unwrap = CK_TRUE;
   sKeyGenTemplateWrapKey.sClass = CKO_SECRET_KEY;
   sKeyGenTemplateWrapKey.skeyType = CKK_AES;
   sKeyGenTemplateWrapKey.skeySize = skeySize;
   sKeyGenTemplateWrapKey.pKeyLabel = pLabel;

   P11_GenerateKey(&sKeyGenTemplateWrapKey, &hWrapKey, CK_FALSE);

   return hWrapKey;

}


/*
    FUNCTION:        CK_BBOOL P11_GenerateKeyPair(P11_KEYGENTEMPLATE * sKeyTemplate)
*/
CK_BBOOL P11_GenerateKeyPair(P11_KEYGENTEMPLATE* sKeyGenTemplate)
{
   CK_RV             retCode = CKR_DEVICE_ERROR;
   CK_OBJECT_HANDLE  hPrivateKey = 0;
   CK_OBJECT_HANDLE  hPublicKey = 0;
   CK_MECHANISM      sKeygenMech = { 0 };
   CK_BBOOL          bWrapEncrypt = CK_FALSE;
   CK_BBOOL          bSignVerify = CK_FALSE;
   CK_LONG PubTemplateSize = 7;     // Size until CKA_LABEL. Do not inlude encrypt and wrap. Do not work for some ecc based key
   CK_LONG PriTemplateSize = 9;    // Size until CKA_LABEL. Do not inlude decrypt and unwrap. Do not work for ecc based key

   // init with common attribute for all public key keys
   CK_ATTRIBUTE PubTemplate[20] = {
      {CKA_CLASS,             &sKeyGenTemplate->sClassPublic,     sizeof(CK_OBJECT_CLASS)},
      {CKA_KEY_TYPE,          &sKeyGenTemplate->skeyType,         sizeof(CK_KEY_TYPE)},
      {CKA_TOKEN,             &sKeyGenTemplate->bCKA_Token,       sizeof(CK_BBOOL)},
      {CKA_PRIVATE,           &sKeyGenTemplate->bCKA_Private,     sizeof(CK_BBOOL)},
      {CKA_DERIVE,            &sKeyGenTemplate->bCKA_Derive,      sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE,        &sKeyGenTemplate->bCKA_Modifiable,  sizeof(CK_BBOOL)},
      {CKA_LABEL,             sKeyGenTemplate->pKeyLabelPublic,   (CK_ULONG)strlen(sKeyGenTemplate->pKeyLabelPublic)},
   };

   // init with common attribute for all private key keys
   CK_ATTRIBUTE PriTemplate[20] = {
      {CKA_CLASS,             &sKeyGenTemplate->sClass,           sizeof(CK_OBJECT_CLASS)},
      {CKA_KEY_TYPE,          &sKeyGenTemplate->skeyType,         sizeof(CK_KEY_TYPE)},
      {CKA_TOKEN,             &sKeyGenTemplate->bCKA_Token,       sizeof(CK_BBOOL)},
      {CKA_SENSITIVE,         &sKeyGenTemplate->bCKA_Sensitive,   sizeof(CK_BBOOL)},
      {CKA_PRIVATE,           &sKeyGenTemplate->bCKA_Private,     sizeof(CK_BBOOL)},
      {CKA_DERIVE,            &sKeyGenTemplate->bCKA_Derive,      sizeof(CK_BBOOL)},
      {CKA_EXTRACTABLE,       &sKeyGenTemplate->bCKA_Extractable, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE,        &sKeyGenTemplate->bCKA_Modifiable,  sizeof(CK_BBOOL)},
      {CKA_LABEL,             sKeyGenTemplate->pKeyLabelPrivate,  (CK_ULONG)strlen(sKeyGenTemplate->pKeyLabelPrivate)},
   };

   // Check if CKA id is given in parameter
   if (sKeyGenTemplate->pCKA_ID != NULL)
   {
      // push CKA id in PubTemplate
      PubTemplate[PubTemplateSize].type = CKA_ID;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pCKA_ID;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->uCKA_ID_Length;
      PubTemplateSize++;

      // push CKA id in PriTemplate
      PriTemplate[PriTemplateSize].type = CKA_ID;
      PriTemplate[PriTemplateSize].pValue = sKeyGenTemplate->pCKA_ID;
      PriTemplate[PriTemplateSize].usValueLen = sKeyGenTemplate->uCKA_ID_Length;
      PriTemplateSize++;
   }

   switch (sKeyGenTemplate->skeyType)
   {
   case CKK_DH:

      // Set prime
      PubTemplate[PubTemplateSize].type = CKA_PRIME;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pDHDomain->sPrime;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pDHDomain->uPrimeLength;
      PubTemplateSize++;

      // Set base
      PubTemplate[PubTemplateSize].type = CKA_BASE;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pDHDomain->sBase;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pDHDomain->uBaseLength;
      PubTemplateSize++;

      // set DH mecansim
      sKeygenMech.mechanism = sKeyGenTemplate->sKeyGenMech;

      if (sKeyGenTemplate->sKeyGenMech == CKM_X9_42_DH_KEY_PAIR_GEN)
      {
         // Set subprime
         PubTemplate[PubTemplateSize].type = CKA_SUBPRIME;
         PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pDHDomain->sSubPrime;
         PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pDHDomain->uSubPrimeLength;
         PubTemplateSize++;

         sKeyGenTemplate->skeyType = CKK_X9_42_DH;

      }
      break;
   case CKK_DSA:

      bSignVerify = CK_TRUE;

      // set ECDSA mecansim
      sKeygenMech.mechanism = CKM_DSA_KEY_PAIR_GEN;

      // Set prime
      PubTemplate[PubTemplateSize].type = CKA_PRIME;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pDSADomain->sPrime;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pDSADomain->uPrimeLength;
      PubTemplateSize++;

      // Set base
      PubTemplate[PubTemplateSize].type = CKA_BASE;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pDSADomain->sBase;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pDSADomain->uBaseLength;
      PubTemplateSize++;

      // Set sub prime
      PubTemplate[PubTemplateSize].type = CKA_SUBPRIME;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pDSADomain->sSubPrime;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pDSADomain->uSubPrimeLength;
      PubTemplateSize++;
      break;

   case CKK_RSA:
   {
      bWrapEncrypt = CK_TRUE;
      bSignVerify = CK_TRUE;
      // Set modulus length in bit
      PubTemplate[PubTemplateSize].type = CKA_MODULUS_BITS;
      PubTemplate[PubTemplateSize].pValue = &sKeyGenTemplate->skeySize;
      PubTemplate[PubTemplateSize].usValueLen = sizeof(CK_LONG);
      PubTemplateSize++;

      // Set public exponant
      PubTemplate[PubTemplateSize].type = CKA_PUBLIC_EXPONENT;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pKeyPublicExp->exp;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pKeyPublicExp->expLen;
      PubTemplateSize++;

      // set RSA mecansim
      sKeygenMech.mechanism = sKeyGenTemplate->sKeyGenMech;
      break;
   }
   case CKK_EC_EDWARDS:
   case CKK_EC_EDWARDS_OLD:
      bSignVerify = CK_TRUE;
      sKeygenMech.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;

      // check if selected curve is compatible with ECDSA
      if (sKeyGenTemplate->pECCurveOID->cktype != CKK_EC_EDWARDS)
      {
         printf("curve not compatible with EDDSA : %s", sKeyGenTemplate->pECCurveOID->sCurveName);
         return CK_FALSE;
      }

      // Set eddsa params
      PubTemplate[PubTemplateSize].type = CKA_EC_PARAMS;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pECCurveOID->oid;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pECCurveOID->oidLen;
      PubTemplateSize++;
      break;
   case CKK_SM2:
      bSignVerify = CK_TRUE;
      sKeygenMech.mechanism = CKM_SM2_KEY_PAIR_GEN;

      // check if selected curve is compatible with ECDSA
      if (sKeyGenTemplate->pECCurveOID->cktype != CKK_SM2)
      {
         printf("curve not compatible with SM2 : %s", sKeyGenTemplate->pECCurveOID->sCurveName);
         return CK_FALSE;
      }

      // Set SM2 params
      PubTemplate[PubTemplateSize].type = CKA_EC_PARAMS;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pECCurveOID->oid;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pECCurveOID->oidLen;
      PubTemplateSize++;
      break;

   case CKK_EC_MONTGOMERY:
   case CKK_EC_MONTGOMERY_OLD:
      sKeygenMech.mechanism = CKM_EC_MONTGOMERY_KEY_PAIR_GEN;

      // check if selected curve is compatible with ECDSA
      if (sKeyGenTemplate->pECCurveOID->cktype != CKK_EC_MONTGOMERY)
      {
         printf("curve not compatible with Montgomery : %s", sKeyGenTemplate->pECCurveOID->sCurveName);
         return CK_FALSE;
      }

      // Set eddsa params
      PubTemplate[PubTemplateSize].type = CKA_EC_PARAMS;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pECCurveOID->oid;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pECCurveOID->oidLen;
      PubTemplateSize++;
      break;
   case CKK_ECDSA :
   {
      bWrapEncrypt = CK_TRUE;
      bSignVerify = CK_TRUE;
      // set ECDSA mecansim
      sKeygenMech.mechanism = CKM_EC_KEY_PAIR_GEN;

      // check if selected curve is compatible with ECDSA
      if (sKeyGenTemplate->pECCurveOID->cktype != CKK_ECDSA)
      {
         printf("curve not compatible with ECDSA : %s", sKeyGenTemplate->pECCurveOID->sCurveName);
         return CK_FALSE;
      }
      // Set ecdsa params
      PubTemplate[PubTemplateSize].type = CKA_EC_PARAMS;
      PubTemplate[PubTemplateSize].pValue = sKeyGenTemplate->pECCurveOID->oid;
      PubTemplate[PubTemplateSize].usValueLen = sKeyGenTemplate->pECCurveOID->oidLen;
      PubTemplateSize++;
      break;
   }

   default:
      printf("C_GenerateKey : invalid keytype : %i", sKeyGenTemplate->skeyType);
      return CK_FALSE;
   }

      // Check if key has encrypt or wrap capability
   if (bSignVerify == CK_TRUE)
   {
      // include CKA_VERIFY for public key
      PubTemplate[PubTemplateSize].type = CKA_VERIFY;
      PubTemplate[PubTemplateSize].pValue = &sKeyGenTemplate->bCKA_Verify;
      PubTemplate[PubTemplateSize].usValueLen = sizeof(CK_BBOOL);
      PubTemplateSize++;

      // include CKA_SIGN for public key
      PriTemplate[PriTemplateSize].type = CKA_SIGN;
      PriTemplate[PriTemplateSize].pValue = &sKeyGenTemplate->bCKA_Sign;
      PriTemplate[PriTemplateSize].usValueLen = sizeof(CK_BBOOL);
      PriTemplateSize++;
   }

   // Check if key has encrypt or wrap capability
   if (bWrapEncrypt == CK_TRUE)
   {
      // include CKA_ENCRYPT and CKA WRAP for public key
      PubTemplate[PubTemplateSize].type = CKA_ENCRYPT;
      PubTemplate[PubTemplateSize].pValue = &sKeyGenTemplate->bCKA_Encrypt;
      PubTemplate[PubTemplateSize].usValueLen = sizeof(CK_BBOOL);
      PubTemplateSize++;
      PubTemplate[PubTemplateSize].type = CKA_WRAP;
      PubTemplate[PubTemplateSize].pValue = &sKeyGenTemplate->bCKA_Wrap;
      PubTemplate[PubTemplateSize].usValueLen = sizeof(CK_BBOOL);
      PubTemplateSize++;

      // include CKA_DECRYPT and CKA CKA_UNWRAP for public key
      PriTemplate[PriTemplateSize].type = CKA_DECRYPT;
      PriTemplate[PriTemplateSize].pValue = &sKeyGenTemplate->bCKA_Decrypt;
      PriTemplate[PriTemplateSize].usValueLen = sizeof(CK_BBOOL);
      PriTemplateSize++;
      PriTemplate[PriTemplateSize].type = CKA_UNWRAP;
      PriTemplate[PriTemplateSize].pValue = &sKeyGenTemplate->bCKA_Unwrap;
      PriTemplate[PriTemplateSize].usValueLen = sizeof(CK_BBOOL);
      PriTemplateSize++;
   }

   // generate keypair
   retCode = P11Functions->C_GenerateKeyPair(hSession,
      (CK_MECHANISM_PTR)&sKeygenMech,
      PubTemplate,
      PubTemplateSize,
      PriTemplate,
      PriTemplateSize,
      &hPublicKey,
      &hPrivateKey);

   if (retCode == CKR_OK)
   {
      printf("Key pair successfully generated, private key handle : %i, public key handle : %i \n", hPrivateKey, hPublicKey);
      return CK_TRUE;
   }

   printf("C_GenerateKeyPair error code : %s \n", P11Util_DisplayErrorName(retCode));
   return CK_FALSE;
}


/*
    FUNCTION:        CK_BBOOL P11_CreateDO(P11_DOTEMPLATE* sDOTemplate)
*/
CK_BBOOL P11_CreateDO(P11_DOTEMPLATE* sDOTemplate)
{
   CK_RV             retCode = CKR_DEVICE_ERROR;
   CK_OBJECT_CLASS   cDO = CKO_DATA;
   CK_OBJECT_HANDLE  hDataObject;
   CK_ULONG          uAppLength = 0;

   if (sDOTemplate->pApplication != NULL)
   {
      uAppLength = (CK_ULONG)strlen(sDOTemplate->pApplication);
   }

   CK_ATTRIBUTE DOTemplate[20] = {
      {CKA_CLASS,             &cDO,                            sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN,             &sDOTemplate->bCKA_Token,        sizeof(CK_BBOOL)},
      {CKA_PRIVATE,           &sDOTemplate->bCKA_Private,      sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE,        &sDOTemplate->bCKA_Modifiable,   sizeof(CK_BBOOL)},
      {CKA_LABEL,             sDOTemplate->pLabel,             (CK_ULONG)strlen(sDOTemplate->pLabel)},
      {CKA_APPLICATION ,      sDOTemplate->pApplication,       uAppLength},
      {CKA_VALUE,             sDOTemplate->pValue,             (CK_ULONG)sDOTemplate->upValueLength},
   };

   // create DO
   retCode = P11Functions->C_CreateObject(hSession,
      DOTemplate,
      DIM(DOTemplate),
      &hDataObject);

   if (retCode == CKR_OK)
   {
      printf("Data Object successfully generated, handle value is %i,\n", hDataObject);
      return CK_TRUE;
   }

   printf("C_CreateObject error code : %s \n", P11Util_DisplayErrorName(retCode));
   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL P11_WrapPrivateSecretKey(P11_WRAPTEMPLATE* sWrapTemplate,  CK_BYTE_PTR   pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
*/
CK_BBOOL P11_WrapPrivateSecretKey(P11_WRAPTEMPLATE* sWrapTemplate, CK_BYTE_PTR   pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
   CK_RV             retCode = CKR_DEVICE_ERROR;
   CK_MECHANISM      swrapMech = { 0 };


   if (P11_BuildCKEncMecanism(sWrapTemplate->wrap_key_mech, &swrapMech) == CK_FALSE)
   {
      return CK_FALSE;
   }

   // unwrap the key
   retCode = P11Functions->C_WrapKey(hSession, &swrapMech, sWrapTemplate->hWrappingKey, sWrapTemplate->hKeyToExport, pWrappedKey, pulWrappedKeyLen);

   // check if successfull
   if (retCode == CKR_OK)
   {
      return CK_TRUE;
   }

   printf("C_WrapKey error code : %s \n", P11Util_DisplayErrorName(retCode));
   return CK_FALSE;
}

/*
    FUNCTION:       CK_BBOOL P11_UnwrapPrivateSecretKey(P11_UNWRAPTEMPLATE* sImportPublicKeyTemplate, CK_CHAR_PTR pWrappedKey, CK_LONG pulWrappedKeyLen)
*/
CK_BBOOL P11_UnwrapPrivateSecretKey(P11_UNWRAPTEMPLATE* sUnWrapTemplate, CK_CHAR_PTR pWrappedKey, CK_LONG pulWrappedKeyLen, CK_OBJECT_HANDLE * hKey)
{
   CK_RV             retCode = CKR_DEVICE_ERROR;
   CK_MECHANISM      swrapMech = { 0 };
   CK_ATTRIBUTE_PTR  KeyTemplate;
   CK_OBJECT_HANDLE  hUnwrappedKey = 0;
   CK_ULONG          templatesize = 0;
   CK_ULONG          symtemplatesize = 15;
   CK_ULONG          privtemplatesize = 10;

   CK_ATTRIBUTE SymKeyTemplate[20] = {
   {CKA_CLASS,             &sUnWrapTemplate->sClass,           sizeof(CK_OBJECT_CLASS)},
   {CKA_KEY_TYPE,          &sUnWrapTemplate->skeyType,         sizeof(CK_KEY_TYPE)},
   {CKA_TOKEN,             &sUnWrapTemplate->bCKA_Token,       sizeof(CK_BBOOL)},
   {CKA_SENSITIVE,         &sUnWrapTemplate->bCKA_Sensitive,   sizeof(CK_BBOOL)},
   {CKA_PRIVATE,           &sUnWrapTemplate->bCKA_Private,     sizeof(CK_BBOOL)},
   {CKA_ENCRYPT,           &sUnWrapTemplate->bCKA_Encrypt,     sizeof(CK_BBOOL)},
   {CKA_DECRYPT,           &sUnWrapTemplate->bCKA_Decrypt,     sizeof(CK_BBOOL)},
   {CKA_SIGN,              &sUnWrapTemplate->bCKA_Sign,        sizeof(CK_BBOOL)},
   {CKA_VERIFY,            &sUnWrapTemplate->bCKA_Verify,      sizeof(CK_BBOOL)},
   {CKA_WRAP,              &sUnWrapTemplate->bCKA_Wrap,        sizeof(CK_BBOOL)},
   {CKA_UNWRAP,            &sUnWrapTemplate->bCKA_Unwrap,      sizeof(CK_BBOOL)},
   {CKA_DERIVE,            &sUnWrapTemplate->bCKA_Derive,      sizeof(CK_BBOOL)},
   {CKA_EXTRACTABLE,       &sUnWrapTemplate->bCKA_Extractable, sizeof(CK_BBOOL)},
   {CKA_MODIFIABLE,        &sUnWrapTemplate->bCKA_Modifiable,  sizeof(CK_BBOOL)},
   {CKA_LABEL,             sUnWrapTemplate->pKeyLabel,         (CK_ULONG)strlen(sUnWrapTemplate->pKeyLabel)},
   };

   CK_ATTRIBUTE PriTemplate[20] = {
   {CKA_CLASS,             &sUnWrapTemplate->sClass,           sizeof(CK_OBJECT_CLASS)},
   {CKA_KEY_TYPE,          &sUnWrapTemplate->skeyType,         sizeof(CK_KEY_TYPE)},
   {CKA_TOKEN,             &sUnWrapTemplate->bCKA_Token,       sizeof(CK_BBOOL)},
   {CKA_SENSITIVE,         &sUnWrapTemplate->bCKA_Sensitive,   sizeof(CK_BBOOL)},
   {CKA_PRIVATE,           &sUnWrapTemplate->bCKA_Private,     sizeof(CK_BBOOL)},
   {CKA_SIGN,              &sUnWrapTemplate->bCKA_Sign,        sizeof(CK_BBOOL)},
   {CKA_DERIVE,            &sUnWrapTemplate->bCKA_Derive,      sizeof(CK_BBOOL)},
   {CKA_EXTRACTABLE,       &sUnWrapTemplate->bCKA_Extractable, sizeof(CK_BBOOL)},
   {CKA_MODIFIABLE,        &sUnWrapTemplate->bCKA_Modifiable,  sizeof(CK_BBOOL)},
   {CKA_LABEL,             sUnWrapTemplate->pKeyLabel,         (CK_ULONG)strlen(sUnWrapTemplate->pKeyLabel)},
   };

   // Check if CKA id is given in parameter
   if (sUnWrapTemplate->pCKA_ID != NULL)
   {
      // push CKA id in PubTemplate
      SymKeyTemplate[symtemplatesize].type = CKA_ID;
      SymKeyTemplate[symtemplatesize].pValue = sUnWrapTemplate->pCKA_ID;
      SymKeyTemplate[symtemplatesize].usValueLen = sUnWrapTemplate->uCKA_ID_Length;
      symtemplatesize++;

      // push CKA id in PriTemplate
      PriTemplate[privtemplatesize].type = CKA_ID;
      PriTemplate[privtemplatesize].pValue = sUnWrapTemplate->pCKA_ID;
      PriTemplate[privtemplatesize].usValueLen = sUnWrapTemplate->uCKA_ID_Length;
      privtemplatesize++;
   }

   // Check if key size is given in parameter
   if (sUnWrapTemplate->skeySize != 0)
   {
      // push CKA_VALUE_LEN in sym template
      SymKeyTemplate[symtemplatesize].type = CKA_VALUE_LEN;
      SymKeyTemplate[symtemplatesize].pValue = &sUnWrapTemplate->skeySize;
      SymKeyTemplate[symtemplatesize].usValueLen = sizeof(CK_LONG);
      symtemplatesize++;

      // push CKA_VALUE_LEN id in PriTemplate
      PriTemplate[privtemplatesize].type = CKA_VALUE_LEN;
      PriTemplate[privtemplatesize].pValue = sUnWrapTemplate->pCKA_ID;
      PriTemplate[privtemplatesize].usValueLen = sUnWrapTemplate->uCKA_ID_Length;
      privtemplatesize++;
   }

   if (sUnWrapTemplate->sClass == CKO_PRIVATE_KEY)
   {
      if ((sUnWrapTemplate->skeyType == CKK_RSA) || (sUnWrapTemplate->skeyType == CKK_ECDSA))
      {
         // include CKA_DECRYPT and CKA UNWRAP for rsa and ecdsa private key
         PriTemplate[privtemplatesize].type = CKA_DECRYPT;
         PriTemplate[privtemplatesize].pValue = &sUnWrapTemplate->bCKA_Decrypt;
         PriTemplate[privtemplatesize].usValueLen = sizeof(CK_BBOOL);
         privtemplatesize++;
         PriTemplate[privtemplatesize].type = CKA_UNWRAP;
         PriTemplate[privtemplatesize].pValue = &sUnWrapTemplate->bCKA_Unwrap;
         PriTemplate[privtemplatesize].usValueLen = sizeof(CK_BBOOL);
         privtemplatesize++;
      }

      // use the private key attribute template
      KeyTemplate = PriTemplate;
      templatesize = privtemplatesize;
   }
   else
   {
      // use the secret key attribute template
      KeyTemplate = SymKeyTemplate;
      templatesize = symtemplatesize;
   }

   if (P11_BuildCKEncMecanism(sUnWrapTemplate->wrapmech, &swrapMech) == CK_FALSE)
   {
      return CK_FALSE;
   }
   
   // unwrap the key
   retCode = P11Functions->C_UnwrapKey(hSession,
      &swrapMech,
      sUnWrapTemplate->hWrappingKey,
      pWrappedKey,
      pulWrappedKeyLen,
      KeyTemplate,
      templatesize,
      &hUnwrappedKey);


   // check if successfull
   if (retCode == CKR_OK)
   {
      *hKey = hUnwrappedKey;
      //printf("Key successfully unwrapped: handle is : %i, label is : %s \n", hUnwrappedKey, sUnWrapTemplate->pKeyLabel);
      return CK_TRUE;
   }

   printf("C_UnwrapKey error code : %s \n", P11Util_DisplayErrorName(retCode));
   return CK_FALSE;
}


/*
    FUNCTION:       CK_BBOOL P11_CreatePublicKey(P11_UNWRAPTEMPLATE* sImportPublicKeyTemplate, PUBLIC_KEY* sPublicKey)
*/
CK_BBOOL P11_CreatePublicKey(P11_UNWRAPTEMPLATE* sImportPublicKeyTemplate, PUBLIC_KEY* sPublicKey)
{
   CK_RV             retCode = CKR_DEVICE_ERROR;
   CK_OBJECT_HANDLE  hPublicKey = 0;
   CK_LONG           PubTemplateSize = 8;     // Size until CKA_LABEL.
   CK_BBOOL          bWrapEncrypt = CK_FALSE;
   P11_EDDSA_OID_CONVERT* eddsa_convert;

   // init with common attribute for all public key keys
   CK_ATTRIBUTE PubTemplate[20] = {
      {CKA_CLASS,             &sImportPublicKeyTemplate->sClass,           sizeof(CK_OBJECT_CLASS)},
      {CKA_KEY_TYPE,          &sImportPublicKeyTemplate->skeyType,         sizeof(CK_KEY_TYPE)},
      {CKA_TOKEN,             &sImportPublicKeyTemplate->bCKA_Token,       sizeof(CK_BBOOL)},
      {CKA_PRIVATE,           &sImportPublicKeyTemplate->bCKA_Private,     sizeof(CK_BBOOL)},
      {CKA_VERIFY,            &sImportPublicKeyTemplate->bCKA_Verify,      sizeof(CK_BBOOL)},
      {CKA_DERIVE,            &sImportPublicKeyTemplate->bCKA_Derive,      sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE,        &sImportPublicKeyTemplate->bCKA_Modifiable,  sizeof(CK_BBOOL)},
      {CKA_LABEL,             sImportPublicKeyTemplate->pKeyLabel,         (CK_ULONG)strlen(sImportPublicKeyTemplate->pKeyLabel)},
   };

   // Check if CKA id is given in paramter
   if (sImportPublicKeyTemplate->pCKA_ID != NULL)
   {
      // push CKA id in PubTemplate
      PubTemplate[PubTemplateSize].type = CKA_ID;
      PubTemplate[PubTemplateSize].pValue = sImportPublicKeyTemplate->pCKA_ID;
      PubTemplate[PubTemplateSize].usValueLen = sImportPublicKeyTemplate->uCKA_ID_Length;
      PubTemplateSize++;
   }

   // check key type
   switch (sImportPublicKeyTemplate->skeyType)
   {
   case CKK_RSA:
   {
      // set wrap encrypt capability
      bWrapEncrypt = CK_TRUE;

      // Set modulus length in bit
      PubTemplate[PubTemplateSize].type = CKA_MODULUS;
      PubTemplate[PubTemplateSize].pValue = sPublicKey->sRsaPublicKey.sModulus;
      PubTemplate[PubTemplateSize].usValueLen = sPublicKey->sRsaPublicKey.uModulusLength;
      PubTemplateSize++;

      // Set public exponant
      PubTemplate[PubTemplateSize].type = CKA_PUBLIC_EXPONENT;
      PubTemplate[PubTemplateSize].pValue = sPublicKey->sRsaPublicKey.sExponent;
      PubTemplate[PubTemplateSize].usValueLen = sPublicKey->sRsaPublicKey.uExponentLength;
      PubTemplateSize++;
      break;
   }
   case CKK_DH:
   case CKK_X9_42_DH:
      if (sPublicKey->sDsaPublicKey.sDomain.bIsSubPrime == CK_TRUE)
      {
         sImportPublicKeyTemplate->skeyType = CKK_X9_42_DH;
      }
   case CKK_DSA:
   {
      // Set prime
      PubTemplate[PubTemplateSize].type = CKA_PRIME;
      PubTemplate[PubTemplateSize].pValue = sPublicKey->sDsaPublicKey.sDomain.sPrime;
      PubTemplate[PubTemplateSize].usValueLen = sPublicKey->sDsaPublicKey.sDomain.uPrimeLength;
      PubTemplateSize++;

      // Set sub prime
      if (sPublicKey->sDsaPublicKey.sDomain.bIsSubPrime == CK_TRUE)
      {  
         PubTemplate[PubTemplateSize].type = CKA_SUBPRIME;
         PubTemplate[PubTemplateSize].pValue = sPublicKey->sDsaPublicKey.sDomain.sSubPrime;
         PubTemplate[PubTemplateSize].usValueLen = sPublicKey->sDsaPublicKey.sDomain.uSubPrimeLength;
         PubTemplateSize++;
      }

      // Set base
      PubTemplate[PubTemplateSize].type = CKA_BASE;
      PubTemplate[PubTemplateSize].pValue = sPublicKey->sDsaPublicKey.sDomain.sBase;
      PubTemplate[PubTemplateSize].usValueLen = sPublicKey->sDsaPublicKey.sDomain.uBaseLength;
      PubTemplateSize++;

      // Set public key
      PubTemplate[PubTemplateSize].type = CKA_VALUE;
      PubTemplate[PubTemplateSize].pValue = sPublicKey->sDsaPublicKey.sPublicKey;
      PubTemplate[PubTemplateSize].usValueLen = sPublicKey->sDsaPublicKey.uPublicKeyLength;
      PubTemplateSize++;
      break;
   }

   case CKK_EC_EDWARDS:
   case CKK_EC_MONTGOMERY:
   case CKK_EC_EDWARDS_OLD:
   case CKK_EC_MONTGOMERY_OLD:
      // Warning : the oid of the eddsa publicKeyInfo contain oid such as 1.3.101.112 curveEd25519
      // hsm requires oid  	1.3.6.1.4.1.11591.15.1 for Ed25519. In such case need to convert oid
      eddsa_convert = P11Util_EddsaConvertOidStd(sPublicKey->sEcPublicKey.sOid, sPublicKey->sEcPublicKey.uOidSize);
      if (eddsa_convert == NULL)
      {
         printf("C_CreateObject : invalid OID");
         return CK_FALSE;
      }
      // change oid with oid suported by Luna
      sPublicKey->sEcPublicKey.sOid = eddsa_convert->sOidHSM;
      sPublicKey->sEcPublicKey.uOidSize = eddsa_convert->uOidLengthHSM;
   case CKK_SM2:
   case CKK_ECDSA:
   {
      // Set ecdsa params
      PubTemplate[PubTemplateSize].type = CKA_ECDSA_PARAMS;
      PubTemplate[PubTemplateSize].pValue = sPublicKey->sEcPublicKey.sOid;
      PubTemplate[PubTemplateSize].usValueLen = sPublicKey->sEcPublicKey.uOidSize;
      PubTemplateSize++;

      // TODO : why HSM requires public point to be encapsulated in a TLV with TAG 04 ???
      // Why just not take the public key in uncompressed format
      asn1_Build_Init();
      asn1_Build_tlv(0x04, sPublicKey->sEcPublicKey.sPublicPoint, sPublicKey->sEcPublicKey.uPublicPointLength);

      PubTemplate[PubTemplateSize].type = CKA_EC_POINT;
      PubTemplate[PubTemplateSize].pValue = asn1_BuildGetBuffer();
      PubTemplate[PubTemplateSize].usValueLen = asn1_GetBufferSize();
      PubTemplateSize++;
      break;
   }
   default:
      printf("C_CreateObject : invalid keytype : %i", sImportPublicKeyTemplate->skeyType);
      return CK_FALSE;
   }

   // Check if key has encrypt or wrap capability
   if(bWrapEncrypt == CK_TRUE)
   {
      // include CKA_ENCRYPT and CKA WRAP for public key
      PubTemplate[PubTemplateSize].type = CKA_ENCRYPT;
      PubTemplate[PubTemplateSize].pValue = &sImportPublicKeyTemplate->bCKA_Encrypt;
      PubTemplate[PubTemplateSize].usValueLen = sizeof(CK_BBOOL);
      PubTemplateSize++;
      PubTemplate[PubTemplateSize].type = CKA_WRAP;
      PubTemplate[PubTemplateSize].pValue = &sImportPublicKeyTemplate->bCKA_Wrap;
      PubTemplate[PubTemplateSize].usValueLen = sizeof(CK_BBOOL);
      PubTemplateSize++;
   }

   // Create the key object
   retCode = P11Functions->C_CreateObject(hSession,
      PubTemplate,
      PubTemplateSize,
      &hPublicKey);


   // check if successfull
   if (retCode == CKR_OK)
   {
      printf("Public key successfully imported: handle is : %i, label is : %s \n", hPublicKey, sImportPublicKeyTemplate->pKeyLabel);
      return CK_TRUE;
   }

   printf("C_CreateObject error code : %s \n", P11Util_DisplayErrorName(retCode));
   return CK_FALSE;
}

/*
    FUNCTION:       CK_BBOOL P11_EncryptData(P11_ENCRYPT_TEMPLATE* sEncryptTemplate, CK_CHAR_PTR * pDecryptedData, CK_ULONG_PTR pDecryptedDataLength)
*/
CK_BBOOL P11_EncryptData(P11_ENCRYPT_TEMPLATE* sEncryptTemplate, CK_CHAR_PTR * pEncryptedData, CK_ULONG_PTR pEncryptedDataLength)
{
   CK_RV             retCode = CKR_DEVICE_ERROR;
   CK_MECHANISM      sEncMech = { 0 };
   CK_ULONG          uExpectedEncryptionSize = 0;

   do
   {

      if (P11_BuildCKEncMecanism(sEncryptTemplate->encryption_mech, &sEncMech) == CK_FALSE)
      {
         break;
      }

      // Call Encryption init fonction
      retCode = P11Functions->C_EncryptInit(hSession, &sEncMech, sEncryptTemplate->hEncyptiontKey);
      if (retCode != CKR_OK)
      {
         break;
      }

      // Call Encryption Fonction to get the size of encrypted data
      retCode = P11Functions->C_Encrypt(hSession, sEncryptTemplate->sInputData, sEncryptTemplate->sInputDataLength, NULL, &uExpectedEncryptionSize);
      if (retCode != CKR_OK)
      {
         break;
      }

      // Allocate Buffer of the size of data
      *pEncryptedData = malloc(uExpectedEncryptionSize);

      // check if allocation is ok
      if (*pEncryptedData == NULL)
      {
         break;
      }

      *pEncryptedDataLength = uExpectedEncryptionSize;
      // Call Encryption Fonction
      retCode = P11Functions->C_Encrypt(hSession, sEncryptTemplate->sInputData, sEncryptTemplate->sInputDataLength, *pEncryptedData, pEncryptedDataLength);
      if (retCode != CKR_OK)
      {
         break;
      }

      return CK_TRUE;

   } while (FALSE);

   printf("C_Encrypt : error code : %i", retCode);

   return CK_FALSE;
}

/*
    FUNCTION:       CK_BBOOL P11_DecryptData(P11_ENCRYPT_TEMPLATE* sEncryptTemplate, CK_CHAR_PTR* pDecryptedData, CK_ULONG_PTR pDecryptedDataLength)
*/
CK_BBOOL P11_DecryptData(P11_ENCRYPT_TEMPLATE* sEncryptTemplate, CK_CHAR_PTR* pDecryptedData, CK_ULONG_PTR pDecryptedDataLength)
{
   CK_RV             retCode = CKR_DEVICE_ERROR;
   CK_MECHANISM      sEncMech = { 0 };
   CK_ULONG          uExpectedDecryptionSize = 0;

   do
   {

      if (P11_BuildCKEncMecanism(sEncryptTemplate->encryption_mech, &sEncMech) == CK_FALSE)
      {
         break;
      }

      // Call Encryption init fonction
      retCode = P11Functions->C_DecryptInit(hSession, &sEncMech, sEncryptTemplate->hEncyptiontKey);
      if (retCode != CKR_OK)
      {
         printf("C_DecryptInit error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      /*
      // Call Encryption Fonction to get the size of encrypted data
      retCode = P11Functions->C_Decrypt(hSession, sEncryptTemplate->sInputData, sEncryptTemplate->sInputDataLength, NULL, &uExpectedDecryptionSize);
      if (retCode != CKR_OK)
      {
         break;
      }
      */
      // Allocate Buffer of the size of input data. Decrypt data will always be smaller
      *pDecryptedData = malloc(sEncryptTemplate->sInputDataLength);

      // check if allocation is ok
      if (*pDecryptedData == NULL)
      {
         break;
      }

      *pDecryptedDataLength = sEncryptTemplate->sInputDataLength;
      // Call Encryption Fonction
      retCode = P11Functions->C_Decrypt(hSession, sEncryptTemplate->sInputData, sEncryptTemplate->sInputDataLength, *pDecryptedData, pDecryptedDataLength);
      if (retCode != CKR_OK)
      {
         // if error here, must release allocated memory
         free(*pDecryptedData);

         printf("C_Decrypt error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:       CK_BBOOL P11_BuildCKEncMecanism(P11_ENCRYPTION_MECH* sign_mech, CK_MECHANISM_PTR  sEncMech)
*/
CK_BBOOL P11_BuildCKEncMecanism(P11_ENCRYPTION_MECH* encryption_mech, CK_MECHANISM_PTR  sEncMech)
{
   // Set enc mecansim value
   sEncMech->mechanism = encryption_mech->ckMechType;

   // check the unwrap mecanism type
   switch (encryption_mech->ckMechType)
   {
   case CKM_AES_ECB:
   case CKM_AES_KWP:
   case CKM_AES_KW:
      sEncMech->pParameter = NULL;
      sEncMech->usParameterLen = 0;
      break;
   case CKM_AES_CBC:
   case CKM_AES_CBC_PAD:
   case CKM_AES_CFB8:
   case CKM_AES_CFB128:
   case CKM_AES_OFB:
   case CKM_AES_CBC_PAD_IPSEC:
      // Init the sIV buffer and size
      sEncMech->pParameter = encryption_mech->aes_param.iv;
      sEncMech->usParameterLen = AES_IV_LENGTH;
      break;
   case CKM_AES_GCM:
      // Init the sIV buffer and size
      sEncMech->pParameter = &encryption_mech->aes_gcm_param;
      sEncMech->usParameterLen = sizeof(CK_GCM_PARAMS);
      break;
   case CKM_RSA_PKCS_OAEP:
      // push CK_RSA_PKCS_OAEP_PARAMS from sEncryptTemplate
      sEncMech->pParameter = &encryption_mech->rsa_oeap_param;
      sEncMech->usParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
      break;
   default:
      printf("P11_BuildCKEncMecanism : Invalid Mecanism : %i", encryption_mech->ckMechType);
      return CK_FALSE;
   };

   return CK_TRUE;
}

/*
    FUNCTION:       CK_BBOOL P11_BuildCKSignMecanism(P11_SIGN_MECH* sign_mech, CK_MECHANISM_PTR  sEncMech)
*/
CK_BBOOL P11_BuildCKSignMecanism(P11_SIGN_MECH* sign_mech, CK_MECHANISM_PTR  sEncMech)
{
   // Set enc mecansim value
   sEncMech->mechanism = sign_mech->ckMechType;

   // check the unwrap mecanism type
   switch (sign_mech->ckMechType)
   {
   case CKM_AES_CMAC:
      // Init the sIV buffer and size
      sEncMech->pParameter = sign_mech->aes_param.iv;
      if (sEncMech->pParameter != NULL)
      {
         sEncMech->usParameterLen = AES_IV_LENGTH;
      }
      else
      {
         sEncMech->usParameterLen = 0;
      }
      break;
   case CKM_DES3_CMAC:
   case CKM_DES_MAC:
   case CKM_DES3_MAC:
      // Init the sIV buffer and size
      sEncMech->pParameter = sign_mech->des_param.iv;
      if (sEncMech->pParameter != NULL)
      {
         sEncMech->usParameterLen = DES_IV_LENGTH;
      }
      else
      {
         sEncMech->usParameterLen = 0;
      }
      break;
   case CKM_SHA256_HMAC:
      sEncMech->pParameter = NULL;
      sEncMech->usParameterLen = 0;
      break;

   default:
      printf("P11_BuildCKSignMecanism : Invalid Mecanism : %i", sign_mech->ckMechType);
      return CK_FALSE;
   };

   return CK_TRUE;
}

/*
    FUNCTION:       CK_BBOOL P11_EncryptData(P11_ENCRYPT_TEMPLATE* sEncryptTemplate, CK_CHAR_PTR * pDecryptedData, CK_ULONG_PTR pDecryptedDataLength)
*/
CK_BBOOL P11_SignData(P11_SIGNATURE_TEMPLATE* sSignTemplate, CK_CHAR_PTR* pSignauture, CK_ULONG_PTR pSignautureLength)
{
   CK_RV             retCode = CKR_DEVICE_ERROR;
   CK_MECHANISM      sEncMech = { 0 };
   CK_ULONG          uExpectedEncryptionSize = 0;
   CK_BBOOL          bIsAllocate = CK_FALSE;

   do
   {
      if (P11_BuildCKSignMecanism(sSignTemplate->sign_mech, &sEncMech) == CK_FALSE)
      {
         break;
      }

      // Call sign init fonction
      retCode = P11Functions->C_SignInit(hSession, &sEncMech, sSignTemplate->hSignatureKey);
      if (retCode != CKR_OK)
      {
         break;
      } 


      // Call sign Fonction to get the size of encrypted data
      retCode = P11Functions->C_Sign(hSession, sSignTemplate->sInputData, sSignTemplate->sInputDataLength, NULL, &uExpectedEncryptionSize);
      if (retCode != CKR_OK)
      {
         break;
      }

      // check if a buffer is already provided in input. If not allocate memory
      if (!((*pSignauture != NULL) && (*pSignautureLength >= uExpectedEncryptionSize)))
      {
         // Allocate Buffer of the size of data
         *pSignauture = malloc(uExpectedEncryptionSize);

         // check if allocation is ok
         if (*pSignauture == NULL)
         {
            break;
         }
         bIsAllocate = CK_TRUE;
      }



      // Call sign Fonction to get the size of encrypted data
      *pSignautureLength = uExpectedEncryptionSize;
      retCode = P11Functions->C_Sign(hSession, sSignTemplate->sInputData, sSignTemplate->sInputDataLength, *pSignauture, pSignautureLength);
      if (retCode != CKR_OK)
      {
         if (bIsAllocate == CK_TRUE)
         {
            free(*pSignauture);
         }
         break;
      }


      return CK_TRUE;

   } while (FALSE);

   printf("C_Sign error code : %s \n", P11Util_DisplayErrorName(retCode));

   return CK_FALSE;
}

/*
    FUNCTION:       CK_BBOOL P11_DeriveKey(P11_DERIVETEMPLATE* sDeriveTemplate)
*/
CK_BBOOL P11_DeriveKey(P11_DERIVETEMPLATE* sDeriveTemplate)
{

   CK_RV             retCode = CKR_DEVICE_ERROR;
   CK_MECHANISM      sDeriveMech = { 0 };
   CK_ULONG          uTemplateSize = 16;
   CK_OBJECT_HANDLE  hDerivedKey = 0;
   
   CK_ATTRIBUTE SymKeyTemplate[20] = {
   {CKA_CLASS,             &sDeriveTemplate->sDerivedClass,       sizeof(CK_OBJECT_CLASS)},
   {CKA_KEY_TYPE,          &sDeriveTemplate->sderivedKeyType,     sizeof(CK_KEY_TYPE)},
   {CKA_VALUE_LEN,         &sDeriveTemplate->sderivedKeyLength,   sizeof(CK_LONG)},
   {CKA_TOKEN,             &sDeriveTemplate->bCKA_Token,          sizeof(CK_BBOOL)},
   {CKA_SENSITIVE,         &sDeriveTemplate->bCKA_Sensitive,      sizeof(CK_BBOOL)},
   {CKA_PRIVATE,           &sDeriveTemplate->bCKA_Private,        sizeof(CK_BBOOL)},
   {CKA_ENCRYPT,           &sDeriveTemplate->bCKA_Encrypt,        sizeof(CK_BBOOL)},
   {CKA_DECRYPT,           &sDeriveTemplate->bCKA_Decrypt,        sizeof(CK_BBOOL)},
   {CKA_SIGN,              &sDeriveTemplate->bCKA_Sign,           sizeof(CK_BBOOL)},
   {CKA_VERIFY,            &sDeriveTemplate->bCKA_Verify,         sizeof(CK_BBOOL)},
   {CKA_WRAP,              &sDeriveTemplate->bCKA_Wrap,           sizeof(CK_BBOOL)},
   {CKA_UNWRAP,            &sDeriveTemplate->bCKA_Unwrap,         sizeof(CK_BBOOL)},
   {CKA_DERIVE,            &sDeriveTemplate->bCKA_Derive,         sizeof(CK_BBOOL)},
   {CKA_EXTRACTABLE,       &sDeriveTemplate->bCKA_Extractable,    sizeof(CK_BBOOL)},
   {CKA_MODIFIABLE,        &sDeriveTemplate->bCKA_Modifiable,     sizeof(CK_BBOOL)},
   {CKA_LABEL,             sDeriveTemplate->pDerivedKeyLabel,     (CK_ULONG)strlen(sDeriveTemplate->pDerivedKeyLabel)},
   };

   // Check if CKA id is given in paramter
   if (sDeriveTemplate->pCKA_ID != NULL)
   {
      // push CKA id in PubTemplate
      SymKeyTemplate[uTemplateSize].type = CKA_ID;
      SymKeyTemplate[uTemplateSize].pValue = sDeriveTemplate->pCKA_ID;
      SymKeyTemplate[uTemplateSize].usValueLen = sDeriveTemplate->uCKA_ID_Length;
      uTemplateSize++;
   }

   // check the derived key type
   switch (sDeriveTemplate->sDeriveMech->ckMechType)
   {
   case CKM_SHA1_KEY_DERIVATION:
   case CKM_SHA224_KEY_DERIVATION:
   case CKM_SHA256_KEY_DERIVATION:
   case CKM_SHA384_KEY_DERIVATION:
   case CKM_SHA512_KEY_DERIVATION:
   case CKM_SHA3_224_KEY_DERIVE:
   case CKM_SHA3_256_KEY_DERIVE:
   case CKM_SHA3_384_KEY_DERIVE:
   case CKM_SHA3_512_KEY_DERIVE:
      sDeriveMech.mechanism = sDeriveTemplate->sDeriveMech->ckMechType;
      sDeriveMech.pParameter = NULL;
      sDeriveMech.usParameterLen = 0;
      break;
   case CKM_PRF_KDF:
   case CKM_NIST_PRF_KDF:
      sDeriveMech.mechanism = sDeriveTemplate->sDeriveMech->ckMechType;
      sDeriveMech.pParameter = &sDeriveTemplate->sDeriveMech->sPrfKdfParams;
      sDeriveMech.usParameterLen = sizeof(CK_PRF_KDF_PARAMS);
      break;

   default:
      printf("C_DeriveKey unknown mecanism : %i \n", sDeriveTemplate->sDeriveMech->ckMechType);
      return CK_FALSE;
   }

   // derive the key
   retCode = P11Functions->C_DeriveKey(hSession,
      &sDeriveMech,
      sDeriveTemplate->hMasterKey,
      SymKeyTemplate,
      uTemplateSize,
      &hDerivedKey);

   // check if successfull
   if (retCode == CKR_OK)
   {
      printf("Key successfully derived: handle is : %i, label is : %s \n", hDerivedKey, sDeriveTemplate->pDerivedKeyLabel);
      return CK_TRUE;
   }

   printf("C_DeriveKey error code : %s \n", P11Util_DisplayErrorName(retCode));

   return CK_FALSE;
}

/*
    FUNCTION:       CK_BBOOL P11_DigestKey(P11_HASH_MECH* sHash, CK_OBJECT_HANDLE  hKey)
*/
CK_BBOOL P11_DigestKey(P11_HASH_MECH* sHash, CK_OBJECT_HANDLE  hKey)
{
   CK_RV             retCode = CKR_DEVICE_ERROR;
   CK_MECHANISM      sDigestKeyMech = { 0 };
   CK_LONG           uLength = TEMP_BUFFER_SIZE;
   do
   {
      sDigestKeyMech.mechanism = sHash->ckMechType;

      retCode = P11Functions->C_DigestInit(hSession, &sDigestKeyMech);
      if (retCode != CKR_OK)
      {
         printf("C_DigestInit error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      retCode = P11Functions->C_DigestKey(hSession, hKey);

      if (retCode != CKR_OK)
      {
         printf("C_DigestKey error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      retCode = P11Functions->C_DigestFinal(hSession, &pTempBuffer[0], &uLength);
      if (retCode != CKR_OK)
      {
         printf("C_DigestFinal error code : %s \n", P11Util_DisplayErrorName(retCode));
         break;
      }

      // display the digest value
      str_DisplayByteArraytoString("DigestKey Value = ", pTempBuffer, uLength);

      return CK_TRUE;

   } while (FALSE);

   return CK_FALSE;
}


/*
    FUNCTION:        CK_BBOOL P11_ComputeKCV(BYTE bKCVMethod, CK_OBJECT_HANDLE  hKey, CK_CHAR_PTR pKcvBuffer)
*/
 CK_BBOOL P11_ComputeKCV(BYTE bKCVMethod, CK_OBJECT_HANDLE  hKey, CK_CHAR_PTR * pKcvBuffer)
{
    CK_RV                     retCode = CKR_DEVICE_ERROR;
    CK_MECHANISM              sMech = { 0 };
    P11_SIGN_MECH             sSignMech = { 0 };
    P11_ENCRYPTION_MECH       sEncMech = { 0 };
    CK_CHAR                   sInputData[16] = { 0 };
    CK_ULONG                  sSigbDataLengh = 0;
    CK_BBOOL                  bRestoreAttribute = CK_FALSE;
    CK_BBOOL                  bResult;
    P11_SIGNATURE_TEMPLATE    sSignatureTemplate = { 0 };
    P11_ENCRYPT_TEMPLATE      sEncryptionTemplate = { 0 };
    CK_OBJECT_CLASS           sClass = 0;
    CK_KEY_TYPE               skeyType = 0;
    CK_MECHANISM_TYPE         ckMechTypeMac = 0;
    CK_MECHANISM_TYPE         ckMechTypeEnc = 0;
    CK_MECHANISM_TYPE         ckMechTypehMac = 0;
    CK_ULONG                  uInputLengh = 0;

    sClass = P11_GetObjectClass(hKey);

    // check class
    if (sClass != CKO_SECRET_KEY)
    {
       printf("error : unsupported key class : %s\n", P11Util_DisplayClassName(sClass));
       return CK_FALSE;
    }


    // check key type
    skeyType = P11_GetKeyType(hKey);
    switch (skeyType)
    {
    case CKK_AES:
       ckMechTypeMac = CKM_AES_CMAC;
       ckMechTypeEnc = CKM_AES_ECB;
       uInputLengh = AES_BLOCK_LENGTH;
       break;
    case CKK_DES:
       ckMechTypeMac = CKM_DES_MAC;
       ckMechTypeEnc = CKM_DES_ECB;
       uInputLengh = DES_BLOCK_LENGTH;
    case CKK_DES2:
    case CKK_DES3:
       ckMechTypeMac = CKM_DES3_MAC;
       ckMechTypeEnc = CKM_DES3_ECB;
       uInputLengh = DES_BLOCK_LENGTH;
       break;
    case CKK_GENERIC_SECRET:
       ckMechTypehMac = CKM_SHA256_HMAC;
       uInputLengh = 0;
       break;
    default:
       printf("P11_ComputeKCV error : unsuported key type : %s\n", P11Util_DisplayKeyTypeName(skeyType));
       return CK_FALSE;
    }

    // check kcv method
    switch (bKCVMethod)
    {
    case KCV_GP:

       if (skeyType == CKK_AES)
       {
          // Global platform method need a buffer set to 0101...0101
          for (CK_BYTE bLoop = 0; bLoop < sizeof(sInputData); bLoop++)
          {
             sInputData[bLoop] = 0x01;
          }

       }
       // continue with cmac
    case KCV_PCI:

       // use cmac signature
       sSignatureTemplate.hSignatureKey = hKey;
       sSignatureTemplate.sClass = sClass;
       sSignatureTemplate.skeyType = skeyType;
       sSignatureTemplate.sInputData = sInputData;
       sSignatureTemplate.sInputDataLength = uInputLengh;
       sSignMech.aes_param.iv = NULL;
       sSignMech.ckMechType = ckMechTypeMac;

       sSignatureTemplate.sign_mech = &sSignMech;

       // Check if key has attribute CKA_SIGN
       if (P11_GetBooleanAttribute(hKey, CKA_SIGN) == CK_FALSE)
       {
          if (P11_SetAttributeBoolean(hKey, CKA_SIGN, CK_TRUE) == CK_FALSE)
          {
             printf("P11_ComputeKCV error : Sign attribute is not set\n ");
             break;
          }
          bRestoreAttribute = CK_TRUE;
       }

       bResult = P11_SignData(&sSignatureTemplate, pKcvBuffer, &sSigbDataLengh);

       // restore sign attribute
       if (bRestoreAttribute == CK_TRUE)
       {
          P11_SetAttributeBoolean(hKey, CKA_SIGN, CK_FALSE);
       }

       if (bResult == FALSE)
       {
          break;
       }
       return CK_TRUE;

    case KCV_PKCS11:

       // Check if key has attribute CKA_ENCRYPT
       if (P11_GetBooleanAttribute(hKey, CKA_ENCRYPT) == CK_FALSE)
       {
          if (P11_SetAttributeBoolean(hKey, CKA_ENCRYPT, CK_TRUE) == CK_FALSE)
          {
             printf("P11_ComputeKCV error : Encrypt attribute is not set\n ");
             break;
          }
          bRestoreAttribute = CK_TRUE;
       }

       // use encryption
       sEncryptionTemplate.hEncyptiontKey = hKey;
       sEncryptionTemplate.sClass = sClass;
       sEncryptionTemplate.skeyType = skeyType;
       sEncryptionTemplate.sInputData = sInputData;
       sEncryptionTemplate.sInputDataLength = uInputLengh;
       sEncMech.aes_param.iv = NULL;
       sEncMech.ckMechType = ckMechTypeEnc;
       sEncryptionTemplate.encryption_mech = &sEncMech;

       P11_EncryptData(&sEncryptionTemplate, pKcvBuffer, &sSigbDataLengh);

       // restore encrypt attribute
       if (bRestoreAttribute == CK_TRUE)
       {
          P11_SetAttributeBoolean(hKey, CKA_ENCRYPT, CK_FALSE);
       }

       return CK_TRUE;

    case KCV_HMAC_256:
       // use cmac signature
       sSignatureTemplate.hSignatureKey = hKey;
       sSignatureTemplate.sClass = sClass;
       sSignatureTemplate.skeyType = skeyType;
       sSignatureTemplate.sInputData = sInputData;
       sSignatureTemplate.sInputDataLength = uInputLengh;
       sSignMech.aes_param.iv = NULL;
       sSignMech.ckMechType = ckMechTypehMac;

       sSignatureTemplate.sign_mech = &sSignMech;

       // Check if key has attribute CKA_SIGN
       if (P11_GetBooleanAttribute(hKey, CKA_SIGN) == CK_FALSE)
       {
          if (P11_SetAttributeBoolean(hKey, CKA_SIGN, CK_TRUE) == CK_FALSE)
          {
             printf("P11_ComputeKCV error : Sign attribute is not set\n ");
             break;
          }
          bRestoreAttribute = CK_TRUE;
       }

       bResult = P11_SignData(&sSignatureTemplate, pKcvBuffer, &sSigbDataLengh);

       // restore sign attribute
       if (bRestoreAttribute == CK_TRUE)
       {
          P11_SetAttributeBoolean(hKey, CKA_SIGN, CK_FALSE);
       }

       if (bResult == FALSE)
       {
          break;
       }
       return CK_TRUE;


    default:
       printf("P11_ComputeKCV error : unknown KCV method\n ");
       break;
    }

   return CK_FALSE;
}

/*
    FUNCTION:         CK_BBOOL P11_GenerateRandom(CK_BYTE_PTR pbBuffer, CK_ULONG uLength)
*/
 CK_BBOOL P11_GenerateRandom(CK_BYTE_PTR pbBuffer, CK_ULONG uLength)
 {
    CK_RV             retCode = CKR_DEVICE_ERROR;
    do
    {
       // generate random from HSM
       retCode = P11Functions->C_GenerateRandom(hSession, pbBuffer, uLength);

       if (retCode != CKR_OK)
       {
          break;
       }

       // no error
       return CK_TRUE;

    } while (FALSE);
    
    // print error code
    printf("C_GenerateRandom error code : %s \n", P11Util_DisplayErrorName(retCode));
    return CK_FALSE;
 }
