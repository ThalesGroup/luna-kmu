/****************************************************************************\
*
* This file is part of the "Luna KMU" tool.
*
* The "KMU" tool is provided under the MIT license (see the
* following Web site for further details: https://mit-license.org/ ).
*
* Author: Sanyam Bassi
*
* Copyright © 2023-2024 Thales Group
*
\****************************************************************************/

#define _P11_QUERY_C

#ifdef OS_WIN32
#include <windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "p11query.h"
#include "p11util.h"
#include "str.h"
#include "file.h"
#include "pkcs8.h"
#include "asn1.h"
#include "tr31.h"
#include "tmd.h"

extern CK_FUNCTION_LIST* P11Functions;
extern CK_SESSION_HANDLE hSession;

/*
    FUNCTION:        CK_BBOOL P11_QuerySlots(P11_SLOT_ROW* rows, CK_ULONG maxRows, CK_ULONG* pCount)
*/
CK_BBOOL P11_QuerySlots(P11_SLOT_ROW* rows, CK_ULONG maxRows, CK_ULONG* pCount)
{
   CK_RV retCode = CKR_OK;
   CK_ULONG ulCount = 0;
   CK_SLOT_ID_PTR pList = NULL;
   CK_ULONG ulLoop;
   CK_ULONG ulFilled = 0;
   CK_TOKEN_INFO sTokenInfo;
   CK_BBOOL bOk = CK_FALSE;

   do
   {
      if ((rows == NULL) || (pCount == NULL))
      {
         break;
      }

      *pCount = 0;

      if ((maxRows == 0) || (P11Functions == NULL))
      {
         break;
      }

      /* Own C_GetSlotList allocation — do not use or free global pSlotList. */
      retCode = P11Functions->C_GetSlotList(CK_TRUE, NULL, &ulCount);
      if (retCode != CKR_OK)
      {
         break;
      }

      if (ulCount == 0)
      {
         bOk = CK_TRUE;
         break;
      }

      pList = (CK_SLOT_ID_PTR)calloc(ulCount, sizeof(CK_SLOT_ID));
      if (pList == NULL)
      {
         break;
      }

      retCode = P11Functions->C_GetSlotList(CK_TRUE, pList, &ulCount);
      if (retCode != CKR_OK)
      {
         break;
      }

      for (ulLoop = 0; (ulLoop < ulCount) && (ulFilled < maxRows); ulLoop++)
      {
         memset(&sTokenInfo, 0, sizeof(sTokenInfo));
         memset(&rows[ulFilled], 0, sizeof(P11_SLOT_ROW));
         rows[ulFilled].slotId = pList[ulLoop];
         rows[ulFilled].bPasswordRequired = CK_TRUE;

         retCode = P11Functions->C_GetTokenInfo(pList[ulLoop], &sTokenInfo);
         if (retCode == CKR_OK)
         {
            memcpy(rows[ulFilled].label, sTokenInfo.label, P11_SLOT_LABEL_MAX);
            rows[ulFilled].label[P11_SLOT_LABEL_MAX] = 0;
            str_TruncateString(rows[ulFilled].label, P11_SLOT_LABEL_MAX);
            rows[ulFilled].label[P11_SLOT_LABEL_MAX] = 0;
            if ((sTokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) == CKF_PROTECTED_AUTHENTICATION_PATH)
            {
               rows[ulFilled].bPasswordRequired = CK_FALSE;
            }
            P11_GetSlotIdentity(pList[ulLoop], &sTokenInfo,
               rows[ulFilled].model, sizeof(rows[ulFilled].model),
               rows[ulFilled].firmware, sizeof(rows[ulFilled].firmware),
               rows[ulFilled].software, sizeof(rows[ulFilled].software),
               rows[ulFilled].serial, sizeof(rows[ulFilled].serial));
         }

         ulFilled++;
      }

      *pCount = ulFilled;
      bOk = CK_TRUE;
   } while (FALSE);

   if (pList != NULL)
   {
      free(pList);
   }

   return bOk;
}

static CK_BBOOL s_bObjQueryOpen = CK_FALSE;
static CK_BBOOL s_bObjHavePeek = CK_FALSE;
static CK_OBJECT_HANDLE s_hObjPeek = 0;

static void P11_FillObjectRow(CK_OBJECT_HANDLE hObj, P11_OBJECT_ROW* pRow)
{
   CK_OBJECT_CLASS ckclass = 0;
   CK_KEY_TYPE keyType = 0;
   CK_BYTE labelBuf[P11_OBJECT_LABEL_MAX + 1];
   CK_ATTRIBUTE sClassLabel[2];
   CK_ATTRIBUTE sKeyType[1];

   memset(pRow, 0, sizeof(P11_OBJECT_ROW));
   pRow->handle = hObj;
   pRow->keyType = P11_KEY_TYPE_NONE;

   memset(labelBuf, 0, sizeof(labelBuf));
   sClassLabel[0].type = CKA_CLASS;
   sClassLabel[0].pValue = &ckclass;
   sClassLabel[0].usValueLen = sizeof(CK_OBJECT_CLASS);
   sClassLabel[1].type = CKA_LABEL;
   sClassLabel[1].pValue = labelBuf;
   sClassLabel[1].usValueLen = P11_OBJECT_LABEL_MAX;

   if (P11Functions->C_GetAttributeValue(hSession, hObj, sClassLabel, 2) != CKR_OK)
   {
      return;
   }

   pRow->ckClass = ckclass;
   if ((sClassLabel[1].usValueLen != (CK_ULONG)-1) &&
      (sClassLabel[1].usValueLen <= P11_OBJECT_LABEL_MAX))
   {
      memcpy(pRow->label, labelBuf, sClassLabel[1].usValueLen);
      pRow->label[sClassLabel[1].usValueLen] = 0;
      str_TruncateString(pRow->label, P11_OBJECT_LABEL_MAX);
      pRow->label[P11_OBJECT_LABEL_MAX] = 0;
   }

   if ((ckclass == CKO_PUBLIC_KEY) || (ckclass == CKO_PRIVATE_KEY) || (ckclass == CKO_SECRET_KEY))
   {
      sKeyType[0].type = CKA_KEY_TYPE;
      sKeyType[0].pValue = &keyType;
      sKeyType[0].usValueLen = sizeof(CK_KEY_TYPE);
      if (P11Functions->C_GetAttributeValue(hSession, hObj, sKeyType, 1) == CKR_OK)
      {
         pRow->keyType = keyType;
      }
   }
}

/*
    FUNCTION:        void P11_QueryObjectsClose(void)
*/
void P11_QueryObjectsClose(void)
{
   if ((s_bObjQueryOpen == CK_TRUE) && (P11Functions != NULL) && (hSession != 0))
   {
      P11Functions->C_FindObjectsFinal(hSession);
   }
   s_bObjQueryOpen = CK_FALSE;
   s_bObjHavePeek = CK_FALSE;
   s_hObjPeek = 0;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryObjectsOpen(void)
*/
CK_BBOOL P11_QueryObjectsOpen(void)
{
   CK_RV retCode;

   P11_QueryObjectsClose();

   if ((P11Functions == NULL) || (hSession == 0))
   {
      return CK_FALSE;
   }

   retCode = P11Functions->C_FindObjectsInit(hSession, NULL, 0);
   if (retCode != CKR_OK)
   {
      return CK_FALSE;
   }

   s_bObjQueryOpen = CK_TRUE;
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryObjectsNext(...)
*/
CK_BBOOL P11_QueryObjectsNext(P11_OBJECT_ROW* rows, CK_ULONG maxRows, CK_ULONG* pCount, CK_BBOOL* pHasMore)
{
   CK_OBJECT_HANDLE hBatch[P11_OBJECT_FIND_BATCH];
   CK_ULONG ulFilled = 0;
   CK_ULONG ulAsk;
   CK_ULONG ulGot;
   CK_ULONG ulLoop;
   CK_RV retCode = CKR_OK;
   CK_BBOOL bHasMore = CK_FALSE;

   if (pHasMore != NULL)
   {
      *pHasMore = CK_FALSE;
   }
   if ((rows == NULL) || (pCount == NULL))
   {
      return CK_FALSE;
   }

   *pCount = 0;

   if ((maxRows == 0) || (s_bObjQueryOpen != CK_TRUE) || (P11Functions == NULL) || (hSession == 0))
   {
      return CK_TRUE;
   }

   if (s_bObjHavePeek == CK_TRUE)
   {
      P11_FillObjectRow(s_hObjPeek, &rows[ulFilled]);
      ulFilled++;
      s_bObjHavePeek = CK_FALSE;
      s_hObjPeek = 0;
   }

   while (ulFilled < maxRows)
   {
      ulAsk = maxRows - ulFilled;
      if (ulAsk > P11_OBJECT_FIND_BATCH)
      {
         ulAsk = P11_OBJECT_FIND_BATCH;
      }
      ulGot = 0;
      memset(hBatch, 0, sizeof(hBatch));
      retCode = P11Functions->C_FindObjects(hSession, hBatch, ulAsk, &ulGot);
      if ((retCode != CKR_OK) || (ulGot == 0))
      {
         break;
      }

      for (ulLoop = 0; ulLoop < ulGot; ulLoop++)
      {
         P11_FillObjectRow(hBatch[ulLoop], &rows[ulFilled]);
         ulFilled++;
      }

      if (ulGot < ulAsk)
      {
         break;
      }
   }

   if ((retCode != CKR_OK) && (ulFilled == 0))
   {
      return CK_FALSE;
   }

   if ((ulFilled == maxRows) && (retCode == CKR_OK))
   {
      ulGot = 0;
      s_hObjPeek = 0;
      retCode = P11Functions->C_FindObjects(hSession, &s_hObjPeek, 1, &ulGot);
      if ((retCode == CKR_OK) && (ulGot > 0))
      {
         s_bObjHavePeek = CK_TRUE;
         bHasMore = CK_TRUE;
      }
   }

   *pCount = ulFilled;
   if (pHasMore != NULL)
   {
      *pHasMore = bHasMore;
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryObjects(...)
*/
CK_BBOOL P11_QueryObjects(P11_OBJECT_ROW* rows, CK_ULONG maxRows, CK_LONG lLimit, CK_ULONG* pCount)
{
   CK_ULONG ulWant = maxRows;
   CK_BBOOL bOk;

   if ((lLimit != CK_NULL_ELEMENT) && (lLimit >= 0) && ((CK_ULONG)lLimit < ulWant))
   {
      ulWant = (CK_ULONG)lLimit;
   }

   if (P11_QueryObjectsOpen() != CK_TRUE)
   {
      return CK_FALSE;
   }

   bOk = P11_QueryObjectsNext(rows, ulWant, pCount, NULL);
   P11_QueryObjectsClose();
   return bOk;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryDestroyObject(CK_OBJECT_HANDLE hObj, CK_RV* pRv)
*/
CK_BBOOL P11_QueryDestroyObject(CK_OBJECT_HANDLE hObj, CK_RV* pRv)
{
   CK_RV retCode;

   if (pRv != NULL)
   {
      *pRv = CKR_GENERAL_ERROR;
   }
   if ((P11Functions == NULL) || (hSession == 0))
   {
      return CK_FALSE;
   }

   retCode = P11Functions->C_DestroyObject(hSession, hObj);
   if (pRv != NULL)
   {
      *pRv = retCode;
   }
   return (retCode == CKR_OK) ? CK_TRUE : CK_FALSE;
}

static CK_BBOOL P11_QueryAttrRaw(CK_OBJECT_HANDLE hObj, CK_ATTRIBUTE_TYPE type,
   CK_BYTE** ppData, CK_ULONG* pLen, CK_RV* pRv)
{
   CK_ATTRIBUTE attr;
   CK_RV retCode;
   CK_BYTE_PTR pBuf = NULL;

   if (ppData != NULL)
   {
      *ppData = NULL;
   }
   if (pLen != NULL)
   {
      *pLen = 0;
   }
   if (pRv != NULL)
   {
      *pRv = CKR_GENERAL_ERROR;
   }
   if ((P11Functions == NULL) || (hSession == 0))
   {
      return CK_FALSE;
   }

   memset(&attr, 0, sizeof(attr));
   attr.type = type;
   attr.pValue = NULL;
   attr.usValueLen = 0;
   retCode = P11Functions->C_GetAttributeValue(hSession, hObj, &attr, 1);
   if (pRv != NULL)
   {
      *pRv = retCode;
   }
   if ((retCode != CKR_OK) && (retCode != CKR_BUFFER_TOO_SMALL))
   {
      return CK_FALSE;
   }
   if (attr.usValueLen == (CK_ULONG)-1)
   {
      return CK_FALSE;
   }
   if (attr.usValueLen == 0)
   {
      return CK_TRUE;
   }

   pBuf = (CK_BYTE_PTR)malloc((size_t)attr.usValueLen + 1);
   if (pBuf == NULL)
   {
      if (pRv != NULL)
      {
         *pRv = CKR_HOST_MEMORY;
      }
      return CK_FALSE;
   }
   memset(pBuf, 0, (size_t)attr.usValueLen + 1);
   attr.pValue = pBuf;
   retCode = P11Functions->C_GetAttributeValue(hSession, hObj, &attr, 1);
   if (pRv != NULL)
   {
      *pRv = retCode;
   }
   if ((retCode != CKR_OK) || (attr.usValueLen == (CK_ULONG)-1))
   {
      free(pBuf);
      return CK_FALSE;
   }
   if (ppData != NULL)
   {
      *ppData = pBuf;
   }
   else
   {
      free(pBuf);
   }
   if (pLen != NULL)
   {
      *pLen = attr.usValueLen;
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryAttrBool(...)
*/
CK_BBOOL P11_QueryAttrBool(CK_OBJECT_HANDLE hObj, CK_ATTRIBUTE_TYPE type, CK_BBOOL* pVal)
{
   CK_BYTE* pData = NULL;
   CK_ULONG ulLen = 0;
   CK_BBOOL bOk;

   if (pVal != NULL)
   {
      *pVal = CK_FALSE;
   }
   bOk = P11_QueryAttrRaw(hObj, type, &pData, &ulLen, NULL);
   if ((bOk == CK_TRUE) && (pData != NULL) && (ulLen >= 1) && (pVal != NULL))
   {
      *pVal = pData[0] ? CK_TRUE : CK_FALSE;
   }
   if (pData != NULL)
   {
      free(pData);
   }
   return bOk;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryAttrUlong(...)
*/
CK_BBOOL P11_QueryAttrUlong(CK_OBJECT_HANDLE hObj, CK_ATTRIBUTE_TYPE type, CK_ULONG* pVal)
{
   CK_BYTE* pData = NULL;
   CK_ULONG ulLen = 0;
   CK_BBOOL bOk;
   CK_ULONG ulValue = 0;

   if (pVal != NULL)
   {
      *pVal = 0;
   }
   bOk = P11_QueryAttrRaw(hObj, type, &pData, &ulLen, NULL);
   if ((bOk == CK_TRUE) && (pData != NULL) && (pVal != NULL))
   {
      if (ulLen >= sizeof(CK_ULONG))
      {
         memcpy(&ulValue, pData, sizeof(CK_ULONG));
         *pVal = ulValue;
      }
      else if (ulLen >= 4)
      {
         unsigned int u32 = 0;
         memcpy(&u32, pData, 4);
         *pVal = (CK_ULONG)u32;
      }
      else
      {
         bOk = CK_FALSE;
      }
   }
   else
   {
      bOk = CK_FALSE;
   }
   if (pData != NULL)
   {
      free(pData);
   }
   return bOk;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryAttrBytes(...)
*/
CK_BBOOL P11_QueryAttrBytes(CK_OBJECT_HANDLE hObj, CK_ATTRIBUTE_TYPE type,
   CK_BYTE** ppData, CK_ULONG* pLen, CK_RV* pRv)
{
   return P11_QueryAttrRaw(hObj, type, ppData, pLen, pRv);
}

/*
    FUNCTION:        CK_BBOOL P11_QueryCreateDO(...)
*/
CK_BBOOL P11_QueryCreateDO(P11_DOTEMPLATE* pTpl, CK_OBJECT_HANDLE* pHandle, CK_RV* pRv)
{
   CK_RV retCode;
   CK_OBJECT_CLASS cClass = CKO_DATA;
   CK_OBJECT_HANDLE hObj = 0;
   CK_ULONG uAppLen = 0;
   CK_ULONG uLabelLen = 0;
   CK_ULONG uValLen = 0;
   CK_CHAR_PTR pApp;
   CK_CHAR_PTR pVal;
   CK_CHAR szEmpty[1] = { 0 };
   CK_ATTRIBUTE attrs[7];

   if (pHandle != NULL)
   {
      *pHandle = 0;
   }
   if (pRv != NULL)
   {
      *pRv = CKR_GENERAL_ERROR;
   }
   if ((P11Functions == NULL) || (hSession == 0) || (pTpl == NULL) ||
      (pTpl->pLabel == NULL) || (pTpl->pLabel[0] == 0))
   {
      return CK_FALSE;
   }

   uLabelLen = (CK_ULONG)strlen((const char*)pTpl->pLabel);
   pApp = pTpl->pApplication;
   if (pApp == NULL)
   {
      pApp = szEmpty;
      uAppLen = 0;
   }
   else
   {
      uAppLen = (CK_ULONG)strlen((const char*)pApp);
   }
   pVal = pTpl->pValue;
   if ((pTpl->upValueLength > 0) && (pVal != NULL))
   {
      uValLen = (CK_ULONG)pTpl->upValueLength;
   }
   else
   {
      pVal = szEmpty;
      uValLen = 0;
   }

   memset(attrs, 0, sizeof(attrs));
   attrs[0].type = CKA_CLASS;
   attrs[0].pValue = &cClass;
   attrs[0].usValueLen = sizeof(cClass);
   attrs[1].type = CKA_TOKEN;
   attrs[1].pValue = &pTpl->bCKA_Token;
   attrs[1].usValueLen = sizeof(CK_BBOOL);
   attrs[2].type = CKA_PRIVATE;
   attrs[2].pValue = &pTpl->bCKA_Private;
   attrs[2].usValueLen = sizeof(CK_BBOOL);
   attrs[3].type = CKA_MODIFIABLE;
   attrs[3].pValue = &pTpl->bCKA_Modifiable;
   attrs[3].usValueLen = sizeof(CK_BBOOL);
   attrs[4].type = CKA_LABEL;
   attrs[4].pValue = pTpl->pLabel;
   attrs[4].usValueLen = uLabelLen;
   attrs[5].type = CKA_APPLICATION;
   attrs[5].pValue = pApp;
   attrs[5].usValueLen = uAppLen;
   attrs[6].type = CKA_VALUE;
   attrs[6].pValue = pVal;
   attrs[6].usValueLen = uValLen;

   retCode = P11Functions->C_CreateObject(hSession, attrs, 7, &hObj);
   if (pRv != NULL)
   {
      *pRv = retCode;
   }
   if (retCode != CKR_OK)
   {
      return CK_FALSE;
   }
   if (pHandle != NULL)
   {
      *pHandle = hObj;
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryDigestKey(...)
*/
CK_BBOOL P11_QueryDigestKey(CK_OBJECT_HANDLE hKey, P11_HASH_MECH* sHash,
   CK_BYTE** ppDigest, CK_ULONG* pLen, CK_RV* pRv)
{
   CK_RV retCode = CKR_GENERAL_ERROR;
   CK_MECHANISM sMech;
   CK_BYTE buf[128];
   CK_ULONG ulLen = sizeof(buf);
   CK_ULONG ulClass = 0;
   CK_BYTE* pOut = NULL;

   if (ppDigest != NULL)
   {
      *ppDigest = NULL;
   }
   if (pLen != NULL)
   {
      *pLen = 0;
   }
   if (pRv != NULL)
   {
      *pRv = CKR_GENERAL_ERROR;
   }
   if ((P11Functions == NULL) || (hSession == 0) || (sHash == NULL) || (hKey == 0))
   {
      return CK_FALSE;
   }

   if (P11_QueryAttrUlong(hKey, CKA_CLASS, &ulClass) != CK_TRUE)
   {
      if (pRv != NULL)
      {
         *pRv = CKR_OBJECT_HANDLE_INVALID;
      }
      return CK_FALSE;
   }
   if (ulClass != CKO_SECRET_KEY)
   {
      if (pRv != NULL)
      {
         *pRv = CKR_KEY_TYPE_INCONSISTENT;
      }
      return CK_FALSE;
   }

   memset(&sMech, 0, sizeof(sMech));
   sMech.mechanism = sHash->ckMechType;
   retCode = P11Functions->C_DigestInit(hSession, &sMech);
   if (retCode != CKR_OK)
   {
      if (pRv != NULL)
      {
         *pRv = retCode;
      }
      return CK_FALSE;
   }

   retCode = P11Functions->C_DigestKey(hSession, hKey);
   if (retCode != CKR_OK)
   {
      if (pRv != NULL)
      {
         *pRv = retCode;
      }
      return CK_FALSE;
   }

   memset(buf, 0, sizeof(buf));
   retCode = P11Functions->C_DigestFinal(hSession, buf, &ulLen);
   if (pRv != NULL)
   {
      *pRv = retCode;
   }
   if (retCode != CKR_OK)
   {
      return CK_FALSE;
   }

   pOut = (CK_BYTE*)malloc((ulLen > 0) ? (size_t)ulLen : 1);
   if (pOut == NULL)
   {
      if (pRv != NULL)
      {
         *pRv = CKR_HOST_MEMORY;
      }
      return CK_FALSE;
   }
   if (ulLen > 0)
   {
      memcpy(pOut, buf, (size_t)ulLen);
   }
   if (ppDigest != NULL)
   {
      *ppDigest = pOut;
   }
   else
   {
      free(pOut);
   }
   if (pLen != NULL)
   {
      *pLen = ulLen;
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryComputeKCV(...)
*/
CK_BBOOL P11_QueryComputeKCV(CK_OBJECT_HANDLE hKey, BYTE bMethod,
   CK_BYTE** ppKcv, CK_ULONG* pLen, CK_RV* pRv)
{
   CK_CHAR_PTR pBuf = NULL;
   CK_ULONG ulClass = 0;
   CK_ULONG ulType = 0;
   CK_BYTE* pOut = NULL;

   if (ppKcv != NULL)
   {
      *ppKcv = NULL;
   }
   if (pLen != NULL)
   {
      *pLen = 0;
   }
   if (pRv != NULL)
   {
      *pRv = CKR_GENERAL_ERROR;
   }
   if ((P11Functions == NULL) || (hSession == 0) || (hKey == 0) || (bMethod == 0))
   {
      if ((bMethod == 0) && (pRv != NULL))
      {
         *pRv = CKR_ARGUMENTS_BAD;
      }
      return CK_FALSE;
   }

   if (P11_QueryAttrUlong(hKey, CKA_CLASS, &ulClass) != CK_TRUE)
   {
      if (pRv != NULL)
      {
         *pRv = CKR_OBJECT_HANDLE_INVALID;
      }
      return CK_FALSE;
   }
   if (ulClass != CKO_SECRET_KEY)
   {
      if (pRv != NULL)
      {
         *pRv = CKR_KEY_TYPE_INCONSISTENT;
      }
      return CK_FALSE;
   }

   if (P11_QueryAttrUlong(hKey, CKA_KEY_TYPE, &ulType) == CK_TRUE)
   {
      switch (ulType)
      {
      case CKK_AES:
      case CKK_DES:
      case CKK_DES2:
      case CKK_DES3:
      case CKK_GENERIC_SECRET:
         break;
      default:
         if (pRv != NULL)
         {
            *pRv = CKR_KEY_TYPE_INCONSISTENT;
         }
         return CK_FALSE;
      }
   }

   if ((P11_ComputeKCV(bMethod, hKey, &pBuf) != CK_TRUE) || (pBuf == NULL))
   {
      if (pRv != NULL)
      {
         *pRv = CKR_FUNCTION_FAILED;
      }
      if (pBuf != NULL)
      {
         free(pBuf);
      }
      return CK_FALSE;
   }

   pOut = (CK_BYTE*)malloc(3);
   if (pOut == NULL)
   {
      free(pBuf);
      if (pRv != NULL)
      {
         *pRv = CKR_HOST_MEMORY;
      }
      return CK_FALSE;
   }
   memcpy(pOut, pBuf, 3);
   free(pBuf);

   if (ppKcv != NULL)
   {
      *ppKcv = pOut;
   }
   else
   {
      free(pOut);
   }
   if (pLen != NULL)
   {
      *pLen = 3;
   }
   if (pRv != NULL)
   {
      *pRv = CKR_OK;
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryCapabilities(...)
*/
CK_BBOOL P11_QueryCapabilities(CK_SLOT_ID slotId, P11_CAP_ROW* rows,
   CK_ULONG maxRows, CK_ULONG* pCount, CK_RV* pRv)
{
   CK_RV retCode = CKR_GENERAL_ERROR;
   CK_SLOT_INFO sSlotInfo;
   CK_MECHANISM_INFO sInfo;
   CK_ULONG ulMechCount;
   CK_ULONG ulLoop;
   CK_ULONG ulFilled = 0;
   CK_CHAR_PTR pName = NULL;
   CK_KEY_TYPE keyType = 0;
   CK_MECHANISM_TYPE mech = 0;

   if (pCount != NULL)
   {
      *pCount = 0;
   }
   if (pRv != NULL)
   {
      *pRv = CKR_GENERAL_ERROR;
   }
   if ((P11Functions == NULL) || (rows == NULL) || (maxRows == 0))
   {
      return CK_FALSE;
   }

   memset(&sSlotInfo, 0, sizeof(sSlotInfo));
   retCode = P11Functions->C_GetSlotInfo(slotId, &sSlotInfo);
   if (pRv != NULL)
   {
      *pRv = retCode;
   }
   if (retCode != CKR_OK)
   {
      return CK_FALSE;
   }

   ulMechCount = P11Util_GetCapMechCount();
   for (ulLoop = 0; (ulLoop < ulMechCount) && (ulFilled < maxRows); ulLoop++)
   {
      if (P11Util_GetCapMechAt(ulLoop, &pName, &keyType, &mech) != CK_TRUE)
      {
         continue;
      }

      memset(&rows[ulFilled], 0, sizeof(rows[ulFilled]));
      if (pName != NULL)
      {
         strncpy((char*)rows[ulFilled].name, (const char*)pName, P11_CAP_NAME_MAX - 1);
      }
      rows[ulFilled].keyType = keyType;

      memset(&sInfo, 0, sizeof(sInfo));
      retCode = P11Functions->C_GetMechanismInfo(slotId, mech, &sInfo);
      if (retCode == CKR_OK)
      {
         rows[ulFilled].bSupported = CK_TRUE;
         rows[ulFilled].ulMinKeySize = sInfo.ulMinKeySize;
         rows[ulFilled].ulMaxKeySize = sInfo.ulMaxKeySize;
         if (keyType == CKK_HSS)
         {
            rows[ulFilled].bNoKeySize = CK_TRUE;
            strncpy((char*)rows[ulFilled].note,
               "Does not use key size; see LMS / LMOTS types",
               P11_CAP_NOTE_MAX - 1);
         }
      }
      else
      {
         rows[ulFilled].bSupported = CK_FALSE;
         if ((keyType == CKK_ML_DSA) || (keyType == CKK_ML_KEM))
         {
            strncpy((char*)rows[ulFilled].note,
               "Requires client 10.9.1 and firmware 7.9.1",
               P11_CAP_NOTE_MAX - 1);
         }
         else if (keyType == CKK_HSS)
         {
            strncpy((char*)rows[ulFilled].note,
               "Requires client 10.8.0 and firmware 7.8.8",
               P11_CAP_NOTE_MAX - 1);
         }
      }
      ulFilled++;
   }

   if (pCount != NULL)
   {
      *pCount = ulFilled;
   }
   if (pRv != NULL)
   {
      *pRv = CKR_OK;
   }
   return CK_TRUE;
}

static void QuerySetError(char* err, CK_ULONG errMax, const char* msg)
{
   if ((err == NULL) || (errMax == 0))
   {
      return;
   }
   memset(err, 0, errMax);
   if (msg != NULL)
   {
      strncpy(err, msg, errMax - 1);
   }
}

/* TEXT (0x10) is hexadecimal ASCII; BINARY (0x10|1) is raw bytes. Same as CLI -format. */
static CK_BBOOL QueryReadHexFile(const char* path, CK_CHAR_PTR* pBuf, CK_ULONG* pLen,
   CK_BYTE format, const char* what, char* err, CK_ULONG errMax)
{
   CK_BBOOL bBinary;
   CK_ULONG uLen;
   CK_CHAR_PTR pData = NULL;
   char sz[P11_QUERY_ERR_MAX];

   if ((pBuf == NULL) || (pLen == NULL))
   {
      QuerySetError(err, errMax, "Internal error.");
      return CK_FALSE;
   }
   *pBuf = NULL;
   *pLen = 0;
   if ((path == NULL) || (path[0] == 0))
   {
      memset(sz, 0, sizeof(sz));
      _snprintf(sz, sizeof(sz) - 1, "The %s file path is empty.", (what != NULL) ? what : "input");
      QuerySetError(err, errMax, sz);
      return CK_FALSE;
   }

   bBinary = ((format & CK_TRUE) != 0) ? CK_TRUE : CK_FALSE;
   uLen = File_Read((CK_CHAR_PTR)path, &pData, bBinary);
   if (uLen == 0)
   {
      memset(sz, 0, sizeof(sz));
      _snprintf(sz, sizeof(sz) - 1, "Cannot read the %s file.", (what != NULL) ? what : "input");
      QuerySetError(err, errMax, sz);
      return CK_FALSE;
   }
   if (bBinary == CK_FALSE)
   {
      uLen = str_StringtoByteArray(pData, uLen);
      if (uLen == 0)
      {
         free(pData);
         QuerySetError(err, errMax,
            "hex text expects even-length hexadecimal. Use binary for a raw file (for example a .txt).");
         return CK_FALSE;
      }
   }
   *pBuf = pData;
   *pLen = uLen;
   return CK_TRUE;
}

static void QueryStripHex(char* s)
{
   char* pSrc;
   char* pDst;

   if (s == NULL)
   {
      return;
   }
   pSrc = s;
   if ((pSrc[0] == '0') && ((pSrc[1] == 'x') || (pSrc[1] == 'X')))
   {
      pSrc += 2;
   }
   pDst = s;
   while (*pSrc != 0)
   {
      if ((*pSrc != ' ') && (*pSrc != '\t') && (*pSrc != '\r') && (*pSrc != '\n'))
      {
         *pDst++ = *pSrc;
      }
      pSrc++;
   }
   *pDst = 0;
}

static CK_ULONG QueryHexToBuf(const char* hex, CK_BYTE* buf, CK_ULONG bufMax)
{
   char szTmp[512];
   CK_ULONG uLen;

   if ((hex == NULL) || (hex[0] == 0) || (buf == NULL) || (bufMax == 0))
   {
      return 0;
   }
   memset(szTmp, 0, sizeof(szTmp));
   strncpy(szTmp, hex, sizeof(szTmp) - 1);
   QueryStripHex(szTmp);
   if (szTmp[0] == 0)
   {
      return 0;
   }
   uLen = str_StringtoByteArray((CK_CHAR_PTR)szTmp, (CK_ULONG)strlen(szTmp));
   if ((uLen == 0) || (uLen > bufMax))
   {
      return 0;
   }
   memcpy(buf, szTmp, (size_t)uLen);
   memset(szTmp, 0, sizeof(szTmp));
   return uLen;
}

static CK_ULONG QueryObjectSize(CK_OBJECT_HANDLE hObj)
{
   CK_ULONG ulSize = 0;

   if ((P11Functions == NULL) || (hObj == 0))
   {
      return 0;
   }
   if (P11Functions->C_GetObjectSize(hSession, hObj, &ulSize) != CKR_OK)
   {
      return 0;
   }
   return ulSize;
}

static CK_OBJECT_HANDLE QueryFindNewestByLabel(CK_OBJECT_CLASS cls, const char* label)
{
   CK_ATTRIBUTE attrs[2];
   CK_OBJECT_HANDLE found[64];
   CK_ULONG n = 0;
   CK_ULONG i;
   CK_OBJECT_HANDLE maxH = 0;
   CK_ULONG labelLen;

   if ((P11Functions == NULL) || (label == NULL) || (label[0] == 0))
   {
      return 0;
   }
   labelLen = (CK_ULONG)strlen(label);
   memset(attrs, 0, sizeof(attrs));
   attrs[0].type = CKA_CLASS;
   attrs[0].pValue = &cls;
   attrs[0].usValueLen = sizeof(cls);
   attrs[1].type = CKA_LABEL;
   attrs[1].pValue = (CK_VOID_PTR)label;
   attrs[1].usValueLen = labelLen;
   if (P11Functions->C_FindObjectsInit(hSession, attrs, 2) != CKR_OK)
   {
      return 0;
   }
   P11Functions->C_FindObjects(hSession, found, 64, &n);
   P11Functions->C_FindObjectsFinal(hSession);
   for (i = 0; i < n; i++)
   {
      if (found[i] > maxH)
      {
         maxH = found[i];
      }
   }
   return maxH;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryBuildWrapMech(...)
*/
CK_BBOOL P11_QueryBuildWrapMech(const char* algoName, CK_ULONG uFlag,
   const char* ivHex, const char* aadHex, CK_ULONG tagBits,
   const char* oaepHashName, P11_ENCRYPTION_MECH* pMech,
   CK_BYTE* ivBuf, CK_ULONG ivBufMax,
   CK_BYTE* aadBuf, CK_ULONG aadBufMax,
   char* err, CK_ULONG errMax)
{
   P11_ENCRYPTION_MECH* pSrc;
   CK_ULONG uLen;

   QuerySetError(err, errMax, "");
   if ((pMech == NULL) || (algoName == NULL) || (algoName[0] == 0))
   {
      QuerySetError(err, errMax, "Missing wrap algorithm.");
      return CK_FALSE;
   }

   pSrc = P11Util_GetEncryptionParam((CK_CHAR_PTR)algoName, uFlag);
   if (pSrc == NULL)
   {
      QuerySetError(err, errMax, "Unknown wrap algorithm.");
      return CK_FALSE;
   }
   memcpy(pMech, pSrc, sizeof(*pMech));

   switch (pMech->ckMechType)
   {
   case CKM_AES_ECB:
   case CKM_AES_KW:
   case CKM_AES_KWP:
      return CK_TRUE;

   case CKM_AES_CBC:
   case CKM_AES_CBC_PAD:
   case CKM_AES_CBC_PAD_IPSEC:
   case CKM_AES_CFB8:
   case CKM_AES_CFB128:
   case CKM_AES_OFB:
      if ((ivHex != NULL) && (ivHex[0] != 0))
      {
         if ((ivBuf == NULL) || (ivBufMax < AES_IV_LENGTH))
         {
            QuerySetError(err, errMax, "IV buffer too small.");
            return CK_FALSE;
         }
         uLen = QueryHexToBuf(ivHex, ivBuf, ivBufMax);
         if (uLen != AES_IV_LENGTH)
         {
            QuerySetError(err, errMax, "IV must be 16 bytes of hex.");
            return CK_FALSE;
         }
         pMech->aes_param.pIv = (CK_CHAR_PTR)ivBuf;
      }
      return CK_TRUE;

   case CKM_AES_GCM:
      if ((ivHex != NULL) && (ivHex[0] != 0))
      {
         if ((ivBuf == NULL) || (ivBufMax < AES_GCM_IV_MIN_LENGTH))
         {
            QuerySetError(err, errMax, "IV buffer too small.");
            return CK_FALSE;
         }
         uLen = QueryHexToBuf(ivHex, ivBuf, ivBufMax);
         if (uLen < AES_GCM_IV_MIN_LENGTH)
         {
            QuerySetError(err, errMax, "GCM IV must be at least 12 bytes of hex.");
            return CK_FALSE;
         }
         pMech->aes_gcm_param.pIv = (CK_CHAR_PTR)ivBuf;
         pMech->aes_gcm_param.ulIvLen = uLen;
         pMech->aes_gcm_param.ulIvBits = uLen << 3;
      }
      if ((aadHex != NULL) && (aadHex[0] != 0))
      {
         if ((aadBuf == NULL) || (aadBufMax == 0))
         {
            QuerySetError(err, errMax, "AAD buffer too small.");
            return CK_FALSE;
         }
         uLen = QueryHexToBuf(aadHex, aadBuf, aadBufMax);
         if (uLen == 0)
         {
            QuerySetError(err, errMax, "AAD must be hexadecimal.");
            return CK_FALSE;
         }
         pMech->aes_gcm_param.pAAD = (CK_CHAR_PTR)aadBuf;
         pMech->aes_gcm_param.ulAADLen = uLen;
      }
      if (tagBits != 0)
      {
         pMech->aes_gcm_param.ulTagBits = tagBits;
      }
      return CK_TRUE;

   case CKM_RSA_PKCS_OAEP:
      if (pMech->rsa_oeap_param.hashAlg == 0)
      {
         P11_HASH_MECH* pHash;

         if ((oaepHashName == NULL) || (oaepHashName[0] == 0))
         {
            QuerySetError(err, errMax, "Select an OAEP hash.");
            return CK_FALSE;
         }
         pHash = P11Util_GetHash((CK_CHAR_PTR)oaepHashName, KEY_TYPE_IMPORT_EXPORTKEY);
         if (pHash == NULL)
         {
            QuerySetError(err, errMax, "Unknown OAEP hash.");
            return CK_FALSE;
         }
         pMech->rsa_oeap_param.hashAlg = pHash->ckMechType;
         pMech->rsa_oeap_param.mgf = pHash->ckMechOaepMgfType;
         pMech->rsa_oeap_param.source = CKZ_DATA_SPECIFIED;
      }
      return CK_TRUE;

   default:
      return CK_TRUE;
   }
}

/*
    FUNCTION:        CK_BBOOL P11_QueryBuildPbeMech(...)
*/
CK_BBOOL P11_QueryBuildPbeMech(const char* algoName, const char* password,
   const char* saltHex, CK_LONG iterations, const char* ivHex,
   P11_ENCRYPTION_MECH* pMech, char* err, CK_ULONG errMax)
{
   P11_ENCRYPTION_MECH* pSrc;
   CK_ULONG uLen;

   QuerySetError(err, errMax, "");
   if ((pMech == NULL) || (algoName == NULL) || (algoName[0] == 0))
   {
      QuerySetError(err, errMax, "Missing PBE algorithm.");
      return CK_FALSE;
   }
   if ((password == NULL) || (password[0] == 0))
   {
      QuerySetError(err, errMax, "Password is required for PKCS#8.");
      return CK_FALSE;
   }

   pSrc = P11Util_GetEncryptionParam((CK_CHAR_PTR)algoName, KEY_TYPE_PBE);
   if (pSrc == NULL)
   {
      QuerySetError(err, errMax, "Unknown PBE algorithm.");
      return CK_FALSE;
   }
   memcpy(pMech, pSrc, sizeof(*pMech));
   pMech->pbe_param.ckPbeMechType = CKM_PKCS5_PBKD2;
   pMech->ckMechType = pSrc->pbe_param.ckEncMechType;
   pMech->pbe_param.sEncClass = pSrc->pbe_param.sEncClass;
   pMech->pbe_param.ckEncMechType = pSrc->pbe_param.ckEncMechType;
   pMech->pbe_param.sEnckeyType = pSrc->pbe_param.sEnckeyType;
   pMech->pbe_param.sEnckeySize = pSrc->pbe_param.sEnckeySize;
   pMech->pbe_param.pbkdf2.pbfkd2_param.prf = pSrc->pbe_param.pbkdf2.pbfkd2_param.prf;
   pMech->pbe_param.ulIvLen = pSrc->pbe_param.ulIvLen;

   if (iterations < 0)
   {
      pMech->pbe_param.pbkdf2.pbfkd2_param.iterations = PBFKD2_DEFAULT_ITERATION;
   }
   else
   {
      pMech->pbe_param.pbkdf2.pbfkd2_param.iterations = (CK_ULONG)iterations;
   }

   if ((saltHex == NULL) || (saltHex[0] == 0))
   {
      P11_GenerateRandom((CK_BYTE_PTR)pMech->pbe_param.pbkdf2.sSalt, PBFKD2_SALT_LENGTH);
      pMech->pbe_param.pbkdf2.pbfkd2_param.pSaltSourceData = (CK_BYTE_PTR)pMech->pbe_param.pbkdf2.sSalt;
      pMech->pbe_param.pbkdf2.pbfkd2_param.ulSaltSourceDataLen = PBFKD2_SALT_LENGTH;
   }
   else
   {
      uLen = QueryHexToBuf(saltHex, (CK_BYTE*)pMech->pbe_param.pbkdf2.sSalt, PBFKD2_SALT_LENGTH);
      if (uLen == 0)
      {
         QuerySetError(err, errMax, "Salt must be hexadecimal.");
         return CK_FALSE;
      }
      pMech->pbe_param.pbkdf2.pbfkd2_param.pSaltSourceData = (CK_BYTE_PTR)pMech->pbe_param.pbkdf2.sSalt;
      pMech->pbe_param.pbkdf2.pbfkd2_param.ulSaltSourceDataLen = uLen;
   }
   pMech->pbe_param.pbkdf2.pbfkd2_param.saltSource = CKZ_SALT_SPECIFIED;
   pMech->pbe_param.pbkdf2.pbfkd2_param.pPassword = (CK_CHAR_PTR)password;
   pMech->pbe_param.pbkdf2.pbfkd2_param.usPasswordLen = (CK_ULONG)strlen(password);

   if ((ivHex == NULL) || (ivHex[0] == 0))
   {
      P11_GenerateRandom((CK_BYTE_PTR)pMech->pbe_param.pbkdf2.sIV, pMech->pbe_param.ulIvLen);
      pMech->pbe_param.pIv = (CK_CHAR_PTR)pMech->pbe_param.pbkdf2.sIV;
   }
   else
   {
      uLen = QueryHexToBuf(ivHex, (CK_BYTE*)pMech->pbe_param.pbkdf2.sIV, AES_IV_LENGTH);
      if (uLen != pMech->pbe_param.ulIvLen)
      {
         QuerySetError(err, errMax, "PBE IV must be 16 bytes of hex.");
         return CK_FALSE;
      }
      pMech->pbe_param.pIv = (CK_CHAR_PTR)pMech->pbe_param.pbkdf2.sIV;
   }

   return CK_TRUE;
}

static CK_BBOOL QueryExportPublic(P11_WRAPTEMPLATE* pTpl, const char* path, CK_BYTE format,
   CK_ULONG* pWritten, char* err, CK_ULONG errMax)
{
   PUBLIC_KEY sPublicKey;
   CK_LONG writtenSize = 0;
   CK_BBOOL bBuilt = CK_FALSE;

   memset(&sPublicKey, 0, sizeof(sPublicKey));
   switch (pTpl->skeyType)
   {
   case CKK_RSA:
      if (P11_GetRsaPublicKey(pTpl->hKeyToExport, &sPublicKey.sRsaPublicKey) == CK_TRUE)
      {
         bBuilt = pksc8_Build_PublicKeyInfoRSA(&sPublicKey.sRsaPublicKey);
      }
      break;
   case CKK_DSA:
      if (P11_GetDsaPublicKey(pTpl->hKeyToExport, &sPublicKey.sDsaPublicKey) == CK_TRUE)
      {
         bBuilt = pksc8_Build_PublicKeyInfoDSA(&sPublicKey.sDsaPublicKey);
      }
      break;
   case CKK_DH:
   case CKK_X9_42_DH:
      if (P11_GetDHPublicKey(pTpl->hKeyToExport, &sPublicKey.sDhPublicKey, pTpl->skeyType) == CK_TRUE)
      {
         bBuilt = pksc8_Build_PublicKeyInfoDH(&sPublicKey.sDhPublicKey);
      }
      break;
   case CKK_ECDSA:
   case CKK_EC_EDWARDS:
   case CKK_EC_EDWARDS_OLD:
   case CKK_EC_MONTGOMERY:
   case CKK_EC_MONTGOMERY_OLD:
   case CKK_SM2:
      if (P11_GetEccPublicKey(pTpl->hKeyToExport, &sPublicKey.sEcPublicKey, pTpl->skeyType) == CK_TRUE)
      {
         bBuilt = pksc8_Build_PublicKeyInfoEC(&sPublicKey.sEcPublicKey, pTpl->skeyType);
      }
      break;
   case CKK_ML_DSA:
      if (P11_GetMLDSAPublicKey(pTpl->hKeyToExport, &sPublicKey.sMlDsaPublicKey) == CK_TRUE)
      {
         bBuilt = pksc8_Build_PublicKeyInfoMLDSA(&sPublicKey.sMlDsaPublicKey);
      }
      break;
   case CKK_ML_KEM:
      if (P11_GetMLKEMPublicKey(pTpl->hKeyToExport, &sPublicKey.sMlKemPublicKey) == CK_TRUE)
      {
         bBuilt = pksc8_Build_PublicKeyInfoMLKEM(&sPublicKey.sMlKemPublicKey);
      }
      break;
   case CKK_HSS:
      if (P11_GetLMSPublicKey(pTpl->hKeyToExport, &sPublicKey.sLmsPublicKey) == CK_TRUE)
      {
         bBuilt = pksc8_Build_PublicKeyInfoLMS(&sPublicKey.sLmsPublicKey);
      }
      break;
   default:
      QuerySetError(err, errMax, "This public key type cannot be exported.");
      return CK_FALSE;
   }

   if (bBuilt != CK_TRUE)
   {
      QuerySetError(err, errMax, "Failed to read or encode the public key.");
      return CK_FALSE;
   }

   if (format == P11_FILE_FORMAT_TEXT)
   {
      CK_CHAR_PTR buffer = str_ByteArraytoString(asn1_BuildGetBuffer(), (CK_LONG)asn1_GetBufferSize());
      if (buffer == NULL)
      {
         QuerySetError(err, errMax, "Failed to encode public key as text.");
         return CK_FALSE;
      }
      writtenSize = File_Write((CK_CHAR_PTR)path, buffer, (CK_ULONG)strlen((char*)buffer), CK_FALSE);
      free(buffer);
   }
   else if (format == P11_FILE_FORMAT_BINARY)
   {
      writtenSize = File_Write((CK_CHAR_PTR)path, asn1_BuildGetBuffer(), asn1_GetBufferSize(), CK_TRUE);
   }
   else if (format == P11_FILE_FORMAT_PKCS8)
   {
      CK_CHAR_PTR buffer = pkcs8_EncodePublicKeyToPem(asn1_BuildGetBuffer(), asn1_GetBufferSize());
      if (buffer == NULL)
      {
         QuerySetError(err, errMax, "Failed to encode public key as PKCS#8.");
         return CK_FALSE;
      }
      writtenSize = File_Write((CK_CHAR_PTR)path, buffer, (CK_ULONG)strlen((char*)buffer), CK_FALSE);
      free(buffer);
   }
   else
   {
      QuerySetError(err, errMax, "Unsupported export format for a public key.");
      return CK_FALSE;
   }

   if (writtenSize <= 0)
   {
      QuerySetError(err, errMax, "Failed to write the export file.");
      return CK_FALSE;
   }
   if (pWritten != NULL)
   {
      *pWritten = (CK_ULONG)writtenSize;
   }
   return CK_TRUE;
}

static CK_BBOOL QueryWrapPrivateSecret(P11_WRAPTEMPLATE* pTpl, const char* path, CK_BYTE format,
   CK_ULONG* pWritten, char* err, CK_ULONG errMax)
{
   CK_ULONG ulKeySize;
   CK_ULONG ulWrapSize;
   CK_ULONG ulAlloc;
   CK_BYTE_PTR pBuf = NULL;
   CK_BBOOL bResult = CK_FALSE;
   P11_KEYGENTEMPLATE sKeyGen;
   CK_LONG writtenSize = 0;

   memset(&sKeyGen, 0, sizeof(sKeyGen));

   if (!((format == P11_FILE_FORMAT_TEXT) || (format == P11_FILE_FORMAT_BINARY) ||
      (format == P11_FILE_FORMAT_PKCS8)))
   {
      QuerySetError(err, errMax, "Unsupported wrap file format.");
      return CK_FALSE;
   }

   if (pTpl->bPbe == CK_TRUE)
   {
      if (pTpl->wrap_key_mech == NULL)
      {
         QuerySetError(err, errMax, "Missing PBE algorithm.");
         return CK_FALSE;
      }
      sKeyGen.sClass = pTpl->wrap_key_mech->pbe_param.sEncClass;
      sKeyGen.skeyType = pTpl->wrap_key_mech->pbe_param.sEnckeyType;
      sKeyGen.skeySize = pTpl->wrap_key_mech->pbe_param.sEnckeySize;
      sKeyGen.bCKA_Wrap = CK_TRUE;
      sKeyGen.bCKA_Unwrap = CK_TRUE;
      sKeyGen.pKeyLabel = "pbe_temp";
      sKeyGen.bCKA_Private = CK_TRUE;
      sKeyGen.bCKA_Sensitive = CK_TRUE;
      sKeyGen.bCKA_Token = CK_FALSE;
      if (P11_GenerateKeyPbe(&sKeyGen, &pTpl->hWrappingKey, &pTpl->wrap_key_mech->pbe_param, CK_FALSE) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Failed to generate the PBE wrapping key.");
         return CK_FALSE;
      }
   }

   do
   {
      ulKeySize = QueryObjectSize(pTpl->hKeyToExport);
      ulWrapSize = QueryObjectSize(pTpl->hWrappingKey);
      ulAlloc = MAX(ulKeySize, ulWrapSize);
      if (ulAlloc < 512)
      {
         ulAlloc = 512;
      }
      ulAlloc += 4096;
      pBuf = (CK_BYTE_PTR)malloc((size_t)ulAlloc);
      if (pBuf == NULL)
      {
         QuerySetError(err, errMax, "Out of memory.");
         break;
      }

      if (P11_WrapPrivateSecretKey(pTpl, pBuf, &ulAlloc) != CK_TRUE)
      {
         QuerySetError(err, errMax, "C_WrapKey failed.");
         break;
      }

      if (format == P11_FILE_FORMAT_PKCS8)
      {
         CK_CHAR_PTR pPem;
         CK_BBOOL bAsn;

         if (pTpl->bPbe != CK_TRUE)
         {
            QuerySetError(err, errMax, "PKCS#8 export requires password-based encryption.");
            break;
         }
         pTpl->wrap_key_mech->pbe_param.pWrappedKey = (CK_CHAR_PTR)pBuf;
         pTpl->wrap_key_mech->pbe_param.ulWrappedKeyLen = ulAlloc;
         bAsn = pksc8_Build_EncryptedPrivateKeyInfoPbe(&pTpl->wrap_key_mech->pbe_param);
         if (bAsn != CK_TRUE)
         {
            QuerySetError(err, errMax, "Failed to build EncryptedPrivateKeyInfo.");
            break;
         }
         pPem = pkcs8_EncodeEncryptedPrivateKeyToPem(asn1_BuildGetBuffer(), asn1_GetBufferSize());
         if (pPem == NULL)
         {
            QuerySetError(err, errMax, "Failed to encode PKCS#8 PEM.");
            break;
         }
         writtenSize = File_Write((CK_CHAR_PTR)path, pPem, (CK_ULONG)strlen((char*)pPem), CK_FALSE);
         free(pPem);
      }
      else
      {
         writtenSize = (CK_LONG)File_WriteHexFile((CK_CHAR_PTR)path, (CK_CHAR_PTR)pBuf, ulAlloc,
            (CK_BBOOL)(format & CK_TRUE));
      }

      if (writtenSize <= 0)
      {
         QuerySetError(err, errMax, "Failed to write the export file.");
         break;
      }
      if (pWritten != NULL)
      {
         *pWritten = (CK_ULONG)writtenSize;
      }
      bResult = CK_TRUE;
   } while (FALSE);

   if (pBuf != NULL)
   {
      free(pBuf);
   }
   if (pTpl->bPbe == CK_TRUE)
   {
      P11_DeleteObject(pTpl->hWrappingKey);
      pTpl->hWrappingKey = 0;
   }
   return bResult;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryExportKey(...)
*/
CK_BBOOL P11_QueryExportKey(P11_WRAPTEMPLATE* pTpl, const char* path, CK_BYTE format,
   CK_ULONG* pWritten, char* err, CK_ULONG errMax)
{
   QuerySetError(err, errMax, "");
   if (pWritten != NULL)
   {
      *pWritten = 0;
   }
   if ((pTpl == NULL) || (path == NULL) || (path[0] == 0))
   {
      QuerySetError(err, errMax, "Missing export path or template.");
      return CK_FALSE;
   }
   if (P11_IsLoggedIn() != CK_TRUE)
   {
      QuerySetError(err, errMax, "Not logged in.");
      return CK_FALSE;
   }
   if (P11_FindKeyObject(pTpl->hKeyToExport) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Key to export was not found.");
      return CK_FALSE;
   }

   pTpl->sClass = P11_GetObjectClass(pTpl->hKeyToExport);
   switch (pTpl->sClass)
   {
   case CKO_PUBLIC_KEY:
      pTpl->skeyType = P11_GetKeyType(pTpl->hKeyToExport);
      return QueryExportPublic(pTpl, path, format, pWritten, err, errMax);

   case CKO_PRIVATE_KEY:
   case CKO_SECRET_KEY:
      if (P11_GetBooleanAttribute(pTpl->hKeyToExport, CKA_EXTRACTABLE) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Key is not extractable.");
         return CK_FALSE;
      }
      if (pTpl->bPbe != CK_TRUE)
      {
         if (P11_FindKeyObject(pTpl->hWrappingKey) != CK_TRUE)
         {
            QuerySetError(err, errMax, "Wrapping key was not found.");
            return CK_FALSE;
         }
         if (P11_GetBooleanAttribute(pTpl->hWrappingKey, CKA_WRAP) != CK_TRUE)
         {
            QuerySetError(err, errMax, "Wrapping key does not have CKA_WRAP.");
            return CK_FALSE;
         }
         if (pTpl->wrap_key_mech == NULL)
         {
            QuerySetError(err, errMax, "Missing wrap algorithm.");
            return CK_FALSE;
         }
      }
      else if (pTpl->sClass != CKO_PRIVATE_KEY)
      {
         QuerySetError(err, errMax, "PKCS#8 PBE export is only for private keys.");
         return CK_FALSE;
      }
      return QueryWrapPrivateSecret(pTpl, path, format, pWritten, err, errMax);

   default:
      QuerySetError(err, errMax, "Object is not a key that can be exported.");
      return CK_FALSE;
   }
}

static CK_BBOOL QueryImportPublic(P11_UNWRAPTEMPLATE* pTpl, CK_CHAR_PTR pData, CK_ULONG uLen,
   CK_BYTE format, CK_OBJECT_HANDLE* pHandle, char* err, CK_ULONG errMax)
{
   PUBLIC_KEY uPublicKey;
   CK_BBOOL bResult = CK_FALSE;

   memset(&uPublicKey, 0, sizeof(uPublicKey));
   if (format == P11_FILE_FORMAT_TEXT)
   {
      uLen = str_StringtoByteArray(pData, uLen);
      if (uLen == 0)
      {
         QuerySetError(err, errMax, "File must be hexadecimal.");
         return CK_FALSE;
      }
   }
   else if (format == P11_FILE_FORMAT_PKCS8)
   {
      uLen = pkcs8_DecodePublicKeyFromPem(pData, uLen);
      if (uLen == 0)
      {
         QuerySetError(err, errMax, "Cannot decode PKCS#8 public key.");
         return CK_FALSE;
      }
   }

   switch (pTpl->skeyType)
   {
   case CKK_RSA:
      bResult = pksc8_Check_PublicKeyInfoRSA(&uPublicKey.sRsaPublicKey, pData, uLen);
      break;
   case CKK_DSA:
      bResult = pksc8_Check_PublicKeyInfoDSA(&uPublicKey.sDsaPublicKey, pData, uLen);
      break;
   case CKK_DH:
      bResult = pksc8_Check_PublicKeyInfoDH(&uPublicKey.sDhPublicKey, pData, uLen);
      break;
   case CKK_ECDSA:
   case CKK_EC_EDWARDS:
   case CKK_EC_MONTGOMERY:
   case CKK_EC_EDWARDS_OLD:
   case CKK_EC_MONTGOMERY_OLD:
   case CKK_SM2:
      bResult = pksc8_Check_PublicKeyInfoEC(&uPublicKey.sEcPublicKey, pData, uLen, pTpl->skeyType);
      break;
   case CKK_ML_DSA:
      bResult = pksc8_Check_PublicKeyInfoMLDSA(&uPublicKey.sMlDsaPublicKey, pData, uLen);
      break;
   case CKK_ML_KEM:
      bResult = pksc8_Check_PublicKeyInfoMLKEM(&uPublicKey.sMlKemPublicKey, pData, uLen);
      break;
   case CKK_HSS:
      bResult = pksc8_Check_PublicKeyInfoLMS(&uPublicKey.sLmsPublicKey, pData, uLen);
      break;
   default:
      QuerySetError(err, errMax, "This key type cannot be imported as a public key.");
      return CK_FALSE;
   }

   if (bResult != CK_TRUE)
   {
      QuerySetError(err, errMax, "Failed to decode publicKeyInfo.");
      return CK_FALSE;
   }
   if (P11_CreatePublicKey(pTpl, &uPublicKey) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Failed to create the public key object.");
      return CK_FALSE;
   }
   if (pHandle != NULL)
   {
      *pHandle = QueryFindNewestByLabel(CKO_PUBLIC_KEY, (const char*)pTpl->pKeyLabel);
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryImportKey(...)
*/
CK_BBOOL P11_QueryImportKey(P11_UNWRAPTEMPLATE* pTpl, const char* path, CK_BYTE format,
   const char* pbePassword, CK_OBJECT_HANDLE* pHandle, char* err, CK_ULONG errMax)
{
   CK_CHAR_PTR pData = NULL;
   CK_ULONG uLen = 0;
   CK_BBOOL bResult = CK_FALSE;
   CK_OBJECT_HANDLE hKey = 0;
   P11_ENCRYPTION_MECH wrapalgo;
   P11_KEYGENTEMPLATE sKeyGen;

   QuerySetError(err, errMax, "");
   if (pHandle != NULL)
   {
      *pHandle = 0;
   }
   memset(&wrapalgo, 0, sizeof(wrapalgo));
   memset(&sKeyGen, 0, sizeof(sKeyGen));

   if ((pTpl == NULL) || (path == NULL) || (path[0] == 0) || (pTpl->pKeyLabel == NULL) ||
      (pTpl->pKeyLabel[0] == 0))
   {
      QuerySetError(err, errMax, "Label and input file are required.");
      return CK_FALSE;
   }
   if (P11_IsLoggedIn() != CK_TRUE)
   {
      QuerySetError(err, errMax, "Not logged in.");
      return CK_FALSE;
   }

   if (pTpl->sClass == CKO_PUBLIC_KEY)
   {
      CK_BBOOL bBinary = (format == P11_FILE_FORMAT_BINARY) ? CK_TRUE : CK_FALSE;
      uLen = File_Read((CK_CHAR_PTR)path, &pData, bBinary);
      if ((uLen == 0) || (pData == NULL))
      {
         QuerySetError(err, errMax, "Cannot read the input file.");
         return CK_FALSE;
      }
      bResult = QueryImportPublic(pTpl, pData, uLen, format, pHandle, err, errMax);
      free(pData);
      return bResult;
   }

   if ((pTpl->sClass != CKO_PRIVATE_KEY) && (pTpl->sClass != CKO_SECRET_KEY))
   {
      QuerySetError(err, errMax, "Key class must be public, private, or secret.");
      return CK_FALSE;
   }

   if (format == P11_FILE_FORMAT_PKCS8)
   {
      if (pTpl->sClass != CKO_PRIVATE_KEY)
      {
         QuerySetError(err, errMax, "PKCS#8 import is only for private keys.");
         return CK_FALSE;
      }
      pTpl->bPbe = CK_TRUE;
   }

   if ((format != P11_FILE_FORMAT_TR31) && (pTpl->bPbe != CK_TRUE))
   {
      if (P11_FindKeyObject(pTpl->hWrappingKey) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Unwrap key was not found.");
         return CK_FALSE;
      }
      if (P11_GetBooleanAttribute(pTpl->hWrappingKey, CKA_UNWRAP) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Unwrap key does not have CKA_UNWRAP.");
         return CK_FALSE;
      }
      if (pTpl->wrapmech == NULL)
      {
         QuerySetError(err, errMax, "Missing unwrap algorithm.");
         return CK_FALSE;
      }
   }
   else if (format == P11_FILE_FORMAT_TR31)
   {
      if (P11_FindKeyObject(pTpl->hWrappingKey) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Unwrap key was not found.");
         return CK_FALSE;
      }
      if (P11_GetBooleanAttribute(pTpl->hWrappingKey, CKA_UNWRAP) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Unwrap key does not have CKA_UNWRAP.");
         return CK_FALSE;
      }
   }

   do
   {
      switch (format)
      {
      case P11_FILE_FORMAT_TEXT:
      case P11_FILE_FORMAT_BINARY:
         if (File_ReadHexFile((CK_CHAR_PTR)path, &pData, &uLen, (CK_BBOOL)(format & CK_TRUE)) != CK_TRUE)
         {
            QuerySetError(err, errMax, "Cannot read the input file.");
            break;
         }
         bResult = P11_UnwrapPrivateSecretKey(pTpl, pData, (CK_LONG)uLen, &hKey);
         if (bResult != CK_TRUE)
         {
            QuerySetError(err, errMax, "C_UnwrapKey failed.");
         }
         break;

      case P11_FILE_FORMAT_TR31:
         if (File_Read((CK_CHAR_PTR)path, &pData, (CK_BBOOL)(format & CK_TRUE)) == 0)
         {
            QuerySetError(err, errMax, "Cannot read the TR-31 file.");
            break;
         }
         bResult = TR31_UnwrapPrivateSecretKey(pTpl, pData, &hKey);
         if (bResult != CK_TRUE)
         {
            QuerySetError(err, errMax, "TR-31 unwrap failed.");
         }
         break;

      case P11_FILE_FORMAT_PKCS8:
         uLen = File_Read((CK_CHAR_PTR)path, &pData, CK_FALSE);
         if ((uLen == 0) || (pData == NULL))
         {
            QuerySetError(err, errMax, "Cannot read the PKCS#8 file.");
            break;
         }
         uLen = pkcs8_DecodeEncryptedPrivateKeyFromPem(pData, uLen);
         if (uLen == 0)
         {
            QuerySetError(err, errMax, "Cannot decode PKCS#8 file.");
            break;
         }
         if (pkcs8_Check_EncryptedPrivateKeyInfoPbe(&wrapalgo.pbe_param, pData, uLen) != CK_TRUE)
         {
            QuerySetError(err, errMax, "Error decoding EncryptedPrivateKeyInfo.");
            break;
         }
         if ((pbePassword == NULL) || (pbePassword[0] == 0))
         {
            QuerySetError(err, errMax, "Password is required for PKCS#8.");
            break;
         }
         wrapalgo.pbe_param.pbkdf2.pbfkd2_param.pPassword = (CK_CHAR_PTR)pbePassword;
         wrapalgo.pbe_param.pbkdf2.pbfkd2_param.usPasswordLen = (CK_ULONG)strlen(pbePassword);

         sKeyGen.sClass = wrapalgo.pbe_param.sEncClass;
         sKeyGen.skeyType = wrapalgo.pbe_param.sEnckeyType;
         sKeyGen.skeySize = wrapalgo.pbe_param.sEnckeySize;
         sKeyGen.bCKA_Wrap = CK_TRUE;
         sKeyGen.bCKA_Unwrap = CK_TRUE;
         sKeyGen.pKeyLabel = "pbkdf2_temp";
         sKeyGen.bCKA_Private = CK_TRUE;
         sKeyGen.bCKA_Sensitive = CK_TRUE;
         if (P11_GenerateKeyPbe(&sKeyGen, &pTpl->hWrappingKey, &wrapalgo.pbe_param, CK_FALSE) != CK_TRUE)
         {
            QuerySetError(err, errMax, "Failed to generate the PBE wrapping key.");
            break;
         }
         pTpl->wrapmech = &wrapalgo;
         pTpl->wrapmech->ckMechType = wrapalgo.pbe_param.ckEncMechType;
         bResult = P11_UnwrapPrivateSecretKey(pTpl, wrapalgo.pbe_param.pWrappedKey,
            (CK_LONG)wrapalgo.pbe_param.ulWrappedKeyLen, &hKey);
         if (bResult != CK_TRUE)
         {
            QuerySetError(err, errMax, "C_UnwrapKey failed.");
         }
         break;

      default:
         QuerySetError(err, errMax, "Unsupported import file format.");
         break;
      }
   } while (FALSE);

   if (pData != NULL)
   {
      free(pData);
   }
   if (pTpl->bPbe == CK_TRUE)
   {
      P11_DeleteObject(pTpl->hWrappingKey);
      pTpl->hWrappingKey = 0;
   }
   if ((bResult == CK_TRUE) && (pHandle != NULL))
   {
      *pHandle = hKey;
   }
   return bResult;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryConvertFile(...)
*/
CK_BBOOL P11_QueryConvertFile(const char* inPath, CK_BYTE inFmt,
   const char* outPath, CK_BYTE outFmt, CK_ULONG* pWritten, char* err, CK_ULONG errMax)
{
   CK_CHAR_PTR pData = NULL;
   CK_ULONG uLen = 0;
   CK_ULONG uWritten = 0;
   CK_BBOOL bOk = CK_FALSE;

   QuerySetError(err, errMax, "");
   if (pWritten != NULL)
   {
      *pWritten = 0;
   }
   if ((inPath == NULL) || (inPath[0] == 0) || (outPath == NULL) || (outPath[0] == 0))
   {
      QuerySetError(err, errMax, "Input and output files are required.");
      return CK_FALSE;
   }
   if (inFmt == outFmt)
   {
      QuerySetError(err, errMax, "Input and output formats must differ.");
      return CK_FALSE;
   }
   if (!((inFmt == P11_FILE_FORMAT_TEXT) || (inFmt == P11_FILE_FORMAT_BINARY)))
   {
      QuerySetError(err, errMax, "Convert only supports text and binary.");
      return CK_FALSE;
   }
   if (!((outFmt == P11_FILE_FORMAT_TEXT) || (outFmt == P11_FILE_FORMAT_BINARY)))
   {
      QuerySetError(err, errMax, "Convert only supports text and binary.");
      return CK_FALSE;
   }

   bOk = QueryReadHexFile(inPath, &pData, &uLen, inFmt, "input", err, errMax);
   if (bOk != CK_TRUE)
   {
      return CK_FALSE;
   }

   uWritten = File_WriteHexFile((CK_CHAR_PTR)outPath, pData, uLen, (CK_BBOOL)(outFmt & CK_TRUE));
   free(pData);
   if (uWritten == 0)
   {
      QuerySetError(err, errMax, "Failed to write the output file.");
      return CK_FALSE;
   }
   if (pWritten != NULL)
   {
      *pWritten = uWritten;
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryCryptFile(...)
*/
CK_BBOOL P11_QueryCryptFile(CK_BBOOL bDecrypt, CK_OBJECT_HANDLE hKey,
   P11_ENCRYPTION_MECH* pMech, const char* inPath, const char* outPath,
   CK_BYTE format, CK_ULONG* pWritten, char* err, CK_ULONG errMax)
{
   P11_ENCRYPT_TEMPLATE tpl;
   CK_CHAR_PTR pOut = NULL;
   CK_ULONG uOut = 0;
   CK_ULONG uWritten = 0;
   CK_BBOOL bOk = CK_FALSE;
   CK_ATTRIBUTE_TYPE ckaNeed;

   QuerySetError(err, errMax, "");
   if (pWritten != NULL)
   {
      *pWritten = 0;
   }
   memset(&tpl, 0, sizeof(tpl));

   if ((inPath == NULL) || (inPath[0] == 0) || (outPath == NULL) || (outPath[0] == 0))
   {
      QuerySetError(err, errMax, "Input and output files are required.");
      return CK_FALSE;
   }
   if (pMech == NULL)
   {
      QuerySetError(err, errMax, "Missing encryption algorithm.");
      return CK_FALSE;
   }
   if (!((format == P11_FILE_FORMAT_TEXT) || (format == P11_FILE_FORMAT_BINARY)))
   {
      QuerySetError(err, errMax, "Format must be text or binary.");
      return CK_FALSE;
   }
   if (P11_IsLoggedIn() != CK_TRUE)
   {
      QuerySetError(err, errMax, "Not logged in.");
      return CK_FALSE;
   }
   if (P11_FindKeyObject(hKey) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Key was not found.");
      return CK_FALSE;
   }

   ckaNeed = (bDecrypt == CK_TRUE) ? CKA_DECRYPT : CKA_ENCRYPT;
   if (P11_GetBooleanAttribute(hKey, ckaNeed) != CK_TRUE)
   {
      QuerySetError(err, errMax,
         (bDecrypt == CK_TRUE) ? "Key does not have CKA_DECRYPT." : "Key does not have CKA_ENCRYPT.");
      return CK_FALSE;
   }

   tpl.hEncyptiontKey = hKey;
   tpl.sClass = P11_GetObjectClass(hKey);
   tpl.skeyType = P11_GetKeyType(hKey);
   tpl.encryption_mech = pMech;

   if (QueryReadHexFile(inPath, &tpl.sInputData, &tpl.sInputDataLength, format, "input",
      err, errMax) != CK_TRUE)
   {
      return CK_FALSE;
   }

   if (bDecrypt == CK_TRUE)
   {
      bOk = P11_DecryptData(&tpl, &pOut, &uOut);
   }
   else
   {
      bOk = P11_EncryptData(&tpl, &pOut, &uOut);
   }

   if (tpl.sInputData != NULL)
   {
      free(tpl.sInputData);
      tpl.sInputData = NULL;
   }

   if (bOk != CK_TRUE)
   {
      if (pOut != NULL)
      {
         free(pOut);
      }
      QuerySetError(err, errMax, (bDecrypt == CK_TRUE) ? "C_Decrypt failed." : "C_Encrypt failed.");
      return CK_FALSE;
   }

   uWritten = File_WriteHexFile((CK_CHAR_PTR)outPath, pOut, uOut, (CK_BBOOL)(format & CK_TRUE));
   free(pOut);
   if (uWritten == 0)
   {
      QuerySetError(err, errMax, "Failed to write the output file.");
      return CK_FALSE;
   }
   if (pWritten != NULL)
   {
      *pWritten = uWritten;
   }
   return CK_TRUE;
}

static CK_ULONG QueryPssSaltLen(CK_MECHANISM_TYPE hashAlg)
{
   switch (hashAlg)
   {
   case CKM_SHA_1:
      return 20;
   case CKM_SHA224:
      return 28;
   case CKM_SHA256:
      return 32;
   case CKM_SHA384:
      return 48;
   case CKM_SHA512:
      return 64;
   default:
      return 32;
   }
}

/*
    FUNCTION:        CK_BBOOL P11_QueryBuildSignMech(...)
*/
CK_BBOOL P11_QueryBuildSignMech(const char* algoName, const char* pssHashName,
   P11_SIGN_MECH* pMech, char* err, CK_ULONG errMax)
{
   P11_SIGN_MECH* pSrc;

   QuerySetError(err, errMax, "");
   if ((pMech == NULL) || (algoName == NULL) || (algoName[0] == 0))
   {
      QuerySetError(err, errMax, "Missing signature algorithm.");
      return CK_FALSE;
   }

   pSrc = P11Util_GetSignParam((CK_CHAR_PTR)algoName, KEY_TYPE_SIGN);
   if (pSrc == NULL)
   {
      QuerySetError(err, errMax, "Unknown signature algorithm.");
      return CK_FALSE;
   }
   memcpy(pMech, pSrc, sizeof(*pMech));

   if ((pMech->ckMechType == CKM_RSA_PKCS_PSS) && (pMech->rsa_pss_param.hashAlg == 0))
   {
      P11_HASH_MECH* pHash;

      if ((pssHashName == NULL) || (pssHashName[0] == 0))
      {
         QuerySetError(err, errMax, "Select a PSS hash.");
         return CK_FALSE;
      }
      pHash = P11Util_GetHash((CK_CHAR_PTR)pssHashName, KEY_TYPE_HASH);
      if (pHash == NULL)
      {
         QuerySetError(err, errMax, "Unknown PSS hash.");
         return CK_FALSE;
      }
      pMech->rsa_pss_param.hashAlg = pHash->ckMechType;
      pMech->rsa_pss_param.mgf = pHash->ckMechOaepMgfType;
      pMech->rsa_pss_param.usSaltLen = QueryPssSaltLen(pHash->ckMechType);
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QuerySignFile(...)
*/
CK_BBOOL P11_QuerySignFile(CK_OBJECT_HANDLE hKey, P11_SIGN_MECH* pMech,
   const char* inPath, const char* outPath, CK_BYTE format,
   CK_ULONG* pWritten, char* err, CK_ULONG errMax)
{
   P11_SIGNATURE_TEMPLATE tpl;
   CK_CHAR_PTR pSig = NULL;
   CK_ULONG uSig = 0;
   CK_ULONG uWritten = 0;

   QuerySetError(err, errMax, "");
   if (pWritten != NULL)
   {
      *pWritten = 0;
   }
   memset(&tpl, 0, sizeof(tpl));

   if ((inPath == NULL) || (inPath[0] == 0) || (outPath == NULL) || (outPath[0] == 0))
   {
      QuerySetError(err, errMax, "Input and signature files are required.");
      return CK_FALSE;
   }
   if (pMech == NULL)
   {
      QuerySetError(err, errMax, "Missing signature algorithm.");
      return CK_FALSE;
   }
   if (!((format == P11_FILE_FORMAT_TEXT) || (format == P11_FILE_FORMAT_BINARY)))
   {
      QuerySetError(err, errMax, "Format must be text or binary.");
      return CK_FALSE;
   }
   if (P11_IsLoggedIn() != CK_TRUE)
   {
      QuerySetError(err, errMax, "Not logged in.");
      return CK_FALSE;
   }
   if (P11_FindKeyObject(hKey) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Key was not found.");
      return CK_FALSE;
   }
   if (P11_GetBooleanAttribute(hKey, CKA_SIGN) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Key does not have CKA_SIGN.");
      return CK_FALSE;
   }

   tpl.hSignatureKey = hKey;
   tpl.sClass = P11_GetObjectClass(hKey);
   tpl.skeyType = P11_GetKeyType(hKey);
   tpl.sign_mech = pMech;

   if (QueryReadHexFile(inPath, &tpl.sInputData, &tpl.sInputDataLength, format, "input",
      err, errMax) != CK_TRUE)
   {
      return CK_FALSE;
   }

   if (P11_SignData(&tpl, &pSig, &uSig) != CK_TRUE)
   {
      if (tpl.sInputData != NULL)
      {
         free(tpl.sInputData);
      }
      if (pSig != NULL)
      {
         free(pSig);
      }
      QuerySetError(err, errMax, "C_Sign failed.");
      return CK_FALSE;
   }

   if (tpl.sInputData != NULL)
   {
      free(tpl.sInputData);
   }

   uWritten = File_WriteHexFile((CK_CHAR_PTR)outPath, pSig, uSig, (CK_BBOOL)(format & CK_TRUE));
   free(pSig);
   if (uWritten == 0)
   {
      QuerySetError(err, errMax, "Failed to write the signature file.");
      return CK_FALSE;
   }
   if (pWritten != NULL)
   {
      *pWritten = uWritten;
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryVerifyFile(...)
*/
CK_BBOOL P11_QueryVerifyFile(CK_OBJECT_HANDLE hKey, P11_SIGN_MECH* pMech,
   const char* inPath, const char* sigPath, CK_BYTE format,
   char* err, CK_ULONG errMax)
{
   P11_SIGNATURE_TEMPLATE tpl;
   CK_CHAR_PTR pSig = NULL;
   CK_ULONG uSig = 0;
   CK_RV rv = CKR_GENERAL_ERROR;

   QuerySetError(err, errMax, "");
   memset(&tpl, 0, sizeof(tpl));

   if ((inPath == NULL) || (inPath[0] == 0) || (sigPath == NULL) || (sigPath[0] == 0))
   {
      QuerySetError(err, errMax, "Input and signature files are required.");
      return CK_FALSE;
   }
   if (pMech == NULL)
   {
      QuerySetError(err, errMax, "Missing signature algorithm.");
      return CK_FALSE;
   }
   if (!((format == P11_FILE_FORMAT_TEXT) || (format == P11_FILE_FORMAT_BINARY)))
   {
      QuerySetError(err, errMax, "Format must be text or binary.");
      return CK_FALSE;
   }
   if (P11_IsLoggedIn() != CK_TRUE)
   {
      QuerySetError(err, errMax, "Not logged in.");
      return CK_FALSE;
   }
   if (P11_FindKeyObject(hKey) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Key was not found.");
      return CK_FALSE;
   }
   if (P11_GetBooleanAttribute(hKey, CKA_VERIFY) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Key does not have CKA_VERIFY.");
      return CK_FALSE;
   }

   tpl.hSignatureKey = hKey;
   tpl.sClass = P11_GetObjectClass(hKey);
   tpl.skeyType = P11_GetKeyType(hKey);
   tpl.sign_mech = pMech;

   if (QueryReadHexFile(inPath, &tpl.sInputData, &tpl.sInputDataLength, format, "input",
      err, errMax) != CK_TRUE)
   {
      return CK_FALSE;
   }
   if (QueryReadHexFile(sigPath, &pSig, &uSig, format, "signature", err, errMax) != CK_TRUE)
   {
      if (tpl.sInputData != NULL)
      {
         free(tpl.sInputData);
      }
      return CK_FALSE;
   }

   if (P11_VerifyData(&tpl, pSig, uSig, &rv) != CK_TRUE)
   {
      if (tpl.sInputData != NULL)
      {
         free(tpl.sInputData);
      }
      if (pSig != NULL)
      {
         free(pSig);
      }
      if (rv == CKR_SIGNATURE_INVALID)
      {
         QuerySetError(err, errMax, "Signature is invalid.");
      }
      else
      {
         QuerySetError(err, errMax, "C_Verify failed.");
      }
      return CK_FALSE;
   }

   if (tpl.sInputData != NULL)
   {
      free(tpl.sInputData);
   }
   if (pSig != NULL)
   {
      free(pSig);
   }
   return CK_TRUE;
}

static CK_BBOOL QueryIsKdfMech(CK_MECHANISM_TYPE mech)
{
   return ((mech == CKM_PRF_KDF) || (mech == CKM_NIST_PRF_KDF)) ? CK_TRUE : CK_FALSE;
}

static CK_BBOOL QueryValidateDeriveSize(CK_KEY_TYPE keyType, CK_LONG length)
{
   switch (keyType)
   {
   case CKK_AES:
      return ((length == AES_128_KEY_LENGTH) ||
         (length == AES_192_KEY_LENGTH) ||
         (length == AES_256_KEY_LENGTH)) ? CK_TRUE : CK_FALSE;
   case CKK_DES:
   case CKK_DES2:
   case CKK_DES3:
      return ((length == DES_KEY_LENGTH) ||
         (length == DES2_KEY_LENGTH) ||
         (length == DES3_KEY_LENGTH)) ? CK_TRUE : CK_FALSE;
   case CKK_GENERIC_SECRET:
      return ((length >= GENERIC_KEY_MINIMUM_LENGTH) &&
         (length <= GENERIC_KEY__MAXIMUM_LENGTH)) ? CK_TRUE : CK_FALSE;
   default:
      return CK_FALSE;
   }
}

/*
    FUNCTION:        CK_BBOOL P11_QueryBuildDeriveMech(...)
*/
CK_BBOOL P11_QueryBuildDeriveMech(const char* algoName, const char* kdfType,
   const char* kdfScheme, CK_ULONG counter,
   const char* labelHex, const char* contextHex,
   P11_DERIVE_MECH* pMech,
   CK_BYTE* labelBuf, CK_ULONG labelMax,
   CK_BYTE* ctxBuf, CK_ULONG ctxMax,
   char* err, CK_ULONG errMax)
{
   P11_DERIVE_MECH* pSrc;
   CK_ULONG uLen;

   QuerySetError(err, errMax, "");
   if ((pMech == NULL) || (algoName == NULL) || (algoName[0] == 0))
   {
      QuerySetError(err, errMax, "Missing derivation mechanism.");
      return CK_FALSE;
   }

   pSrc = P11Util_GetDerivationParam((CK_CHAR_PTR)algoName);
   if (pSrc == NULL)
   {
      QuerySetError(err, errMax, "Unknown derivation mechanism.");
      return CK_FALSE;
   }
   memcpy(pMech, pSrc, sizeof(*pMech));

   if (QueryIsKdfMech(pMech->ckMechType) != CK_TRUE)
   {
      return CK_TRUE;
   }

   memset(&pMech->sPrfKdfParams, 0, sizeof(pMech->sPrfKdfParams));
   if (P11Util_FindKdfType((CK_CHAR_PTR)kdfType, &pMech->sPrfKdfParams.prfType) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Unknown or missing KDF type.");
      return CK_FALSE;
   }
   if (P11Util_FindKdfScheme((CK_CHAR_PTR)kdfScheme, &pMech->sPrfKdfParams.ulEncodingScheme) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Unknown or missing KDF scheme.");
      return CK_FALSE;
   }
   pMech->sPrfKdfParams.ulCounter = counter;

   if ((labelHex != NULL) && (labelHex[0] != 0))
   {
      if ((labelBuf == NULL) || (labelMax == 0))
      {
         QuerySetError(err, errMax, "KDF label buffer is missing.");
         return CK_FALSE;
      }
      uLen = QueryHexToBuf(labelHex, labelBuf, labelMax);
      if (uLen == 0)
      {
         QuerySetError(err, errMax, "KDF label must be hexadecimal.");
         return CK_FALSE;
      }
      pMech->sPrfKdfParams.pLabel = labelBuf;
      pMech->sPrfKdfParams.ulLabelLen = uLen;
   }

   if ((contextHex != NULL) && (contextHex[0] != 0))
   {
      if ((ctxBuf == NULL) || (ctxMax == 0))
      {
         QuerySetError(err, errMax, "KDF context buffer is missing.");
         return CK_FALSE;
      }
      uLen = QueryHexToBuf(contextHex, ctxBuf, ctxMax);
      if (uLen == 0)
      {
         QuerySetError(err, errMax, "KDF context must be hexadecimal.");
         return CK_FALSE;
      }
      pMech->sPrfKdfParams.pContext = ctxBuf;
      pMech->sPrfKdfParams.ulContextLen = uLen;
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_OBJECT_HANDLE P11_QueryResolveKey(...)
*/
CK_OBJECT_HANDLE P11_QueryResolveKey(const char* handleText, const char* label,
   const char* idHex, char* err, CK_ULONG errMax)
{
   char* pEnd = NULL;
   unsigned long v;
   CK_CHAR_PTR pLabel = NULL;
   CK_CHAR_PTR pId = NULL;
   CK_OBJECT_HANDLE hKey;

   QuerySetError(err, errMax, "");
   if ((handleText != NULL) && (handleText[0] != 0))
   {
      v = strtoul(handleText, &pEnd, 10);
      if ((pEnd == handleText) || (*pEnd != 0) || (v == 0))
      {
         QuerySetError(err, errMax, "Handle must be a positive number.");
         return 0;
      }
      return (CK_OBJECT_HANDLE)v;
   }

   if ((label != NULL) && (label[0] != 0))
   {
      pLabel = (CK_CHAR_PTR)label;
   }
   if ((idHex != NULL) && (idHex[0] != 0))
   {
      pId = (CK_CHAR_PTR)idHex;
   }
   if ((pLabel == NULL) && (pId == NULL))
   {
      QuerySetError(err, errMax, "Enter a handle, or a label and/or CKA_ID.");
      return 0;
   }

   hKey = P11_FindKeyObjectByLabelOrId(pLabel, pId);
   if ((hKey == 0) || (hKey == (CK_OBJECT_HANDLE)CK_KEY_NOT_FOUND) ||
      (hKey == (CK_OBJECT_HANDLE)CK_NULL_ELEMENT))
   {
      QuerySetError(err, errMax, "No key matches that label or CKA_ID.");
      return 0;
   }
   return hKey;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryApplyDeriveEncryptData(...)
*/
CK_BBOOL P11_QueryApplyDeriveEncryptData(P11_DERIVE_MECH* pMech, const char* dataHex,
   CK_BYTE* dataBuf, CK_ULONG dataMax, char* err, CK_ULONG errMax)
{
   CK_ULONG uLen;

   QuerySetError(err, errMax, "");
   if (pMech == NULL)
   {
      QuerySetError(err, errMax, "Missing derivation mechanism.");
      return CK_FALSE;
   }
   if (pMech->ckMechType != CKM_AES_ECB_ENCRYPT_DATA)
   {
      return CK_TRUE;
   }
   if ((dataHex == NULL) || (dataHex[0] == 0))
   {
      QuerySetError(err, errMax, "KDF data (hex) is required for aes-encrypt-ecb.");
      return CK_FALSE;
   }
   if ((dataBuf == NULL) || (dataMax == 0))
   {
      QuerySetError(err, errMax, "KDF data buffer is missing.");
      return CK_FALSE;
   }
   uLen = QueryHexToBuf(dataHex, dataBuf, dataMax);
   if (uLen == 0)
   {
      QuerySetError(err, errMax, "KDF data must be hexadecimal.");
      return CK_FALSE;
   }
   pMech->sKeyDerivationStringData.pData = dataBuf;
   pMech->sKeyDerivationStringData.ulLen = uLen;
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryDeriveKey(...)
*/
CK_BBOOL P11_QueryDeriveKey(P11_DERIVETEMPLATE* pTpl, CK_OBJECT_HANDLE* pHandle,
   char* err, CK_ULONG errMax)
{
   CK_OBJECT_HANDLE hKey = 0;

   QuerySetError(err, errMax, "");
   if (pHandle != NULL)
   {
      *pHandle = 0;
   }
   if (pTpl == NULL)
   {
      QuerySetError(err, errMax, "Missing derive template.");
      return CK_FALSE;
   }
   if ((pTpl->pDerivedKeyLabel == NULL) || (pTpl->pDerivedKeyLabel[0] == 0))
   {
      QuerySetError(err, errMax, "Label is required.");
      return CK_FALSE;
   }
   if (pTpl->sDeriveMech == NULL)
   {
      QuerySetError(err, errMax, "Missing derivation mechanism.");
      return CK_FALSE;
   }
   if (P11_IsLoggedIn() != CK_TRUE)
   {
      QuerySetError(err, errMax, "Not logged in.");
      return CK_FALSE;
   }
   if (P11_FindKeyObject(pTpl->hMasterKey) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Master key was not found.");
      return CK_FALSE;
   }
   if (P11_GetBooleanAttribute(pTpl->hMasterKey, CKA_DERIVE) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Master key does not have CKA_DERIVE.");
      return CK_FALSE;
   }
   if (QueryValidateDeriveSize(pTpl->sderivedKeyType, pTpl->sderivedKeyLength) != CK_TRUE)
   {
      QuerySetError(err, errMax, "Invalid derived key type or size.");
      return CK_FALSE;
   }
   if (pTpl->sDerivedClass == 0)
   {
      pTpl->sDerivedClass = CKO_SECRET_KEY;
   }
   if ((pTpl->uCKA_ID_Length == 0) || (pTpl->pCKA_ID == NULL))
   {
      pTpl->pCKA_ID = NULL;
      pTpl->uCKA_ID_Length = 0;
   }

   if (P11_DeriveKey(pTpl, &hKey, CK_FALSE) != CK_TRUE)
   {
      QuerySetError(err, errMax, "C_DeriveKey failed.");
      return CK_FALSE;
   }
   if (pHandle != NULL)
   {
      *pHandle = hKey;
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL P11_QueryRemoteMzmk(...)
*/
CK_BBOOL P11_QueryRemoteMzmk(P11_DERIVETEMPLATE* pTpl, const char* tmdPubPath,
   CK_OBJECT_HANDLE* pHandle,
   char* kcvHex, CK_ULONG kcvHexMax,
   char* csvPath, CK_ULONG csvPathMax,
   char* err, CK_ULONG errMax)
{
   CK_CHAR_PTR sInputFile = NULL;
   CK_CHAR_PTR sHsmPublicKeyAsn1 = NULL;
   CK_CHAR_PTR pKcvHex = NULL;
   CK_CHAR_PTR pKcvBuffer = NULL;
   char szOutFile[4096];
   EC_PUBLIC_KEY sTmdEcPublicKey = { 0 };
   EC_PUBLIC_KEY sHsmEcPublicKey = { 0 };
   P11_KEYGENTEMPLATE sKeyGenTemplate = { 0 };
   P11_DERIVE_MECH sDeriveMech = { 0 };
   CK_OBJECT_HANDLE hPrivateKey = 0;
   CK_OBJECT_HANDLE hPublicKey = 0;
   CK_OBJECT_HANDLE hMZMKKey = 0;
   CK_ULONG sInputFileLength = 0;
   CK_BBOOL bResult = CK_FALSE;

   QuerySetError(err, errMax, "");
   if (pHandle != NULL)
   {
      *pHandle = 0;
   }
   if ((kcvHex != NULL) && (kcvHexMax > 0))
   {
      memset(kcvHex, 0, kcvHexMax);
   }
   if ((csvPath != NULL) && (csvPathMax > 0))
   {
      memset(csvPath, 0, csvPathMax);
   }
   memset(szOutFile, 0, sizeof(szOutFile));

   do
   {
      if (pTpl == NULL)
      {
         QuerySetError(err, errMax, "Missing MZMK template.");
         break;
      }
      if ((tmdPubPath == NULL) || (tmdPubPath[0] == 0))
      {
         QuerySetError(err, errMax, "TMD public key file is required.");
         break;
      }
      if ((pTpl->pDerivedKeyLabel == NULL) || (pTpl->pDerivedKeyLabel[0] == 0))
      {
         QuerySetError(err, errMax, "Label is required.");
         break;
      }
      if (P11_IsLoggedIn() != CK_TRUE)
      {
         QuerySetError(err, errMax, "Not logged in.");
         break;
      }

      switch (pTpl->sderivedKeyType)
      {
      case CKK_AES:
         if ((pTpl->sderivedKeyLength == AES_128_KEY_LENGTH) ||
            (pTpl->sderivedKeyLength == AES_192_KEY_LENGTH) ||
            (pTpl->sderivedKeyLength == AES_256_KEY_LENGTH))
         {
            break;
         }
         QuerySetError(err, errMax, "AES MZMK size must be 16, 24, or 32.");
         return CK_FALSE;
      case CKK_DES:
         if (pTpl->sderivedKeyLength == DES3_KEY_LENGTH)
         {
            pTpl->sderivedKeyType = CKK_DES3;
            break;
         }
         QuerySetError(err, errMax, "DES MZMK size must be 24.");
         return CK_FALSE;
      default:
         QuerySetError(err, errMax, "MZMK type must be aes or des.");
         return CK_FALSE;
      }

      pTpl->sDerivedClass = CKO_SECRET_KEY;
      if ((pTpl->uCKA_ID_Length == 0) || (pTpl->pCKA_ID == NULL))
      {
         pTpl->pCKA_ID = NULL;
         pTpl->uCKA_ID_Length = 0;
      }

      /* PathAppend/PathRemoveFileSpec are MAX_PATH APIs and the CSV
         file name ("MZMKdata_<date>.csv") adds roughly 30 characters. */
      if (strlen(tmdPubPath) + 35 >= MAX_PATH)
      {
         QuerySetError(err, errMax, "TMD file path is too long for the CSV output.");
         break;
      }

      sInputFileLength = File_Read((CK_CHAR_PTR)tmdPubPath, &sInputFile, CK_FALSE);
      if (sInputFileLength == 0)
      {
         QuerySetError(err, errMax, "Cannot read the TMD public key file.");
         break;
      }
      sInputFileLength = str_StringtoByteArray(sInputFile, sInputFileLength);
      if (sInputFileLength == 0)
      {
         QuerySetError(err, errMax, "TMD public key file must be hexadecimal.");
         break;
      }
      if (pksc8_Check_PublicKeyInfoEC(&sTmdEcPublicKey, sInputFile, sInputFileLength, CKK_ECDSA) != CK_TRUE)
      {
         QuerySetError(err, errMax, "TMD file is not an EC public key.");
         break;
      }

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
      if (sKeyGenTemplate.pECCurveOID == NULL)
      {
         QuerySetError(err, errMax, "Unsupported TMD EC curve.");
         break;
      }
      if (P11_GenerateKeyPair(&sKeyGenTemplate, &hPrivateKey, &hPublicKey, CK_FALSE) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Failed to generate the temporary ECDH key pair.");
         break;
      }

      pTpl->hMasterKey = hPrivateKey;
      pTpl->sDeriveMech = &sDeriveMech;
      pTpl->sDeriveMech->ckMechType = CKM_ECDH1_DERIVE;
      pTpl->sDeriveMech->sEcdh1DeriveParams.kdf = CKD_SHA256_KDF;
      pTpl->sDeriveMech->sEcdh1DeriveParams.pSharedData = tmd_getShareinfo();
      pTpl->sDeriveMech->sEcdh1DeriveParams.ulSharedDataLen = tmd_getShareinfoLength();
      pTpl->sDeriveMech->sEcdh1DeriveParams.pPublicData = sTmdEcPublicKey.sPublicPoint;
      pTpl->sDeriveMech->sEcdh1DeriveParams.ulPublicDataLen = sTmdEcPublicKey.uPublicPointLength;
      if (P11_DeriveKey(pTpl, &hMZMKKey, CK_FALSE) != CK_TRUE)
      {
         QuerySetError(err, errMax, "ECDH derive of the MZMK failed.");
         break;
      }

      if (P11_ComputeKCV(KCV_PCI, hMZMKKey, &pKcvBuffer) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Failed to compute the PCI KCV.");
         break;
      }
      pKcvHex = str_ByteArraytoString(pKcvBuffer, 3);
      if (pKcvHex == NULL)
      {
         QuerySetError(err, errMax, "Failed to format the KCV.");
         break;
      }
      if ((kcvHex != NULL) && (kcvHexMax > 0))
      {
         strncpy(kcvHex, pKcvHex, kcvHexMax - 1);
      }

      if (P11_GetEccPublicKey(hPublicKey, &sHsmEcPublicKey, CKK_ECDSA) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Failed to read the temporary EC public key.");
         break;
      }
      if (pksc8_Build_PublicKeyInfoEC(&sHsmEcPublicKey, CKK_ECDSA) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Failed to encode the HSM public key.");
         break;
      }
      sHsmPublicKeyAsn1 = str_ByteArraytoString(asn1_BuildGetBuffer(), (CK_LONG)asn1_GetBufferSize());
      if (sHsmPublicKeyAsn1 == NULL)
      {
         QuerySetError(err, errMax, "Failed to format the HSM public key.");
         break;
      }

      strncpy(szOutFile, tmdPubPath, sizeof(szOutFile) - 1);
      str_PathRemoveFile(szOutFile, (CK_ULONG)strlen(szOutFile));
      if (tmd_generateCSVFile(sHsmPublicKeyAsn1, pTpl->sderivedKeyType, pTpl->sderivedKeyLength,
         (CK_BYTE_PTR)pKcvHex, szOutFile) != CK_TRUE)
      {
         QuerySetError(err, errMax, "Failed to write the TMD CSV file.");
         break;
      }
      if ((csvPath != NULL) && (csvPathMax > 0))
      {
         strncpy(csvPath, szOutFile, csvPathMax - 1);
      }
      if (pHandle != NULL)
      {
         *pHandle = hMZMKKey;
      }
      bResult = CK_TRUE;
   } while (FALSE);

   if (sHsmPublicKeyAsn1 != NULL)
   {
      free(sHsmPublicKeyAsn1);
   }
   if (sInputFile != NULL)
   {
      free(sInputFile);
   }
   if (pKcvBuffer != NULL)
   {
      free(pKcvBuffer);
   }
   if (pKcvHex != NULL)
   {
      free(pKcvHex);
   }
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
