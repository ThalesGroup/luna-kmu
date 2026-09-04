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

#define _DLG_ATTRIBUTES_C

#ifdef OS_WIN32
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "p11.h"
#include "p11util.h"
#include "p11query.h"
#include "str.h"
#include "file.h"
#include "pkcs8.h"
#include "gui.h"
#include "gui_theme.h"
#include "dlg_attributes.h"

#ifdef OS_WIN32
#pragma comment(lib, "comdlg32.lib")
#endif

#define DLG_ATTR_CLASS            "LunaKmuAttributes"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               78
#define DLG_MAX_LABEL             100
#define DLG_CKA_ID_MAX            4096
#define DLG_HEX_MAX               8192
#define DLG_APP_MAX               256
#define DLG_DUMP_HEX_MAX          64
#define DLG_COMBO_DROP            160
#define DLG_FILE_ATTR_W           100

#define IDC_ATTR_SUMMARY          2401
#define IDC_ATTR_LIST             2402
#define IDC_ATTR_STATUS           2403
#define IDC_ATTR_APPLY            2404
#define IDC_ATTR_CLOSE            2405
#define IDC_ATTR_LBL_LABEL        2406
#define IDC_ATTR_LABEL            2407
#define IDC_ATTR_LBL_ID           2408
#define IDC_ATTR_ID               2409
#define IDC_ATTR_LBL_APP          2410
#define IDC_ATTR_APP              2411
#define IDC_ATTR_LBL_VALUE        2412
#define IDC_ATTR_VALUE            2413
#define IDC_ATTR_PRIVATE          2414
#define IDC_ATTR_MODIFIABLE       2415
#define IDC_ATTR_EXTRACTABLE      2416
#define IDC_ATTR_ENCRYPT          2417
#define IDC_ATTR_DECRYPT          2418
#define IDC_ATTR_SIGN             2419
#define IDC_ATTR_VERIFY           2420
#define IDC_ATTR_WRAP             2421
#define IDC_ATTR_UNWRAP           2422
#define IDC_ATTR_DERIVE           2423
#define IDC_ATTR_ENCAPSULATE      2424
#define IDC_ATTR_DECAPSULATE      2425
#define IDC_ATTR_FILEATTR         2426
#define IDC_ATTR_SAVE             2427
#define IDC_ATTR_LOAD             2428

typedef enum
{
   AF_BOOL = 0,
   AF_ULONG,
   AF_CLASS,
   AF_KEYTYPE,
   AF_TEXT,
   AF_HEX,
   AF_DATE
} ATTR_FMT;

typedef struct
{
   CK_ATTRIBUTE_TYPE type;
   const char* name;
   ATTR_FMT fmt;
} ATTR_DUMP;

typedef struct
{
   HWND hChk;
   int id;
   const char* caption;
   CK_ATTRIBUTE_TYPE type;
   BOOL bKeyOnly;
   CK_BBOOL bPresent;
   CK_BBOOL bOrig;
} ATTR_FLAG;

static HWND s_hDlg = NULL;
static HWND s_hSummary = NULL;
static HWND s_hList = NULL;
static HWND s_hStatus = NULL;
static HWND s_hLabel = NULL;
static HWND s_hId = NULL;
static HWND s_hApp = NULL;
static HWND s_hValue = NULL;
static HWND s_hLblApp = NULL;
static HWND s_hLblValue = NULL;
static HWND s_hFileAttr = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static CK_OBJECT_HANDLE s_hObject = 0;
static CK_OBJECT_CLASS s_ckClass = 0;
static BOOL s_bIsKey = FALSE;
static BOOL s_bIsData = FALSE;
static char s_szOrigLabel[DLG_MAX_LABEL];
static char s_szOrigId[(DLG_CKA_ID_MAX * 2) + 2];
static char s_szOrigApp[DLG_APP_MAX];
static char s_szOrigValue[(DLG_HEX_MAX) + 2];
static CK_BBOOL s_bHasId = CK_FALSE;
static CK_BBOOL s_bHasApp = CK_FALSE;
static CK_BBOOL s_bHasValue = CK_FALSE;
static BOOL s_bLoading = FALSE;

static ATTR_FLAG s_flags[] =
{
   { NULL, IDC_ATTR_PRIVATE,      "Private",      CKA_PRIVATE,      FALSE, CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_MODIFIABLE,   "Modifiable",   CKA_MODIFIABLE,   FALSE, CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_EXTRACTABLE,  "Extractable",  CKA_EXTRACTABLE,  TRUE,  CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_ENCRYPT,      "Encrypt",      CKA_ENCRYPT,      TRUE,  CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_DECRYPT,      "Decrypt",      CKA_DECRYPT,      TRUE,  CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_SIGN,         "Sign",         CKA_SIGN,         TRUE,  CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_VERIFY,       "Verify",       CKA_VERIFY,       TRUE,  CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_WRAP,         "Wrap",         CKA_WRAP,         TRUE,  CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_UNWRAP,       "Unwrap",       CKA_UNWRAP,       TRUE,  CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_DERIVE,       "Derive",       CKA_DERIVE,       TRUE,  CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_ENCAPSULATE,  "Encapsulate",  CKA_ENCAPSULATE,  TRUE,  CK_FALSE, CK_FALSE },
   { NULL, IDC_ATTR_DECAPSULATE,  "Decapsulate",  CKA_DECAPSULATE,  TRUE,  CK_FALSE, CK_FALSE },
};

static const ATTR_DUMP s_dump[] =
{
   { CKA_CLASS,          "Class",        AF_CLASS },
   { CKA_TOKEN,          "Token",        AF_BOOL },
   { CKA_PRIVATE,        "Private",      AF_BOOL },
   { CKA_MODIFIABLE,     "Modifiable",   AF_BOOL },
   { CKA_LABEL,          "Label",        AF_TEXT },
   { CKA_KEY_TYPE,       "KeyType",      AF_KEYTYPE },
   { CKA_ID,             "id",           AF_HEX },
   { CKA_LOCAL,          "Local",        AF_BOOL },
   { CKA_SENSITIVE,      "Sensitive",    AF_BOOL },
   { CKA_ALWAYS_SENSITIVE,"AlwaysSensitive", AF_BOOL },
   { CKA_EXTRACTABLE,    "Extractable",  AF_BOOL },
   { CKA_NEVER_EXTRACTABLE,"NeverExtractable", AF_BOOL },
   { CKA_ENCRYPT,        "Encrypt",      AF_BOOL },
   { CKA_DECRYPT,        "Decrypt",      AF_BOOL },
   { CKA_SIGN,           "Sign",         AF_BOOL },
   { CKA_VERIFY,         "Verify",       AF_BOOL },
   { CKA_WRAP,           "Wrap",         AF_BOOL },
   { CKA_UNWRAP,         "Unwrap",       AF_BOOL },
   { CKA_DERIVE,         "Derive",       AF_BOOL },
   { CKA_ENCAPSULATE,    "Encapsulate",  AF_BOOL },
   { CKA_DECAPSULATE,    "Decapsulate",  AF_BOOL },
   { CKA_VALUE_LEN,      "KeyLength",    AF_ULONG },
   { CKA_MODULUS_BITS,   "ModulusSize",  AF_ULONG },
   { CKA_CHECK_VALUE,    "KeyCheckValue",AF_HEX },
   { CKA_START_DATE,     "StartDate",    AF_DATE },
   { CKA_END_DATE,       "EndDate",      AF_DATE },
   { CKA_APPLICATION,    "Application",  AF_TEXT },
   { CKA_VALUE,          "Value",        AF_HEX },
};

#define ATTR_FLAG_COUNT  ((int)(sizeof(s_flags) / sizeof(s_flags[0])))
#define ATTR_DUMP_COUNT  ((int)(sizeof(s_dump) / sizeof(s_dump[0])))
#define ATTR_DUMP_MAX    96

typedef struct
{
   char name[40];
   char value[168];
} ATTR_ROW;

static void DlgAttr_UpdateApply(void);

static void DlgAttr_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static CK_BBOOL DlgAttr_IsChecked(HWND hChk)
{
   if (hChk == NULL)
   {
      return CK_FALSE;
   }
   return (SendMessageA(hChk, BM_GETCHECK, 0, 0) == BST_CHECKED) ? CK_TRUE : CK_FALSE;
}

static void DlgAttr_SetChecked(HWND hChk, CK_BBOOL bOn)
{
   if (hChk != NULL)
   {
      SendMessageA(hChk, BM_SETCHECK, bOn ? BST_CHECKED : BST_UNCHECKED, 0);
   }
}

static void DlgAttr_StripHex(char* s)
{
   char* pIn;
   char* pOut;

   if (s == NULL)
   {
      return;
   }
   pIn = s;
   pOut = s;
   while (*pIn != 0)
   {
      if (!isspace((unsigned char)*pIn))
      {
         *pOut++ = (char)toupper((unsigned char)*pIn);
      }
      pIn++;
   }
   *pOut = 0;
}

static void DlgAttr_BytesToHex(const CK_BYTE* pData, CK_ULONG ulLen, char* out, unsigned int outSize)
{
   CK_ULONG ulLoop;
   unsigned int uPos = 0;

   memset(out, 0, outSize);
   if ((pData == NULL) || (outSize < 3))
   {
      return;
   }
   for (ulLoop = 0; ulLoop < ulLen; ulLoop++)
   {
      if ((uPos + 2) >= outSize)
      {
         break;
      }
      sprintf(out + uPos, "%02X", pData[ulLoop]);
      uPos += 2;
   }
}

static void DlgAttr_CollectRow(ATTR_ROW* rows, int* pCount, const char* sName, const char* sValue)
{
   int n;

   if ((rows == NULL) || (pCount == NULL) || (*pCount >= ATTR_DUMP_MAX))
   {
      return;
   }
   n = *pCount;
   memset(&rows[n], 0, sizeof(rows[n]));
   strncpy(rows[n].name, (sName != NULL) ? sName : "", sizeof(rows[n].name) - 1);
   strncpy(rows[n].value, (sValue != NULL) ? sValue : "", sizeof(rows[n].value) - 1);
   *pCount = n + 1;
}

static void DlgAttr_AddRow(const char* sName, const char* sValue)
{
   LVITEMA item;
   int iItem;

   if (s_hList == NULL)
   {
      return;
   }
   iItem = (int)SendMessageA(s_hList, LVM_GETITEMCOUNT, 0, 0);
   memset(&item, 0, sizeof(item));
   item.mask = LVIF_TEXT;
   item.iItem = iItem;
   item.pszText = (LPSTR)((sName != NULL) ? sName : "");
   SendMessageA(s_hList, LVM_INSERTITEMA, 0, (LPARAM)&item);
   ListView_SetItemText(s_hList, iItem, 1, (LPSTR)((sValue != NULL) ? sValue : ""));
}

static void DlgAttr_CommitDump(const ATTR_ROW* rows, int nCount)
{
   int iLoop;

   if (s_hList == NULL)
   {
      return;
   }
   SendMessageA(s_hList, WM_SETREDRAW, FALSE, 0);
   SendMessageA(s_hList, LVM_DELETEALLITEMS, 0, 0);
   for (iLoop = 0; iLoop < nCount; iLoop++)
   {
      DlgAttr_AddRow(rows[iLoop].name, rows[iLoop].value);
   }
   SendMessageA(s_hList, WM_SETREDRAW, TRUE, 0);
   InvalidateRect(s_hList, NULL, TRUE);
}

static void DlgAttr_FormatHexRow(ATTR_ROW* rows, int* pCount, const char* sName,
   const CK_BYTE* pData, CK_ULONG ulLen)
{
   char sz[168];
   char szHex[DLG_DUMP_HEX_MAX * 2 + 8];
   CK_ULONG ulShow;

   ulShow = ulLen;
   if (ulShow > DLG_DUMP_HEX_MAX)
   {
      ulShow = DLG_DUMP_HEX_MAX;
   }
   DlgAttr_BytesToHex(pData, ulShow, szHex, sizeof(szHex));
   memset(sz, 0, sizeof(sz));
   if (ulLen > DLG_DUMP_HEX_MAX)
   {
      _snprintf(sz, sizeof(sz) - 1, "%s ... (%lu bytes)", szHex, (unsigned long)ulLen);
   }
   else if (ulLen == 0)
   {
      strncpy(sz, "(empty)", sizeof(sz) - 1);
   }
   else
   {
      strncpy(sz, szHex, sizeof(sz) - 1);
   }
   DlgAttr_CollectRow(rows, pCount, sName, sz);
}

static CK_ULONG DlgAttr_BytesToUlong(const CK_BYTE* pData, CK_ULONG ulLen)
{
   CK_ULONG ulVal = 0;

   if ((pData == NULL) || (ulLen < 4))
   {
      return 0;
   }
   if (ulLen >= sizeof(CK_ULONG))
   {
      memcpy(&ulVal, pData, sizeof(CK_ULONG));
   }
   else
   {
      unsigned int u32 = 0;
      memcpy(&u32, pData, 4);
      ulVal = (CK_ULONG)u32;
   }
   return ulVal;
}

static BOOL DlgAttr_ReadUlong(CK_ATTRIBUTE_TYPE type, CK_ULONG* pVal)
{
   CK_BYTE* pData = NULL;
   CK_ULONG ulLen = 0;
   BOOL bOk = FALSE;

   if (pVal != NULL)
   {
      *pVal = 0;
   }
   if (P11_QueryAttrBytes(s_hObject, type, &pData, &ulLen, NULL) != CK_TRUE)
   {
      return FALSE;
   }
   if ((pData != NULL) && (ulLen >= 4) && (pVal != NULL))
   {
      *pVal = DlgAttr_BytesToUlong(pData, ulLen);
      bOk = TRUE;
   }
   if (pData != NULL)
   {
      free(pData);
   }
   return bOk;
}

static void DlgAttr_CollectAttrBool(ATTR_ROW* rows, int* pCount, const char* sName,
   CK_ATTRIBUTE_TYPE type)
{
   CK_BBOOL bVal = CK_FALSE;

   if (P11_QueryAttrBool(s_hObject, type, &bVal) != CK_TRUE)
   {
      return;
   }
   DlgAttr_CollectRow(rows, pCount, sName, (const char*)P11Util_DisplayBooleanName(bVal));
}

static void DlgAttr_CollectAttrUlong(ATTR_ROW* rows, int* pCount, const char* sName,
   CK_ATTRIBUTE_TYPE type)
{
   CK_ULONG ulVal = 0;
   char sz[64];

   if (DlgAttr_ReadUlong(type, &ulVal) == FALSE)
   {
      return;
   }
   memset(sz, 0, sizeof(sz));
   _snprintf(sz, sizeof(sz) - 1, "%lu", (unsigned long)ulVal);
   DlgAttr_CollectRow(rows, pCount, sName, sz);
}

static void DlgAttr_CollectAttrHex(ATTR_ROW* rows, int* pCount, const char* sName,
   CK_ATTRIBUTE_TYPE type)
{
   CK_BYTE* pData = NULL;
   CK_ULONG ulLen = 0;
   CK_RV rv = CKR_OK;

   if (P11_QueryAttrBytes(s_hObject, type, &pData, &ulLen, &rv) != CK_TRUE)
   {
      if (rv == CKR_ATTRIBUTE_SENSITIVE)
      {
         DlgAttr_CollectRow(rows, pCount, sName, "(sensitive)");
      }
      return;
   }
   DlgAttr_FormatHexRow(rows, pCount, sName, pData, ulLen);
   if (pData != NULL)
   {
      free(pData);
   }
}

static void DlgAttr_CollectCurve(ATTR_ROW* rows, int* pCount)
{
   CK_BYTE* pData = NULL;
   CK_ULONG ulLen = 0;
   P11_ECC_OID* pOid;

   if (P11_QueryAttrBytes(s_hObject, CKA_ECDSA_PARAMS, &pData, &ulLen, NULL) != CK_TRUE)
   {
      return;
   }
   DlgAttr_FormatHexRow(rows, pCount, "CurveOID", pData, ulLen);
   pOid = P11Util_GetEcCurveOID((CK_CHAR_PTR)pData, ulLen);
   if ((pOid != NULL) && (pOid->sCurveName != NULL))
   {
      DlgAttr_CollectRow(rows, pCount, "CurveOIDName", (const char*)pOid->sCurveName);
   }
   if (pData != NULL)
   {
      free(pData);
   }
}

static void DlgAttr_CollectParameterSet(ATTR_ROW* rows, int* pCount, CK_KEY_TYPE kt)
{
   CK_ULONG ulSet = 0;
   char sz[96];
   P11_ML_DSA_KEY* pDsa;
   P11_ML_KEM_KEY* pKem;

   if (DlgAttr_ReadUlong(CKA_PARAMETER_SET, &ulSet) == FALSE)
   {
      return;
   }
   memset(sz, 0, sizeof(sz));
   if (kt == CKK_ML_DSA)
   {
      pDsa = P11Util_GetML_DSA_ParameterFromParameterSet((CK_ML_DSA_PARAMETER_SET_TYPE)ulSet);
      if (pDsa != NULL)
      {
         _snprintf(sz, sizeof(sz) - 1, "%s (0x%08X)", (const char*)pDsa->sName,
            (unsigned int)pDsa->uML_DSA_Parameter_Set);
         DlgAttr_CollectRow(rows, pCount, "ParameterSet", sz);
         memset(sz, 0, sizeof(sz));
         _snprintf(sz, sizeof(sz) - 1, "%lu",
            (unsigned long)((s_ckClass == CKO_PRIVATE_KEY) ? pDsa->sPrivateKeySize : pDsa->sPublicKeySize));
         DlgAttr_CollectRow(rows, pCount, "KeySize", sz);
      }
   }
   else if (kt == CKK_ML_KEM)
   {
      pKem = P11Util_GetML_KEM_ParameterFromParameterSet((CK_ML_KEM_PARAMETER_SET_TYPE)ulSet);
      if (pKem != NULL)
      {
         _snprintf(sz, sizeof(sz) - 1, "%s (0x%08X)", (const char*)pKem->sName,
            (unsigned int)pKem->uML_KEM_Parameter_Set);
         DlgAttr_CollectRow(rows, pCount, "ParameterSet", sz);
         memset(sz, 0, sizeof(sz));
         _snprintf(sz, sizeof(sz) - 1, "%lu",
            (unsigned long)((s_ckClass == CKO_PRIVATE_KEY) ? pKem->sPrivateKeySize : pKem->sPublicKeySize));
         DlgAttr_CollectRow(rows, pCount, "KeySize", sz);
      }
   }
}

static void DlgAttr_CollectParsedPublicKey(ATTR_ROW* rows, int* pCount, CK_KEY_TYPE kt)
{
   CK_BYTE* pData = NULL;
   CK_ULONG ulLen = 0;
   ML_DSA_PUBLIC_KEY sDsa;
   ML_KEM_PUBLIC_KEY sKem;

   if (P11_QueryAttrBytes(s_hObject, CKA_PUBLIC_KEY_INFO, &pData, &ulLen, NULL) != CK_TRUE)
   {
      return;
   }
   memset(&sDsa, 0, sizeof(sDsa));
   memset(&sKem, 0, sizeof(sKem));
   if ((kt == CKK_ML_DSA) &&
      (pksc8_Check_PublicKeyInfoMLDSA(&sDsa, (CK_CHAR_PTR)pData, ulLen) == CK_TRUE) &&
      (sDsa.sPublicKey != NULL) && (sDsa.uPublicKeyLength > 0))
   {
      DlgAttr_FormatHexRow(rows, pCount, "PublicKey", (const CK_BYTE*)sDsa.sPublicKey, sDsa.uPublicKeyLength);
   }
   else if ((kt == CKK_ML_KEM) &&
      (pksc8_Check_PublicKeyInfoMLKEM(&sKem, (CK_CHAR_PTR)pData, ulLen) == CK_TRUE) &&
      (sKem.sPublicKey != NULL) && (sKem.uPublicKeyLength > 0))
   {
      DlgAttr_FormatHexRow(rows, pCount, "PublicKey", (const CK_BYTE*)sKem.sPublicKey, sKem.uPublicKeyLength);
   }
   else
   {
      DlgAttr_FormatHexRow(rows, pCount, "PublicKeyInfo", pData, ulLen);
   }
   if (pData != NULL)
   {
      free(pData);
   }
}

static void DlgAttr_CollectHss(ATTR_ROW* rows, int* pCount, BOOL bPrivate)
{
   CK_ULONG ulLevels = 0;
   CK_ULONG ulLoop;
   CK_ULONG ulCount;
   CK_BYTE* pData = NULL;
   CK_ULONG ulLen = 0;
   char szName[40];
   char sz[128];
   CK_LMS_TYPE lms;
   CK_LMOTS_TYPE lmots;
   const char* pTypeName;

   if (DlgAttr_ReadUlong(CKA_HSS_LEVELS, &ulLevels) != FALSE)
   {
      memset(sz, 0, sizeof(sz));
      if (ulLevels == 1)
      {
         strncpy(sz, "1 (LMS Key)", sizeof(sz) - 1);
      }
      else
      {
         _snprintf(sz, sizeof(sz) - 1, "%lu", (unsigned long)ulLevels);
      }
      DlgAttr_CollectRow(rows, pCount, "HSSLevel", sz);
   }

   if (bPrivate == FALSE)
   {
      if (DlgAttr_ReadUlong(CKA_HSS_LMS_TYPE, &ulLoop) != FALSE)
      {
         pTypeName = (const char*)P11Util_GetLMSTypeName((CK_LMS_TYPE)ulLoop);
         memset(sz, 0, sizeof(sz));
         _snprintf(sz, sizeof(sz) - 1, "%lu (%s)", (unsigned long)ulLoop,
            (pTypeName != NULL) ? pTypeName : "");
         DlgAttr_CollectRow(rows, pCount, "LMS-Type", sz);
      }
      if (DlgAttr_ReadUlong(CKA_HSS_LMOTS_TYPE, &ulLoop) != FALSE)
      {
         pTypeName = (const char*)P11Util_GetLMOTSTypeName((CK_LMOTS_TYPE)ulLoop);
         memset(sz, 0, sizeof(sz));
         _snprintf(sz, sizeof(sz) - 1, "%lu (%s)", (unsigned long)ulLoop,
            (pTypeName != NULL) ? pTypeName : "");
         DlgAttr_CollectRow(rows, pCount, "LMOTS-Type", sz);
      }
      DlgAttr_CollectAttrHex(rows, pCount, "PublicKey", CKA_VALUE);
      return;
   }

   if (P11_QueryAttrBytes(s_hObject, CKA_HSS_LMS_TYPES, &pData, &ulLen, NULL) == CK_TRUE)
   {
      ulCount = ulLen / sizeof(CK_LMS_TYPE);
      if (ulCount > MAX_HSS_LEVEL)
      {
         ulCount = MAX_HSS_LEVEL;
      }
      for (ulLoop = 0; ulLoop < ulCount; ulLoop++)
      {
         memcpy(&lms, pData + (ulLoop * sizeof(CK_LMS_TYPE)), sizeof(CK_LMS_TYPE));
         pTypeName = (const char*)P11Util_GetLMSTypeName(lms);
         memset(szName, 0, sizeof(szName));
         _snprintf(szName, sizeof(szName) - 1, "LMS-Type(Level %lu)", (unsigned long)(ulLoop + 1));
         memset(sz, 0, sizeof(sz));
         _snprintf(sz, sizeof(sz) - 1, "%lu (%s)", (unsigned long)lms,
            (pTypeName != NULL) ? pTypeName : "");
         DlgAttr_CollectRow(rows, pCount, szName, sz);
      }
      free(pData);
      pData = NULL;
   }
   if (P11_QueryAttrBytes(s_hObject, CKA_HSS_LMOTS_TYPES, &pData, &ulLen, NULL) == CK_TRUE)
   {
      ulCount = ulLen / sizeof(CK_LMOTS_TYPE);
      if (ulCount > MAX_HSS_LEVEL)
      {
         ulCount = MAX_HSS_LEVEL;
      }
      for (ulLoop = 0; ulLoop < ulCount; ulLoop++)
      {
         memcpy(&lmots, pData + (ulLoop * sizeof(CK_LMOTS_TYPE)), sizeof(CK_LMOTS_TYPE));
         pTypeName = (const char*)P11Util_GetLMOTSTypeName(lmots);
         memset(szName, 0, sizeof(szName));
         _snprintf(szName, sizeof(szName) - 1, "LMOTS-Type(Level %lu)", (unsigned long)(ulLoop + 1));
         memset(sz, 0, sizeof(sz));
         _snprintf(sz, sizeof(sz) - 1, "%lu (%s)", (unsigned long)lmots,
            (pTypeName != NULL) ? pTypeName : "");
         DlgAttr_CollectRow(rows, pCount, szName, sz);
      }
      free(pData);
   }
   DlgAttr_CollectAttrUlong(rows, pCount, "KeyRemaining", CKA_HSS_KEYS_REMAINING);
   DlgAttr_CollectAttrHex(rows, pCount, "PublicKey", CKA_PUBLIC_KEY);
}

static void DlgAttr_CollectDhDomain(ATTR_ROW* rows, int* pCount, CK_KEY_TYPE kt, BOOL bPublic)
{
   CK_BYTE* pData = NULL;
   CK_ULONG ulLen = 0;
   char sz[64];

   if (P11_QueryAttrBytes(s_hObject, CKA_PRIME, &pData, &ulLen, NULL) == CK_TRUE)
   {
      memset(sz, 0, sizeof(sz));
      _snprintf(sz, sizeof(sz) - 1, "%lu", (unsigned long)(ulLen << 3));
      DlgAttr_CollectRow(rows, pCount, "KeySize", sz);
      DlgAttr_FormatHexRow(rows, pCount, "Prime", pData, ulLen);
      if (pData != NULL)
      {
         free(pData);
      }
   }
   DlgAttr_CollectAttrHex(rows, pCount, "Base", CKA_BASE);
   if ((kt == CKK_X9_42_DH) || (kt == CKK_DSA))
   {
      DlgAttr_CollectAttrHex(rows, pCount, "SubPrime", CKA_SUBPRIME);
   }
   if (bPublic != FALSE)
   {
      DlgAttr_CollectAttrHex(rows, pCount, "PublicKey", CKA_VALUE);
   }
}

static void DlgAttr_CollectCert(ATTR_ROW* rows, int* pCount)
{
   CK_ULONG ulType = 0;
   char sz[64];

   if (DlgAttr_ReadUlong(CKA_CERTIFICATE_TYPE, &ulType) != FALSE)
   {
      memset(sz, 0, sizeof(sz));
      if (ulType == CKC_X_509)
      {
         strncpy(sz, "X.509", sizeof(sz) - 1);
      }
      else
      {
         _snprintf(sz, sizeof(sz) - 1, "0x%08X", (unsigned int)ulType);
      }
      DlgAttr_CollectRow(rows, pCount, "CertificateType", sz);
   }
   DlgAttr_CollectAttrHex(rows, pCount, "Subject", CKA_SUBJECT);
   DlgAttr_CollectAttrHex(rows, pCount, "Issuer", CKA_ISSUER);
   DlgAttr_CollectAttrHex(rows, pCount, "SerialNumber", CKA_SERIAL_NUMBER);
}

static void DlgAttr_CollectProprietary(ATTR_ROW* rows, int* pCount)
{
   CK_BYTE* pData = NULL;
   CK_ULONG ulLen = 0;
   CK_KEY_STATUS status;
   char sz[80];

   DlgAttr_CollectAttrBool(rows, pCount, "ccm_private", CKA_CCM_PRIVATE);
   if (s_ckClass != CKO_PUBLIC_KEY)
   {
      DlgAttr_CollectAttrBool(rows, pCount, "Assigned", CKA_ASSIGNED);
   }
   DlgAttr_CollectAttrHex(rows, pCount, "Sha1FingerPrint", CKA_FINGERPRINT_SHA1);
   DlgAttr_CollectAttrHex(rows, pCount, "Sha256FingerPrint", CKA_FINGERPRINT_SHA256);
   DlgAttr_CollectAttrHex(rows, pCount, "ouid", CKA_OUID);
   DlgAttr_CollectAttrHex(rows, pCount, "ekm_uid", CKA_EKM_UID);
   DlgAttr_CollectAttrHex(rows, pCount, "generic1", CKA_GENERIC_1);
   DlgAttr_CollectAttrHex(rows, pCount, "generic2", CKA_GENERIC_2);
   DlgAttr_CollectAttrHex(rows, pCount, "generic3", CKA_GENERIC_3);

   if (P11_QueryAttrBytes(s_hObject, CKA_KEY_STATUS, &pData, &ulLen, NULL) == CK_TRUE)
   {
      memset(&status, 0, sizeof(status));
      if ((pData != NULL) && (ulLen >= 2))
      {
         memcpy(&status, pData, (ulLen < sizeof(status)) ? ulLen : sizeof(status));
         memset(sz, 0, sizeof(sz));
         _snprintf(sz, sizeof(sz) - 1, "%02X", status.flags);
         DlgAttr_CollectRow(rows, pCount, "KeyStatusFlag", sz);
         memset(sz, 0, sizeof(sz));
         _snprintf(sz, sizeof(sz) - 1, "%u", (unsigned int)status.failedAuthCountLimit);
         DlgAttr_CollectRow(rows, pCount, "KeyStatusAuthLimit", sz);
      }
      if (pData != NULL)
      {
         free(pData);
      }
   }
   if (s_ckClass != CKO_PUBLIC_KEY)
   {
      CK_ULONG ulCount = 0;
      if (DlgAttr_ReadUlong(CKA_FAILED_KEY_AUTH_COUNT, &ulCount) != FALSE)
      {
         memset(sz, 0, sizeof(sz));
         _snprintf(sz, sizeof(sz) - 1, "%04X", (unsigned int)ulCount);
         DlgAttr_CollectRow(rows, pCount, "FailedKeyAuthCount", sz);
      }
   }
}

static void DlgAttr_FillExtra(ATTR_ROW* rows, int* pCount)
{
   CK_ULONG ulType = 0;
   CK_KEY_TYPE kt = 0;
   BOOL bPublic;
   BOOL bPrivate;

   if (s_ckClass == CKO_CERTIFICATE)
   {
      DlgAttr_CollectCert(rows, pCount);
      return;
   }
   if (s_bIsKey == FALSE)
   {
      return;
   }
   if (DlgAttr_ReadUlong(CKA_KEY_TYPE, &ulType) == FALSE)
   {
      return;
   }
   kt = (CK_KEY_TYPE)ulType;
   bPublic = (s_ckClass == CKO_PUBLIC_KEY) ? TRUE : FALSE;
   bPrivate = (s_ckClass == CKO_PRIVATE_KEY) ? TRUE : FALSE;

   switch (kt)
   {
   case CKK_ECDSA:
   case CKK_SM2:
   case CKK_EC_EDWARDS:
   case CKK_EC_EDWARDS_OLD:
   case CKK_EC_MONTGOMERY:
   case CKK_EC_MONTGOMERY_OLD:
      DlgAttr_CollectCurve(rows, pCount);
      DlgAttr_CollectAttrHex(rows, pCount, "PublicPoint", CKA_EC_POINT);
      break;
   case CKK_RSA:
      DlgAttr_CollectAttrHex(rows, pCount, "Modulus", CKA_MODULUS);
      DlgAttr_CollectAttrHex(rows, pCount, "PublicExponent", CKA_PUBLIC_EXPONENT);
      break;
   case CKK_DH:
   case CKK_X9_42_DH:
   case CKK_DSA:
      DlgAttr_CollectDhDomain(rows, pCount, kt, bPublic);
      break;
   case CKK_ML_DSA:
      DlgAttr_CollectParameterSet(rows, pCount, kt);
      if (bPublic != FALSE)
      {
         DlgAttr_CollectAttrHex(rows, pCount, "PublicKey", CKA_VALUE);
      }
      else if (bPrivate != FALSE)
      {
         DlgAttr_CollectParsedPublicKey(rows, pCount, kt);
      }
      break;
   case CKK_ML_KEM:
      DlgAttr_CollectParameterSet(rows, pCount, kt);
      if (bPublic != FALSE)
      {
         DlgAttr_CollectAttrHex(rows, pCount, "PublicKey", CKA_VALUE);
      }
      else if (bPrivate != FALSE)
      {
         DlgAttr_CollectParsedPublicKey(rows, pCount, kt);
      }
      break;
   case CKK_HSS:
      DlgAttr_CollectHss(rows, pCount, bPrivate);
      break;
   default:
      break;
   }

   DlgAttr_CollectProprietary(rows, pCount);
}

static void DlgAttr_FillDump(void)
{
   ATTR_ROW rows[ATTR_DUMP_MAX];
   int nCount = 0;
   int iLoop;
   CK_LONG nSize;
   char sz[168];
   CK_BYTE* pData;
   CK_ULONG ulLen;
   CK_RV rv;

   memset(rows, 0, sizeof(rows));

   nSize = P11_GetObjectSize(s_hObject);
   memset(sz, 0, sizeof(sz));
   if (nSize > 0)
   {
      _snprintf(sz, sizeof(sz) - 1, "%ld bytes", (long)nSize);
      DlgAttr_CollectRow(rows, &nCount, "ObjectSize", sz);
   }

   for (iLoop = 0; iLoop < ATTR_DUMP_COUNT; iLoop++)
   {
      if ((s_dump[iLoop].type == CKA_VALUE) && (s_bIsKey != FALSE))
      {
         continue;
      }
      pData = NULL;
      ulLen = 0;
      rv = CKR_OK;
      if (P11_QueryAttrBytes(s_hObject, s_dump[iLoop].type, &pData, &ulLen, &rv) != CK_TRUE)
      {
         if (rv == CKR_ATTRIBUTE_SENSITIVE)
         {
            DlgAttr_CollectRow(rows, &nCount, s_dump[iLoop].name, "(sensitive)");
         }
         continue;
      }

      memset(sz, 0, sizeof(sz));
      switch (s_dump[iLoop].fmt)
      {
      case AF_BOOL:
         if ((pData != NULL) && (ulLen >= 1))
         {
            strncpy(sz, (const char*)P11Util_DisplayBooleanName(pData[0] ? CK_TRUE : CK_FALSE),
               sizeof(sz) - 1);
         }
         DlgAttr_CollectRow(rows, &nCount, s_dump[iLoop].name, sz);
         break;
      case AF_ULONG:
         if ((pData != NULL) && (ulLen >= 4))
         {
            CK_ULONG ulVal = 0;
            if (ulLen >= sizeof(CK_ULONG))
            {
               memcpy(&ulVal, pData, sizeof(CK_ULONG));
            }
            else
            {
               unsigned int u32 = 0;
               memcpy(&u32, pData, 4);
               ulVal = (CK_ULONG)u32;
            }
            _snprintf(sz, sizeof(sz) - 1, "%lu", (unsigned long)ulVal);
         }
         DlgAttr_CollectRow(rows, &nCount, s_dump[iLoop].name, sz);
         break;
      case AF_CLASS:
         if ((pData != NULL) && (ulLen >= 4))
         {
            CK_OBJECT_CLASS ck = 0;
            if (ulLen >= sizeof(CK_OBJECT_CLASS))
            {
               memcpy(&ck, pData, sizeof(CK_OBJECT_CLASS));
            }
            else
            {
               unsigned int u32 = 0;
               memcpy(&u32, pData, 4);
               ck = (CK_OBJECT_CLASS)u32;
            }
            strncpy(sz, (const char*)P11Util_DisplayClassName(ck), sizeof(sz) - 1);
         }
         DlgAttr_CollectRow(rows, &nCount, s_dump[iLoop].name, sz);
         break;
      case AF_KEYTYPE:
         if ((pData != NULL) && (ulLen >= 4))
         {
            CK_KEY_TYPE kt = 0;
            if (ulLen >= sizeof(CK_KEY_TYPE))
            {
               memcpy(&kt, pData, sizeof(CK_KEY_TYPE));
            }
            else
            {
               unsigned int u32 = 0;
               memcpy(&u32, pData, 4);
               kt = (CK_KEY_TYPE)u32;
            }
            GUI_FormatKeyTypeName(kt, sz, sizeof(sz));
            if (sz[0] != 0)
            {
               char szKt[168];
               memset(szKt, 0, sizeof(szKt));
               _snprintf(szKt, sizeof(szKt) - 1, "%s (0x%08X)", sz, (unsigned int)kt);
               strncpy(sz, szKt, sizeof(sz) - 1);
            }
         }
         DlgAttr_CollectRow(rows, &nCount, s_dump[iLoop].name, sz);
         break;
      case AF_TEXT:
         if (pData != NULL)
         {
            unsigned int uCopy = (ulLen < (sizeof(sz) - 1)) ? (unsigned int)ulLen : (sizeof(sz) - 1);
            memcpy(sz, pData, uCopy);
         }
         else if (ulLen == 0)
         {
            strncpy(sz, "(empty)", sizeof(sz) - 1);
         }
         DlgAttr_CollectRow(rows, &nCount, s_dump[iLoop].name, sz);
         break;
      case AF_DATE:
         if ((pData != NULL) && (ulLen >= sizeof(CK_DATE)))
         {
            CK_DATE* pDate = (CK_DATE*)pData;
            _snprintf(sz, sizeof(sz) - 1, "%.4s-%.2s-%.2s", pDate->year, pDate->month, pDate->day);
            DlgAttr_CollectRow(rows, &nCount, s_dump[iLoop].name, sz);
         }
         break;
      case AF_HEX:
      default:
         DlgAttr_FormatHexRow(rows, &nCount, s_dump[iLoop].name, pData, ulLen);
         break;
      }
      if (pData != NULL)
      {
         free(pData);
      }
   }

   DlgAttr_FillExtra(rows, &nCount);
   DlgAttr_CommitDump(rows, nCount);
}

static void DlgAttr_LoadEdits(void)
{
   CK_BYTE* pData;
   CK_ULONG ulLen;
   int iLoop;
   char szType[64];
   char szSum[192];
   const char* pClass;

   s_bLoading = TRUE;
   s_ckClass = P11_GetObjectClass(s_hObject);
   s_bIsKey = (s_ckClass == CKO_SECRET_KEY) || (s_ckClass == CKO_PUBLIC_KEY) ||
      (s_ckClass == CKO_PRIVATE_KEY);
   s_bIsData = (s_ckClass == CKO_DATA);

   pClass = (const char*)P11Util_DisplayClassName(s_ckClass);
   memset(szType, 0, sizeof(szType));
   if (s_bIsKey != FALSE)
   {
      GUI_FormatKeyTypeName(P11_GetKeyType(s_hObject), szType, sizeof(szType));
   }
   memset(szSum, 0, sizeof(szSum));
   if (szType[0] != 0)
   {
      _snprintf(szSum, sizeof(szSum) - 1, "Handle %lu    %s    %s",
         (unsigned long)s_hObject, (pClass != NULL) ? pClass : "", szType);
   }
   else
   {
      _snprintf(szSum, sizeof(szSum) - 1, "Handle %lu    %s",
         (unsigned long)s_hObject, (pClass != NULL) ? pClass : "");
   }
   SetWindowTextA(s_hSummary, szSum);

   memset(s_szOrigLabel, 0, sizeof(s_szOrigLabel));
   pData = NULL;
   ulLen = 0;
   if (P11_QueryAttrBytes(s_hObject, CKA_LABEL, &pData, &ulLen, NULL) == CK_TRUE)
   {
      if ((pData != NULL) && (ulLen > 0))
      {
         if (ulLen >= sizeof(s_szOrigLabel))
         {
            ulLen = sizeof(s_szOrigLabel) - 1;
         }
         memcpy(s_szOrigLabel, pData, ulLen);
      }
      if (pData != NULL)
      {
         free(pData);
      }
   }
   SetWindowTextA(s_hLabel, s_szOrigLabel);

   memset(s_szOrigId, 0, sizeof(s_szOrigId));
   s_bHasId = CK_FALSE;
   pData = NULL;
   ulLen = 0;
   if (P11_QueryAttrBytes(s_hObject, CKA_ID, &pData, &ulLen, NULL) == CK_TRUE)
   {
      s_bHasId = CK_TRUE;
      DlgAttr_BytesToHex(pData, ulLen, s_szOrigId, sizeof(s_szOrigId));
      if (pData != NULL)
      {
         free(pData);
      }
   }
   SetWindowTextA(s_hId, s_szOrigId);
   ShowWindow(GetDlgItem(s_hDlg, IDC_ATTR_LBL_ID), s_bIsKey ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hId, s_bIsKey ? SW_SHOW : SW_HIDE);

   memset(s_szOrigApp, 0, sizeof(s_szOrigApp));
   s_bHasApp = CK_FALSE;
   pData = NULL;
   ulLen = 0;
   if (P11_QueryAttrBytes(s_hObject, CKA_APPLICATION, &pData, &ulLen, NULL) == CK_TRUE)
   {
      s_bHasApp = CK_TRUE;
      if ((pData != NULL) && (ulLen > 0))
      {
         if (ulLen >= sizeof(s_szOrigApp))
         {
            ulLen = sizeof(s_szOrigApp) - 1;
         }
         memcpy(s_szOrigApp, pData, ulLen);
      }
      if (pData != NULL)
      {
         free(pData);
      }
   }
   SetWindowTextA(s_hApp, s_szOrigApp);

   memset(s_szOrigValue, 0, sizeof(s_szOrigValue));
   s_bHasValue = CK_FALSE;
   pData = NULL;
   ulLen = 0;
   if (P11_QueryAttrBytes(s_hObject, CKA_VALUE, &pData, &ulLen, NULL) == CK_TRUE)
   {
      s_bHasValue = CK_TRUE;
      DlgAttr_BytesToHex(pData, ulLen, s_szOrigValue, sizeof(s_szOrigValue));
      if (pData != NULL)
      {
         free(pData);
      }
   }
   SetWindowTextA(s_hValue, s_szOrigValue);
   ShowWindow(s_hLblApp, s_bIsData ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hApp, s_bIsData ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hLblValue, s_bIsData ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hValue, s_bIsData ? SW_SHOW : SW_HIDE);

   for (iLoop = 0; iLoop < ATTR_FLAG_COUNT; iLoop++)
   {
      CK_BBOOL bVal = CK_FALSE;
      BOOL bShow;

      s_flags[iLoop].bPresent = CK_FALSE;
      s_flags[iLoop].bOrig = CK_FALSE;
      bShow = (s_flags[iLoop].bKeyOnly == FALSE) || (s_bIsKey != FALSE);
      if ((bShow != FALSE) &&
         (P11_QueryAttrBool(s_hObject, s_flags[iLoop].type, &bVal) == CK_TRUE))
      {
         s_flags[iLoop].bPresent = CK_TRUE;
         s_flags[iLoop].bOrig = bVal;
      }
      DlgAttr_SetChecked(s_flags[iLoop].hChk, s_flags[iLoop].bOrig);
      ShowWindow(s_flags[iLoop].hChk, (bShow && (s_flags[iLoop].bPresent == CK_TRUE)) ? SW_SHOW : SW_HIDE);
   }
   s_bLoading = FALSE;
   if (s_hFileAttr != NULL)
   {
      if ((int)SendMessageA(s_hFileAttr, CB_GETCURSEL, 0, 0) < 0)
      {
         SendMessageA(s_hFileAttr, CB_SETCURSEL, (WPARAM)((s_bIsData != FALSE) ? 1 : 0), 0);
      }
   }
   DlgAttr_UpdateApply();
}

static BOOL DlgAttr_FlagShown(const ATTR_FLAG* pFlag)
{
   if (pFlag == NULL)
   {
      return FALSE;
   }
   if ((pFlag->bKeyOnly != FALSE) && (s_bIsKey == FALSE))
   {
      return FALSE;
   }
   return (pFlag->bPresent == CK_TRUE) ? TRUE : FALSE;
}

static BOOL DlgAttr_IsDirty(void)
{
   char sz[DLG_HEX_MAX + 2];
   int iLoop;

   if (s_bLoading != FALSE)
   {
      return FALSE;
   }

   memset(sz, 0, sizeof(sz));
   GetWindowTextA(s_hLabel, sz, DLG_MAX_LABEL);
   if (strcmp(sz, s_szOrigLabel) != 0)
   {
      return TRUE;
   }

   if (s_bIsKey != FALSE)
   {
      memset(sz, 0, sizeof(sz));
      GetWindowTextA(s_hId, sz, sizeof(sz));
      DlgAttr_StripHex(sz);
      if (strcmp(sz, s_szOrigId) != 0)
      {
         return TRUE;
      }
   }

   if (s_bIsData != FALSE)
   {
      memset(sz, 0, sizeof(sz));
      GetWindowTextA(s_hApp, sz, DLG_APP_MAX);
      if (strcmp(sz, s_szOrigApp) != 0)
      {
         return TRUE;
      }
      memset(sz, 0, sizeof(sz));
      GetWindowTextA(s_hValue, sz, sizeof(sz));
      DlgAttr_StripHex(sz);
      if (strcmp(sz, s_szOrigValue) != 0)
      {
         return TRUE;
      }
   }

   for (iLoop = 0; iLoop < ATTR_FLAG_COUNT; iLoop++)
   {
      if (DlgAttr_FlagShown(&s_flags[iLoop]) == FALSE)
      {
         continue;
      }
      if (DlgAttr_IsChecked(s_flags[iLoop].hChk) != s_flags[iLoop].bOrig)
      {
         return TRUE;
      }
   }
   return FALSE;
}

static void DlgAttr_UpdateApply(void)
{
   HWND hApply;

   if (s_hDlg == NULL)
   {
      return;
   }
   hApply = GetDlgItem(s_hDlg, IDC_ATTR_APPLY);
   if (hApply != NULL)
   {
      EnableWindow(hApply, (s_bLoading == FALSE) && (DlgAttr_IsDirty() != FALSE));
   }
}

static int DlgAttr_PlaceFlags(int y, int cx)
{
   int x = DLG_MARGIN;
   int iLoop;
   int nWidth;

   for (iLoop = 0; iLoop < ATTR_FLAG_COUNT; iLoop++)
   {
      if (DlgAttr_FlagShown(&s_flags[iLoop]) == FALSE)
      {
         continue;
      }
      nWidth = 90;
      if ((strcmp(s_flags[iLoop].caption, "Extractable") == 0) ||
         (strcmp(s_flags[iLoop].caption, "Encapsulate") == 0) ||
         (strcmp(s_flags[iLoop].caption, "Decapsulate") == 0) ||
         (strcmp(s_flags[iLoop].caption, "Modifiable") == 0))
      {
         nWidth = 96;
      }
      if ((x + nWidth) > (cx - DLG_MARGIN))
      {
         x = DLG_MARGIN;
         y += 20;
      }
      MoveWindow(s_flags[iLoop].hChk, x, y, nWidth, 18, TRUE);
      x += nWidth + 8;
   }
   return y + 22;
}

static void DlgAttr_Layout(int cx, int cy)
{
   int y;
   int editX;
   int editW;
   int listH;
   int yBtn;
   BOOL bData = s_bIsData;
   BOOL bKey = s_bIsKey;

   if (cx < 420)
   {
      cx = 420;
   }
   if (cy < 320)
   {
      cy = 320;
   }

   editX = DLG_MARGIN + DLG_LABEL_W + 8;
   editW = cx - editX - DLG_MARGIN;
   if (editW < 140)
   {
      editW = 140;
   }

   y = DLG_MARGIN;
   MoveWindow(s_hSummary, DLG_MARGIN, y, cx - (2 * DLG_MARGIN), 18, TRUE);
   y += 22;

   yBtn = cy - DLG_MARGIN - DLG_BTN_H;
   listH = yBtn - 150;
   if (bData != FALSE)
   {
      listH -= 56;
   }
   if (bKey != FALSE)
   {
      listH -= 44;
   }
   if (listH < 80)
   {
      listH = 80;
   }
   MoveWindow(s_hList, DLG_MARGIN, y, cx - (2 * DLG_MARGIN), listH, TRUE);
   ListView_SetColumnWidth(s_hList, 1, cx - (2 * DLG_MARGIN) - 140 - 28);
   y += listH + 8;

   MoveWindow(GetDlgItem(s_hDlg, IDC_ATTR_LBL_LABEL), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hLabel, editX, y, editW, DLG_EDIT_H, TRUE);
   y += DLG_EDIT_H + 6;

   if (bKey != FALSE)
   {
      MoveWindow(GetDlgItem(s_hDlg, IDC_ATTR_LBL_ID), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
      MoveWindow(s_hId, editX, y, editW, DLG_EDIT_H, TRUE);
      y += DLG_EDIT_H + 6;
   }
   if (bData != FALSE)
   {
      MoveWindow(s_hLblApp, DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
      MoveWindow(s_hApp, editX, y, editW, DLG_EDIT_H, TRUE);
      y += DLG_EDIT_H + 6;
      MoveWindow(s_hLblValue, DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
      MoveWindow(s_hValue, editX, y, editW, DLG_EDIT_H, TRUE);
      y += DLG_EDIT_H + 6;
   }

   y = DlgAttr_PlaceFlags(y + 2, cx);
   MoveWindow(s_hStatus, DLG_MARGIN, yBtn - 22, cx - (2 * DLG_MARGIN), 18, TRUE);
   MoveWindow(s_hFileAttr, DLG_MARGIN, yBtn, DLG_FILE_ATTR_W, DLG_COMBO_DROP, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_ATTR_SAVE),
      DLG_MARGIN + DLG_FILE_ATTR_W + 8, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_ATTR_LOAD),
      DLG_MARGIN + DLG_FILE_ATTR_W + 8 + DLG_BTN_W + 8, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_ATTR_APPLY), cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_ATTR_CLOSE), cx - DLG_MARGIN - DLG_BTN_W, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static void DlgAttr_Reload(void)
{
   DlgAttr_LoadEdits();
   DlgAttr_FillDump();
   {
      RECT rc;
      GetClientRect(s_hDlg, &rc);
      DlgAttr_Layout(rc.right - rc.left, rc.bottom - rc.top);
   }
}

static int DlgAttr_ApplyBool(ATTR_FLAG* pFlag)
{
   CK_BBOOL bNow;

   if ((pFlag == NULL) || (pFlag->bPresent != CK_TRUE) || (DlgAttr_FlagShown(pFlag) == FALSE))
   {
      return 0;
   }
   bNow = DlgAttr_IsChecked(pFlag->hChk);
   if (bNow == pFlag->bOrig)
   {
      return 0;
   }
   if (P11_SetAttributeBoolean(s_hObject, pFlag->type, bNow) == CK_TRUE)
   {
      pFlag->bOrig = bNow;
      return 1;
   }
   return -1;
}

static void DlgAttr_DoApply(void)
{
   char szLabel[DLG_MAX_LABEL];
   char szId[(DLG_CKA_ID_MAX * 2) + 2];
   char szApp[DLG_APP_MAX];
   char szValue[DLG_HEX_MAX + 2];
   int nOk = 0;
   int nFail = 0;
   int iLoop;
   int nFlag;
   CK_LONG nIdLen;
   char szStatus[128];

   if (DlgAttr_IsDirty() == FALSE)
   {
      DlgAttr_SetStatus("No attributes changed.");
      DlgAttr_UpdateApply();
      return;
   }

   EnableWindow(GetDlgItem(s_hDlg, IDC_ATTR_APPLY), FALSE);
   DlgAttr_SetStatus("Updating...");
   UpdateWindow(s_hStatus);

   memset(szLabel, 0, sizeof(szLabel));
   GetWindowTextA(s_hLabel, szLabel, sizeof(szLabel));
   if (strcmp(szLabel, s_szOrigLabel) != 0)
   {
      if (P11_SetAttributeString(s_hObject, CKA_LABEL, (CK_CHAR_PTR)szLabel) == CK_TRUE)
      {
         strncpy(s_szOrigLabel, szLabel, sizeof(s_szOrigLabel) - 1);
         nOk++;
      }
      else
      {
         nFail++;
      }
   }

   if (s_bIsKey != FALSE)
   {
      memset(szId, 0, sizeof(szId));
      GetWindowTextA(s_hId, szId, sizeof(szId));
      DlgAttr_StripHex(szId);
      if (strcmp(szId, s_szOrigId) != 0)
      {
         if (szId[0] == 0)
         {
            if (P11_SetAttributeArray(s_hObject, CKA_ID, (CK_CHAR_PTR)"", 0) == CK_TRUE)
            {
               s_szOrigId[0] = 0;
               nOk++;
            }
            else
            {
               nFail++;
            }
         }
         else
         {
            nIdLen = (CK_LONG)str_StringtoByteArray((CK_CHAR_PTR)szId, (CK_ULONG)strlen(szId));
            if (nIdLen == 0)
            {
               DlgAttr_SetStatus("CKA_ID must be hexadecimal.");
               SetFocus(s_hId);
               DlgAttr_UpdateApply();
               return;
            }
            if (P11_SetAttributeArray(s_hObject, CKA_ID, (CK_CHAR_PTR)szId, (CK_ULONG)nIdLen) == CK_TRUE)
            {
               DlgAttr_BytesToHex((const CK_BYTE*)szId, (CK_ULONG)nIdLen, s_szOrigId, sizeof(s_szOrigId));
               SetWindowTextA(s_hId, s_szOrigId);
               nOk++;
            }
            else
            {
               nFail++;
            }
         }
      }
   }

   if (s_bIsData != FALSE)
   {
      memset(szApp, 0, sizeof(szApp));
      GetWindowTextA(s_hApp, szApp, sizeof(szApp));
      if (strcmp(szApp, s_szOrigApp) != 0)
      {
         if (P11_SetAttributeString(s_hObject, CKA_APPLICATION, (CK_CHAR_PTR)szApp) == CK_TRUE)
         {
            strncpy(s_szOrigApp, szApp, sizeof(s_szOrigApp) - 1);
            nOk++;
         }
         else
         {
            nFail++;
         }
      }

      memset(szValue, 0, sizeof(szValue));
      GetWindowTextA(s_hValue, szValue, sizeof(szValue));
      DlgAttr_StripHex(szValue);
      if (strcmp(szValue, s_szOrigValue) != 0)
      {
         if (szValue[0] == 0)
         {
            if (P11_SetAttributeArray(s_hObject, CKA_VALUE, (CK_CHAR_PTR)"", 0) == CK_TRUE)
            {
               s_szOrigValue[0] = 0;
               nOk++;
            }
            else
            {
               nFail++;
            }
         }
         else
         {
            nIdLen = (CK_LONG)str_StringtoByteArray((CK_CHAR_PTR)szValue, (CK_ULONG)strlen(szValue));
            if (nIdLen == 0)
            {
               DlgAttr_SetStatus("Value must be hexadecimal.");
               SetFocus(s_hValue);
               DlgAttr_UpdateApply();
               return;
            }
            if (P11_SetAttributeArray(s_hObject, CKA_VALUE, (CK_CHAR_PTR)szValue, (CK_ULONG)nIdLen) == CK_TRUE)
            {
               DlgAttr_BytesToHex((const CK_BYTE*)szValue, (CK_ULONG)nIdLen, s_szOrigValue, sizeof(s_szOrigValue));
               SetWindowTextA(s_hValue, s_szOrigValue);
               nOk++;
            }
            else
            {
               nFail++;
            }
         }
      }
   }

   for (iLoop = 0; iLoop < ATTR_FLAG_COUNT; iLoop++)
   {
      nFlag = DlgAttr_ApplyBool(&s_flags[iLoop]);
      if (nFlag > 0)
      {
         nOk++;
      }
      else if (nFlag < 0)
      {
         nFail++;
      }
   }

   if ((nOk != 0) || (nFail != 0))
   {
      DlgAttr_SetStatus("Refreshing attributes...");
      UpdateWindow(s_hStatus);
      DlgAttr_FillDump();
   }

   memset(szStatus, 0, sizeof(szStatus));
   if ((nOk == 0) && (nFail == 0))
   {
      strncpy(szStatus, "No attributes changed.", sizeof(szStatus) - 1);
   }
   else if (nFail == 0)
   {
      _snprintf(szStatus, sizeof(szStatus) - 1, "%d attribute(s) updated.", nOk);
   }
   else
   {
      _snprintf(szStatus, sizeof(szStatus) - 1, "%d updated, %d failed (not modifiable?).", nOk, nFail);
   }
   DlgAttr_SetStatus(szStatus);
   DlgAttr_UpdateApply();
}

static CK_ATTRIBUTE_TYPE DlgAttr_SelectedFileAttr(void)
{
   int iSel;

   if (s_hFileAttr == NULL)
   {
      return CKA_ID;
   }
   iSel = (int)SendMessageA(s_hFileAttr, CB_GETCURSEL, 0, 0);
   if (iSel == 1)
   {
      return CKA_VALUE;
   }
   if (iSel == 2)
   {
      return CKA_APPLICATION;
   }
   return CKA_ID;
}

static const char* DlgAttr_FileAttrName(CK_ATTRIBUTE_TYPE type)
{
   if (type == CKA_VALUE)
   {
      return "value";
   }
   if (type == CKA_APPLICATION)
   {
      return "application";
   }
   return "id";
}

static BOOL DlgAttr_PickFile(BOOL bSave, CK_ATTRIBUTE_TYPE type, char* szPath, unsigned int pathSize)
{
   OPENFILENAMEA ofn;
   static const char kFilterText[] = "Text files (*.txt)\0*.txt\0All files (*.*)\0*.*\0";
   static const char kFilterBin[] = "Binary files (*.bin)\0*.bin\0All files (*.*)\0*.*\0";
   const char* pName;

   if ((szPath == NULL) || (pathSize < 8))
   {
      return FALSE;
   }

   pName = DlgAttr_FileAttrName(type);
   memset(szPath, 0, pathSize);
   _snprintf(szPath, pathSize - 1, "attr-%lu-%s.%s",
      (unsigned long)s_hObject, pName,
      (type == CKA_APPLICATION) ? "txt" : "bin");

   memset(&ofn, 0, sizeof(ofn));
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = s_hDlg;
   ofn.lpstrFilter = (type == CKA_APPLICATION) ? kFilterText : kFilterBin;
   ofn.lpstrFile = szPath;
   ofn.nMaxFile = pathSize;
   ofn.Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
   if (bSave != FALSE)
   {
      ofn.Flags |= OFN_OVERWRITEPROMPT;
      ofn.lpstrTitle = "Save attribute";
      ofn.lpstrDefExt = (type == CKA_APPLICATION) ? "txt" : "bin";
      return (GetSaveFileNameA(&ofn) != FALSE) ? TRUE : FALSE;
   }
   ofn.Flags |= OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
   ofn.lpstrTitle = "Load attribute";
   return (GetOpenFileNameA(&ofn) != FALSE) ? TRUE : FALSE;
}

static void DlgAttr_DoSave(void)
{
   CK_ATTRIBUTE_TYPE type;
   char szPath[GUI_PATH_MAX];
   char szStatus[GUI_STATUS_TEXT_MAX];
   CK_BYTE* pData = NULL;
   CK_ULONG ulLen = 0;
   CK_RV rv = CKR_OK;
   CK_BBOOL bBinary;
   CK_CHAR dummy = 0;
   CK_LONG nWritten;

   type = DlgAttr_SelectedFileAttr();
   if (DlgAttr_PickFile(TRUE, type, szPath, sizeof(szPath)) == FALSE)
   {
      return;
   }

   bBinary = (type == CKA_APPLICATION) ? CK_FALSE : CK_TRUE;
   if (P11_QueryAttrBytes(s_hObject, type, &pData, &ulLen, &rv) != CK_TRUE)
   {
      memset(szStatus, 0, sizeof(szStatus));
      if (rv == CKR_ATTRIBUTE_SENSITIVE)
      {
         strncpy(szStatus, "Cannot save: attribute is sensitive.", sizeof(szStatus) - 1);
      }
      else
      {
         _snprintf(szStatus, sizeof(szStatus) - 1, "Cannot read %s: %s",
            DlgAttr_FileAttrName(type), (const char*)P11Util_DisplayErrorName(rv));
      }
      DlgAttr_SetStatus(szStatus);
      return;
   }

   nWritten = File_Write((CK_CHAR_PTR)szPath,
      (pData != NULL) ? (CK_CHAR_PTR)pData : &dummy,
      ulLen, bBinary);
   if (pData != NULL)
   {
      free(pData);
   }
   memset(szStatus, 0, sizeof(szStatus));
   if (nWritten > 0)
   {
      _snprintf(szStatus, sizeof(szStatus) - 1, "Saved %s: %ld bytes to file.",
         DlgAttr_FileAttrName(type), (long)nWritten);
   }
   else if ((nWritten == 0) && (ulLen == 0))
   {
      _snprintf(szStatus, sizeof(szStatus) - 1, "Saved empty %s to file.",
         DlgAttr_FileAttrName(type));
   }
   else
   {
      _snprintf(szStatus, sizeof(szStatus) - 1, "Cannot write file: %s", szPath);
   }
   DlgAttr_SetStatus(szStatus);
}

static void DlgAttr_DoLoad(void)
{
   CK_ATTRIBUTE_TYPE type;
   char szPath[GUI_PATH_MAX];
   char szStatus[GUI_STATUS_TEXT_MAX];
   CK_CHAR_PTR pData = NULL;
   CK_ULONG ulLen;
   CK_BBOOL bBinary;

   type = DlgAttr_SelectedFileAttr();
   if (DlgAttr_PickFile(FALSE, type, szPath, sizeof(szPath)) == FALSE)
   {
      return;
   }

   bBinary = (type == CKA_APPLICATION) ? CK_FALSE : CK_TRUE;
   ulLen = File_Read((CK_CHAR_PTR)szPath, &pData, bBinary);
   if ((ulLen == 0) || (pData == NULL))
   {
      DlgAttr_SetStatus("Cannot read file.");
      if (pData != NULL)
      {
         free(pData);
      }
      return;
   }
   if ((type == CKA_APPLICATION) && (str_CheckASCII(pData, ulLen) != CK_TRUE))
   {
      DlgAttr_SetStatus("Invalid file format (application must be ASCII).");
      free(pData);
      return;
   }

   if (P11_SetAttributeArray(s_hObject, type, pData, ulLen) != CK_TRUE)
   {
      memset(szStatus, 0, sizeof(szStatus));
      _snprintf(szStatus, sizeof(szStatus) - 1, "Failed to set %s.", DlgAttr_FileAttrName(type));
      DlgAttr_SetStatus(szStatus);
      free(pData);
      return;
   }
   free(pData);
   DlgAttr_Reload();
   memset(szStatus, 0, sizeof(szStatus));
   _snprintf(szStatus, sizeof(szStatus) - 1, "Loaded %s: %lu bytes.",
      DlgAttr_FileAttrName(type), (unsigned long)ulLen);
   DlgAttr_SetStatus(szStatus);
   DlgAttr_UpdateApply();
}

static HWND DlgAttr_CreateLabel(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("STATIC", sText, WS_CHILD | WS_VISIBLE,
      0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static HWND DlgAttr_CreateEdit(HWND hWnd, int id)
{
   return CreateWindowA("EDIT", "",
      WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
      0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static HWND DlgAttr_CreateCheck(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("BUTTON", sText,
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
      0, 0, 90, 18, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static LRESULT CALLBACK DlgAttr_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      {
         LVCOLUMNA col;
         HWND hCtrl;
         int iLoop;

         s_hDlg = hWnd;
         s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

         s_hSummary = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_ATTR_SUMMARY, NULL, NULL);

         s_hList = CreateWindowA(WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | WS_VSCROLL |
            LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER,
            0, 0, 100, 100, hWnd, (HMENU)(INT_PTR)IDC_ATTR_LIST, NULL, NULL);

         DlgAttr_CreateLabel(hWnd, "Label:", IDC_ATTR_LBL_LABEL);
         s_hLabel = DlgAttr_CreateEdit(hWnd, IDC_ATTR_LABEL);
         DlgAttr_CreateLabel(hWnd, "CKA_ID:", IDC_ATTR_LBL_ID);
         s_hId = DlgAttr_CreateEdit(hWnd, IDC_ATTR_ID);
         s_hLblApp = DlgAttr_CreateLabel(hWnd, "Application:", IDC_ATTR_LBL_APP);
         s_hApp = DlgAttr_CreateEdit(hWnd, IDC_ATTR_APP);
         s_hLblValue = DlgAttr_CreateLabel(hWnd, "Value:", IDC_ATTR_LBL_VALUE);
         s_hValue = DlgAttr_CreateEdit(hWnd, IDC_ATTR_VALUE);

         for (iLoop = 0; iLoop < ATTR_FLAG_COUNT; iLoop++)
         {
            s_flags[iLoop].hChk = DlgAttr_CreateCheck(hWnd, s_flags[iLoop].caption, s_flags[iLoop].id);
         }

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_ATTR_STATUS, NULL, NULL);

         s_hFileAttr = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, DLG_FILE_ATTR_W, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_ATTR_FILEATTR, NULL, NULL);
         SendMessageA(s_hFileAttr, CB_ADDSTRING, 0, (LPARAM)"id");
         SendMessageA(s_hFileAttr, CB_ADDSTRING, 0, (LPARAM)"value");
         SendMessageA(s_hFileAttr, CB_ADDSTRING, 0, (LPARAM)"application");

         CreateWindowA("BUTTON", "Save",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_ATTR_SAVE, NULL, NULL);
         CreateWindowA("BUTTON", "Load",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_ATTR_LOAD, NULL, NULL);
         CreateWindowA("BUTTON", "Apply",
            WS_CHILD | WS_VISIBLE | WS_DISABLED | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_ATTR_APPLY, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_ATTR_CLOSE, NULL, NULL);

         SendMessageA(s_hLabel, EM_SETLIMITTEXT, DLG_MAX_LABEL - 1, 0);
         SendMessageA(s_hId, EM_SETLIMITTEXT, (DLG_CKA_ID_MAX * 2) - 1, 0);
         SendMessageA(s_hApp, EM_SETLIMITTEXT, DLG_APP_MAX - 1, 0);
         SendMessageA(s_hValue, EM_SETLIMITTEXT, DLG_HEX_MAX - 1, 0);

         for (hCtrl = GetWindow(hWnd, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
         {
            SendMessageA(hCtrl, WM_SETFONT, (WPARAM)s_hFont, TRUE);
         }

         GUI_ThemeMarkStatus(s_hStatus);
         GUI_ThemeStyleList(s_hList);
         memset(&col, 0, sizeof(col));
         col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
         col.cx = 140;
         col.pszText = "Attribute";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
         col.cx = 280;
         col.iSubItem = 1;
         col.pszText = "Value";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);

         DlgAttr_Reload();
         DlgAttr_UpdateApply();
      }
      return 0;

   case WM_CTLCOLOREDIT:
   case WM_CTLCOLORSTATIC:
      {
         LRESULT lBrush = GUI_ThemeCtlColor(uMsg, wParam, lParam);
         if (lBrush != 0)
         {
            return lBrush;
         }
      }
      break;

   case WM_SIZE:
      DlgAttr_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 640;
         pMin->ptMinTrackSize.y = 420;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_ATTR_SAVE:
         DlgAttr_DoSave();
         return 0;
      case IDC_ATTR_LOAD:
         DlgAttr_DoLoad();
         return 0;
      case IDC_ATTR_APPLY:
      case IDOK:
         DlgAttr_DoApply();
         return 0;
      case IDC_ATTR_CLOSE:
      case IDCANCEL:
         DestroyWindow(hWnd);
         return 0;
      case IDC_ATTR_LABEL:
      case IDC_ATTR_ID:
      case IDC_ATTR_APP:
      case IDC_ATTR_VALUE:
         if (HIWORD(wParam) == EN_CHANGE)
         {
            DlgAttr_UpdateApply();
         }
         return 0;
      case IDC_ATTR_PRIVATE:
      case IDC_ATTR_MODIFIABLE:
      case IDC_ATTR_EXTRACTABLE:
      case IDC_ATTR_ENCRYPT:
      case IDC_ATTR_DECRYPT:
      case IDC_ATTR_SIGN:
      case IDC_ATTR_VERIFY:
      case IDC_ATTR_WRAP:
      case IDC_ATTR_UNWRAP:
      case IDC_ATTR_DERIVE:
      case IDC_ATTR_ENCAPSULATE:
      case IDC_ATTR_DECAPSULATE:
         if (HIWORD(wParam) == BN_CLICKED)
         {
            DlgAttr_UpdateApply();
         }
         return 0;
      default:
         break;
      }
      break;

   case WM_CLOSE:
      DestroyWindow(hWnd);
      return 0;

   case WM_DESTROY:
      s_hDlg = NULL;
      s_hSummary = NULL;
      s_hList = NULL;
      s_hStatus = NULL;
      s_hLabel = NULL;
      s_hId = NULL;
      s_hApp = NULL;
      s_hValue = NULL;
      s_hLblApp = NULL;
      s_hLblValue = NULL;
      s_hFileAttr = NULL;
      {
         int iLoop;
         for (iLoop = 0; iLoop < ATTR_FLAG_COUNT; iLoop++)
         {
            s_flags[iLoop].hChk = NULL;
         }
      }
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }

   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

/*
    FUNCTION:        void DlgAttributes_Show(HWND hwndParent, CK_OBJECT_HANDLE hObject)
*/
void DlgAttributes_Show(HWND hwndParent, CK_OBJECT_HANDLE hObject)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      MessageBoxA(hwndParent, "Not logged in.", "Attributes", MB_OK | MB_ICONWARNING);
      return;
   }
   if (P11_FindObject(hObject) != CK_TRUE)
   {
      MessageBoxA(hwndParent, "Object not found.", "Attributes", MB_OK | MB_ICONWARNING);
      return;
   }

   s_hObject = hObject;
   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgAttr_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_ATTR_CLASS;
   RegisterClassExA(&wc);

   s_bDone = FALSE;
   if (hwndParent != NULL)
   {
      GetWindowRect(hwndParent, &rc);
   }
   else
   {
      rc.left = 200;
      rc.top = 160;
   }

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_ATTR_CLASS, "Object attributes",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 36, rc.top + 36, 700, 540,
      hwndParent, NULL, wc.hInstance, NULL);
   if (hDlg == NULL)
   {
      return;
   }

   if (hwndParent != NULL)
   {
      EnableWindow(hwndParent, FALSE);
   }
   ShowWindow(hDlg, SW_SHOW);
   UpdateWindow(hDlg);

   while ((s_bDone == FALSE) && (GetMessageA(&msg, NULL, 0, 0) > 0))
   {
      if (msg.message == WM_QUIT)
      {
         s_bDone = TRUE;
         PostQuitMessage((int)msg.wParam);
         break;
      }
      if ((hDlg == NULL) || (IsDialogMessageA(hDlg, &msg) == FALSE))
      {
         TranslateMessage(&msg);
         DispatchMessageA(&msg);
      }
   }

   if (hwndParent != NULL)
   {
      EnableWindow(hwndParent, TRUE);
      SetForegroundWindow(hwndParent);
   }
}
