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

#define _DLG_DERIVE_C

#ifdef OS_WIN32
#include <windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "p11.h"
#include "p11util.h"
#include "p11query.h"
#include "str.h"
#include "gui.h"
#include "gui_theme.h"
#include "dlg_derive.h"

#define DLG_DERIVE_CLASS          "LunaKmuDerive"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               110
#define DLG_COMBO_DROP            240
#define DLG_MAX_LABEL             100
#define DLG_CKA_ID_MAX            256
#define DLG_KDF_HEX_MAX           256
#define DLG_CHK_W                 108
#define DLG_CHK_H                 18

#define IDC_DRV_HANDLE            3301
#define IDC_DRV_LABEL             3302
#define IDC_DRV_TYPE              3303
#define IDC_DRV_SIZE              3304
#define IDC_DRV_MECH              3305
#define IDC_DRV_KDF_TYPE          3306
#define IDC_DRV_KDF_SCHEME        3307
#define IDC_DRV_COUNTER           3308
#define IDC_DRV_KDF_LABEL         3309
#define IDC_DRV_KDF_CTX           3310
#define IDC_DRV_ID                3311
#define IDC_DRV_GO                3312
#define IDC_DRV_CLOSE             3313
#define IDC_DRV_STATUS            3314
#define IDC_DRV_LBL_HANDLE        3320
#define IDC_DRV_LBL_LABEL         3321
#define IDC_DRV_LBL_TYPE          3322
#define IDC_DRV_LBL_SIZE          3323
#define IDC_DRV_LBL_MECH          3324
#define IDC_DRV_LBL_KDF_TYPE      3325
#define IDC_DRV_LBL_KDF_SCHEME    3326
#define IDC_DRV_LBL_COUNTER       3327
#define IDC_DRV_LBL_KDF_LABEL     3328
#define IDC_DRV_LBL_KDF_CTX       3329
#define IDC_DRV_LBL_ID            3330
#define IDC_DRV_TOKEN             3340
#define IDC_DRV_PRIVATE           3341
#define IDC_DRV_SENSITIVE         3342
#define IDC_DRV_EXTRACTABLE       3343
#define IDC_DRV_MODIFIABLE        3344
#define IDC_DRV_ENCRYPT           3345
#define IDC_DRV_DECRYPT           3346
#define IDC_DRV_SIGN              3347
#define IDC_DRV_VERIFY            3348
#define IDC_DRV_WRAP              3349
#define IDC_DRV_UNWRAP            3350
#define IDC_DRV_DERIVE            3351
#define IDC_DRV_MASTER_LABEL      3352
#define IDC_DRV_MASTER_ID         3353
#define IDC_DRV_KDF_DATA          3354
#define IDC_DRV_LBL_MASTER_LABEL  3355
#define IDC_DRV_LBL_MASTER_ID     3356
#define IDC_DRV_LBL_KDF_DATA      3357

static HWND s_hDlg = NULL;
static HWND s_hHandle = NULL;
static HWND s_hMasterLabel = NULL;
static HWND s_hMasterId = NULL;
static HWND s_hKdfData = NULL;
static HWND s_hLabel = NULL;
static HWND s_hType = NULL;
static HWND s_hSize = NULL;
static HWND s_hMech = NULL;
static HWND s_hKdfType = NULL;
static HWND s_hKdfScheme = NULL;
static HWND s_hCounter = NULL;
static HWND s_hKdfLabel = NULL;
static HWND s_hKdfCtx = NULL;
static HWND s_hId = NULL;
static HWND s_hStatus = NULL;
static HWND s_hToken = NULL;
static HWND s_hPrivate = NULL;
static HWND s_hSensitive = NULL;
static HWND s_hExtractable = NULL;
static HWND s_hModifiable = NULL;
static HWND s_hEncrypt = NULL;
static HWND s_hDecrypt = NULL;
static HWND s_hSign = NULL;
static HWND s_hVerify = NULL;
static HWND s_hWrap = NULL;
static HWND s_hUnwrap = NULL;
static HWND s_hDerive = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static P11_DERIVE_MECH s_mech;
static CK_BYTE s_kdfLabel[DLG_KDF_HEX_MAX];
static CK_BYTE s_kdfCtx[DLG_KDF_HEX_MAX];
static CK_BYTE s_kdfData[DLG_KDF_HEX_MAX];
static char s_szLabel[DLG_MAX_LABEL];
static char s_szCkaId[(DLG_CKA_ID_MAX * 2) + 2];
static char s_szKdfLabel[(DLG_KDF_HEX_MAX * 2) + 2];
static char s_szKdfCtx[(DLG_KDF_HEX_MAX * 2) + 2];
static char s_szKdfData[(DLG_KDF_HEX_MAX * 2) + 2];
static char s_szCounter[16];

static void DlgDerive_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static void DlgDerive_Enable(HWND hCtrl, BOOL bOn)
{
   if (hCtrl != NULL)
   {
      EnableWindow(hCtrl, bOn);
   }
}

static CK_BBOOL DlgDerive_IsChecked(HWND hChk)
{
   return (SendMessageA(hChk, BM_GETCHECK, 0, 0) == BST_CHECKED) ? CK_TRUE : CK_FALSE;
}

static const char* DlgDerive_ComboName(HWND hCombo)
{
   int iSel = (int)SendMessageA(hCombo, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel < 0)
   {
      return NULL;
   }
   data = SendMessageA(hCombo, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if ((data == 0) || (data == CB_ERR))
   {
      return NULL;
   }
   return (const char*)data;
}

static void DlgDerive_SelectNamed(HWND hCombo, const char* sName)
{
   int iCount;
   int iLoop;
   LPARAM data;

   if ((hCombo == NULL) || (sName == NULL))
   {
      return;
   }
   iCount = (int)SendMessageA(hCombo, CB_GETCOUNT, 0, 0);
   for (iLoop = 0; iLoop < iCount; iLoop++)
   {
      data = SendMessageA(hCombo, CB_GETITEMDATA, (WPARAM)iLoop, 0);
      if ((data != 0) && (data != CB_ERR) && (strcmp((const char*)data, sName) == 0))
      {
         SendMessageA(hCombo, CB_SETCURSEL, (WPARAM)iLoop, 0);
         return;
      }
   }
   SendMessageA(hCombo, CB_SETCURSEL, 0, 0);
}

static void DlgDerive_AddSize(CK_ULONG size, CK_ULONG defSize)
{
   char sz[16];
   int iItem;

   memset(sz, 0, sizeof(sz));
   _snprintf(sz, sizeof(sz) - 1, "%lu", (unsigned long)size);
   iItem = (int)SendMessageA(s_hSize, CB_ADDSTRING, 0, (LPARAM)sz);
   if (iItem >= 0)
   {
      SendMessageA(s_hSize, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)size);
      if (size == defSize)
      {
         SendMessageA(s_hSize, CB_SETCURSEL, (WPARAM)iItem, 0);
      }
   }
}

static void DlgDerive_EnsureSizeEditable(BOOL bEdit)
{
   DWORD dwStyle;
   BOOL bIsEdit;

   if (s_hSize == NULL)
   {
      return;
   }
   dwStyle = (DWORD)GetWindowLongA(s_hSize, GWL_STYLE);
   bIsEdit = ((dwStyle & 0x0003L) == CBS_DROPDOWN) ? TRUE : FALSE;
   if (bIsEdit == bEdit)
   {
      return;
   }
   DestroyWindow(s_hSize);
   dwStyle = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL;
   dwStyle |= bEdit ? (CBS_DROPDOWN | CBS_AUTOHSCROLL) : CBS_DROPDOWNLIST;
   s_hSize = CreateWindowA("COMBOBOX", "", dwStyle,
      0, 0, 120, DLG_COMBO_DROP, s_hDlg, (HMENU)(INT_PTR)IDC_DRV_SIZE, NULL, NULL);
   if ((s_hSize != NULL) && (s_hFont != NULL))
   {
      SendMessageA(s_hSize, WM_SETFONT, (WPARAM)s_hFont, TRUE);
   }
}

static void DlgDerive_FillSizes(void)
{
   const char* pType = DlgDerive_ComboName(s_hType);
   BOOL bDes = ((pType != NULL) && (strcmp(pType, "des") == 0)) ? TRUE : FALSE;
   BOOL bAes = ((pType != NULL) && (strcmp(pType, "aes") == 0)) ? TRUE : FALSE;

   /* AES/DES sizes are fixed; generic/hmac accept any 1-512 like the CLI. */
   DlgDerive_EnsureSizeEditable((bDes == FALSE) && (bAes == FALSE));
   SendMessageA(s_hSize, CB_RESETCONTENT, 0, 0);
   if (bDes != FALSE)
   {
      DlgDerive_AddSize(8, 24);
      DlgDerive_AddSize(16, 24);
      DlgDerive_AddSize(24, 24);
   }
   else if (bAes != FALSE)
   {
      DlgDerive_AddSize(16, 32);
      DlgDerive_AddSize(24, 32);
      DlgDerive_AddSize(32, 32);
   }
   else
   {
      DlgDerive_AddSize(16, 32);
      DlgDerive_AddSize(32, 32);
      DlgDerive_AddSize(64, 32);
      DlgDerive_AddSize(128, 32);
      DlgDerive_AddSize(256, 32);
      DlgDerive_AddSize(512, 32);
   }
   if ((int)SendMessageA(s_hSize, CB_GETCURSEL, 0, 0) < 0)
   {
      SendMessageA(s_hSize, CB_SETCURSEL, 0, 0);
   }
}

static void DlgDerive_FillTypes(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetKeyTypeNameCount(KEY_TYPE_DERIVEKEY);
   char szDisp[48];

   SendMessageA(s_hType, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetKeyTypeNameAt(KEY_TYPE_DERIVEKEY, uLoop);
      int iItem;
      if (pName == NULL)
      {
         continue;
      }
      memset(szDisp, 0, sizeof(szDisp));
      GUI_FormatKeyTypeCliName((const char*)pName, szDisp, sizeof(szDisp));
      iItem = (int)SendMessageA(s_hType, CB_ADDSTRING, 0, (LPARAM)szDisp);
      if (iItem >= 0)
      {
         SendMessageA(s_hType, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)pName);
      }
   }
   DlgDerive_SelectNamed(s_hType, "aes");
}

static void DlgDerive_FillMechs(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetDerivationCount();

   SendMessageA(s_hMech, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetDerivationNameAt(uLoop);
      int iItem;
      if (pName == NULL)
      {
         continue;
      }
      iItem = (int)SendMessageA(s_hMech, CB_ADDSTRING, 0, (LPARAM)pName);
      if (iItem >= 0)
      {
         SendMessageA(s_hMech, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)pName);
      }
   }
   DlgDerive_SelectNamed(s_hMech, "sha256");
}

static void DlgDerive_FillKdfTypes(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetKdfTypeCount();

   SendMessageA(s_hKdfType, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetKdfTypeNameAt(uLoop);
      int iItem;
      if (pName == NULL)
      {
         continue;
      }
      iItem = (int)SendMessageA(s_hKdfType, CB_ADDSTRING, 0, (LPARAM)pName);
      if (iItem >= 0)
      {
         SendMessageA(s_hKdfType, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)pName);
      }
   }
   DlgDerive_SelectNamed(s_hKdfType, "aes-cmac");
}

static void DlgDerive_FillKdfSchemes(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetKdfSchemeCount();

   SendMessageA(s_hKdfScheme, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetKdfSchemeNameAt(uLoop);
      int iItem;
      if (pName == NULL)
      {
         continue;
      }
      iItem = (int)SendMessageA(s_hKdfScheme, CB_ADDSTRING, 0, (LPARAM)pName);
      if (iItem >= 0)
      {
         SendMessageA(s_hKdfScheme, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)pName);
      }
   }
   DlgDerive_SelectNamed(s_hKdfScheme, "scp03");
}

static BOOL DlgDerive_IsKdfMech(void)
{
   const char* pMech = DlgDerive_ComboName(s_hMech);
   if (pMech == NULL)
   {
      return FALSE;
   }
   return ((strcmp(pMech, "luna-kdf") == 0) || (strcmp(pMech, "luna-nist-kdf") == 0)) ? TRUE : FALSE;
}

static BOOL DlgDerive_IsEncryptDataMech(void)
{
   const char* pMech = DlgDerive_ComboName(s_hMech);
   if (pMech == NULL)
   {
      return FALSE;
   }
   return (strcmp(pMech, "aes-encrypt-ecb") == 0) ? TRUE : FALSE;
}

static void DlgDerive_UpdateFields(void)
{
   BOOL bKdf = DlgDerive_IsKdfMech();
   BOOL bEnc = DlgDerive_IsEncryptDataMech();
   DlgDerive_Enable(s_hKdfType, bKdf);
   DlgDerive_Enable(s_hKdfScheme, bKdf);
   DlgDerive_Enable(s_hCounter, bKdf);
   DlgDerive_Enable(s_hKdfLabel, bKdf);
   DlgDerive_Enable(s_hKdfCtx, bKdf);
   DlgDerive_Enable(s_hKdfData, bEnc);
}

static void DlgDerive_StripHex(char* s)
{
   char* pDst = s;
   if (s == NULL)
   {
      return;
   }
   if ((s[0] == '0') && ((s[1] == 'x') || (s[1] == 'X')))
   {
      s += 2;
   }
   while (*s != 0)
   {
      if (isspace((unsigned char)*s) == 0)
      {
         *pDst++ = *s;
      }
      s++;
   }
   *pDst = 0;
}

static CK_ULONG DlgDerive_Size(void)
{
   char sz[16];
   char* pEnd = NULL;
   unsigned long v;

   /* Window text covers both the locked list and the typed generic/hmac size. */
   memset(sz, 0, sizeof(sz));
   GetWindowTextA(s_hSize, sz, sizeof(sz));
   if (sz[0] == 0)
   {
      return 0;
   }
   v = strtoul(sz, &pEnd, 10);
   if ((pEnd == sz) || (*pEnd != 0))
   {
      return 0;
   }
   return (CK_ULONG)v;
}

static void DlgDerive_FillAttrs(P11_DERIVETEMPLATE* pTpl)
{
   pTpl->bCKA_Token = DlgDerive_IsChecked(s_hToken);
   pTpl->bCKA_Private = DlgDerive_IsChecked(s_hPrivate);
   pTpl->bCKA_Sensitive = DlgDerive_IsChecked(s_hSensitive);
   pTpl->bCKA_Extractable = DlgDerive_IsChecked(s_hExtractable);
   pTpl->bCKA_Modifiable = DlgDerive_IsChecked(s_hModifiable);
   pTpl->bCKA_Encrypt = DlgDerive_IsChecked(s_hEncrypt);
   pTpl->bCKA_Decrypt = DlgDerive_IsChecked(s_hDecrypt);
   pTpl->bCKA_Sign = DlgDerive_IsChecked(s_hSign);
   pTpl->bCKA_Verify = DlgDerive_IsChecked(s_hVerify);
   pTpl->bCKA_Wrap = DlgDerive_IsChecked(s_hWrap);
   pTpl->bCKA_Unwrap = DlgDerive_IsChecked(s_hUnwrap);
   pTpl->bCKA_Derive = DlgDerive_IsChecked(s_hDerive);
}

static void DlgDerive_DoDerive(void)
{
   P11_DERIVETEMPLATE tpl;
   const char* pType;
   const char* pMech;
   const char* pKdfType = NULL;
   const char* pKdfScheme = NULL;
   char szErr[P11_QUERY_ERR_MAX];
   char szStatus[GUI_STATUS_TEXT_MAX];
   CK_OBJECT_HANDLE hKey = 0;
   CK_KEY_TYPE ckType;
   CK_ULONG counter = 1;
   CK_LONG nIdLen = 0;
   char* pEnd = NULL;

   memset(&tpl, 0, sizeof(tpl));
   memset(s_szLabel, 0, sizeof(s_szLabel));
   memset(s_szCkaId, 0, sizeof(s_szCkaId));
   memset(s_szKdfLabel, 0, sizeof(s_szKdfLabel));
   memset(s_szKdfCtx, 0, sizeof(s_szKdfCtx));
   memset(s_szKdfData, 0, sizeof(s_szKdfData));
   memset(s_szCounter, 0, sizeof(s_szCounter));
   memset(s_kdfLabel, 0, sizeof(s_kdfLabel));
   memset(s_kdfCtx, 0, sizeof(s_kdfCtx));
   memset(s_kdfData, 0, sizeof(s_kdfData));

   tpl.hMasterKey = GUI_ResolveKeyFromEdits(s_hHandle, s_hMasterLabel, s_hMasterId,
      szErr, sizeof(szErr));
   if (tpl.hMasterKey == 0)
   {
      DlgDerive_SetStatus(szErr[0] != 0 ? szErr : "Enter a master handle, or source label and/or CKA_ID.");
      return;
   }

   GetWindowTextA(s_hLabel, s_szLabel, sizeof(s_szLabel));
   if (s_szLabel[0] == 0)
   {
      DlgDerive_SetStatus("Label is required.");
      return;
   }
   tpl.pDerivedKeyLabel = (CK_CHAR_PTR)s_szLabel;

   pType = DlgDerive_ComboName(s_hType);
   if (pType == NULL)
   {
      DlgDerive_SetStatus("Select a key type.");
      return;
   }
   ckType = P11Util_GetCKType((CK_CHAR_PTR)pType, KEY_TYPE_DERIVEKEY);
   if (ckType == CK_NULL_ELEMENT)
   {
      DlgDerive_SetStatus("Unknown key type.");
      return;
   }
   tpl.sderivedKeyType = ckType;
   tpl.sDerivedClass = CKO_SECRET_KEY;
   tpl.sderivedKeyLength = (CK_LONG)DlgDerive_Size();
   if (tpl.sderivedKeyLength == 0)
   {
      DlgDerive_SetStatus("Select a key size.");
      return;
   }

   pMech = DlgDerive_ComboName(s_hMech);
   if (pMech == NULL)
   {
      DlgDerive_SetStatus("Select a derivation mechanism.");
      return;
   }

   if (DlgDerive_IsKdfMech() != FALSE)
   {
      pKdfType = DlgDerive_ComboName(s_hKdfType);
      pKdfScheme = DlgDerive_ComboName(s_hKdfScheme);
      GetWindowTextA(s_hCounter, s_szCounter, sizeof(s_szCounter));
      if (s_szCounter[0] == 0)
      {
         counter = 1;
      }
      else
      {
         counter = strtoul(s_szCounter, &pEnd, 10);
         if ((pEnd == s_szCounter) || (*pEnd != 0))
         {
            DlgDerive_SetStatus("KDF counter must be a number.");
            return;
         }
      }
      GetWindowTextA(s_hKdfLabel, s_szKdfLabel, sizeof(s_szKdfLabel));
      GetWindowTextA(s_hKdfCtx, s_szKdfCtx, sizeof(s_szKdfCtx));
   }

   if (P11_QueryBuildDeriveMech(pMech, pKdfType, pKdfScheme, counter,
      s_szKdfLabel, s_szKdfCtx, &s_mech,
      s_kdfLabel, sizeof(s_kdfLabel), s_kdfCtx, sizeof(s_kdfCtx),
      szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgDerive_SetStatus(szErr[0] != 0 ? szErr : "Invalid derivation mechanism.");
      return;
   }
   GetWindowTextA(s_hKdfData, s_szKdfData, sizeof(s_szKdfData));
   DlgDerive_StripHex(s_szKdfData);
   if (P11_QueryApplyDeriveEncryptData(&s_mech, s_szKdfData, s_kdfData, sizeof(s_kdfData),
      szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgDerive_SetStatus(szErr[0] != 0 ? szErr : "Invalid KDF data.");
      return;
   }
   tpl.sDeriveMech = &s_mech;

   GetWindowTextA(s_hId, s_szCkaId, sizeof(s_szCkaId));
   DlgDerive_StripHex(s_szCkaId);
   if (s_szCkaId[0] != 0)
   {
      nIdLen = (CK_LONG)str_StringtoByteArray((CK_CHAR_PTR)s_szCkaId, (CK_ULONG)strlen(s_szCkaId));
      if (nIdLen == 0)
      {
         DlgDerive_SetStatus("CKA_ID must be hexadecimal.");
         return;
      }
      tpl.pCKA_ID = (CK_CHAR_PTR)s_szCkaId;
      tpl.uCKA_ID_Length = (CK_ULONG)nIdLen;
   }

   DlgDerive_FillAttrs(&tpl);

   if (P11_QueryDeriveKey(&tpl, &hKey, szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgDerive_SetStatus(szErr[0] != 0 ? szErr : "Derive failed.");
      return;
   }

   GUI_SetLastObjectHandle(hKey);
   memset(szStatus, 0, sizeof(szStatus));
   _snprintf(szStatus, sizeof(szStatus) - 1, "Derived key handle %lu.", (unsigned long)hKey);
   DlgDerive_SetStatus(szStatus);
}

static void DlgDerive_Layout(int cx, int cy)
{
   int fieldX;
   int fieldW;
   int y;
   int rowH = DLG_EDIT_H + 8;
   int chkY;
   int col;

   if (cx < 420)
   {
      cx = 420;
   }
   fieldX = DLG_MARGIN + DLG_LABEL_W + 8;
   fieldW = cx - fieldX - DLG_MARGIN;
   if (fieldW < 120)
   {
      fieldW = 120;
   }

   y = DLG_MARGIN;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_HANDLE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hHandle, fieldX, y, 72, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_MASTER_LABEL), fieldX + 80, y + 3, 40, 16, TRUE);
   MoveWindow(s_hMasterLabel, fieldX + 120, y, 140, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_MASTER_ID), fieldX + 268, y + 3, 22, 16, TRUE);
   MoveWindow(s_hMasterId, fieldX + 292, y, 120, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_LABEL), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hLabel, fieldX, y, fieldW, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_TYPE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hType, fieldX, y, 200, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_SIZE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hSize, fieldX, y, 120, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_MECH), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hMech, fieldX, y, 200, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_KDF_DATA), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hKdfData, fieldX, y, fieldW, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_KDF_TYPE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hKdfType, fieldX, y, 200, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_KDF_SCHEME), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hKdfScheme, fieldX, y, 200, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_COUNTER), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hCounter, fieldX, y, 120, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_KDF_LABEL), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hKdfLabel, fieldX, y, fieldW, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_KDF_CTX), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hKdfCtx, fieldX, y, fieldW, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_LBL_ID), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hId, fieldX, y, fieldW, DLG_EDIT_H, TRUE);

   y += rowH + 4;
   chkY = y;
   col = 0;
   MoveWindow(s_hToken, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE); col++;
   MoveWindow(s_hPrivate, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE); col++;
   MoveWindow(s_hSensitive, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE); col++;
   MoveWindow(s_hExtractable, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE);

   chkY += DLG_CHK_H + 4;
   col = 0;
   MoveWindow(s_hModifiable, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE); col++;
   MoveWindow(s_hEncrypt, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE); col++;
   MoveWindow(s_hDecrypt, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE); col++;
   MoveWindow(s_hSign, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE);

   chkY += DLG_CHK_H + 4;
   col = 0;
   MoveWindow(s_hVerify, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE); col++;
   MoveWindow(s_hWrap, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE); col++;
   MoveWindow(s_hUnwrap, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE); col++;
   MoveWindow(s_hDerive, DLG_MARGIN + (col * DLG_CHK_W), chkY, DLG_CHK_W, DLG_CHK_H, TRUE);

   y = cy - DLG_MARGIN - DLG_BTN_H;
   MoveWindow(s_hStatus, DLG_MARGIN, y - 26, cx - (2 * DLG_MARGIN), 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_GO), cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, y, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_DRV_CLOSE), cx - DLG_MARGIN - DLG_BTN_W, y, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static HWND DlgDerive_Label(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("STATIC", sText, WS_CHILD | WS_VISIBLE,
      0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static HWND DlgDerive_Check(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("BUTTON", sText,
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
      0, 0, DLG_CHK_W, DLG_CHK_H, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static void DlgDerive_CheckDefault(HWND hChk)
{
   SendMessageA(hChk, BM_SETCHECK, BST_CHECKED, 0);
}

static LRESULT CALLBACK DlgDerive_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      {
         HWND hCtrl;
         CK_OBJECT_HANDLE hLast;
         char szHandle[32];

         s_hDlg = hWnd;
         s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

         DlgDerive_Label(hWnd, "Master handle:", IDC_DRV_LBL_HANDLE);
         s_hHandle = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 72, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_HANDLE, NULL, NULL);
         DlgDerive_Label(hWnd, "Src label:", IDC_DRV_LBL_MASTER_LABEL);
         s_hMasterLabel = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 140, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_MASTER_LABEL, NULL, NULL);
         DlgDerive_Label(hWnd, "Src ID:", IDC_DRV_LBL_MASTER_ID);
         s_hMasterId = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 120, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_MASTER_ID, NULL, NULL);
         DlgDerive_Label(hWnd, "Label:", IDC_DRV_LBL_LABEL);
         s_hLabel = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_LABEL, NULL, NULL);
         DlgDerive_Label(hWnd, "Type:", IDC_DRV_LBL_TYPE);
         s_hType = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 200, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_DRV_TYPE, NULL, NULL);
         DlgDerive_Label(hWnd, "Size:", IDC_DRV_LBL_SIZE);
         s_hSize = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 120, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_DRV_SIZE, NULL, NULL);
         DlgDerive_Label(hWnd, "Mechanism:", IDC_DRV_LBL_MECH);
         s_hMech = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 200, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_DRV_MECH, NULL, NULL);
         DlgDerive_Label(hWnd, "KDF data:", IDC_DRV_LBL_KDF_DATA);
         s_hKdfData = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_KDF_DATA, NULL, NULL);
         DlgDerive_Label(hWnd, "KDF type:", IDC_DRV_LBL_KDF_TYPE);
         s_hKdfType = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 200, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_DRV_KDF_TYPE, NULL, NULL);
         DlgDerive_Label(hWnd, "KDF scheme:", IDC_DRV_LBL_KDF_SCHEME);
         s_hKdfScheme = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 200, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_DRV_KDF_SCHEME, NULL, NULL);
         DlgDerive_Label(hWnd, "KDF counter:", IDC_DRV_LBL_COUNTER);
         s_hCounter = CreateWindowA("EDIT", "1",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 120, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_COUNTER, NULL, NULL);
         DlgDerive_Label(hWnd, "KDF label:", IDC_DRV_LBL_KDF_LABEL);
         s_hKdfLabel = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_KDF_LABEL, NULL, NULL);
         DlgDerive_Label(hWnd, "KDF context:", IDC_DRV_LBL_KDF_CTX);
         s_hKdfCtx = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_KDF_CTX, NULL, NULL);
         DlgDerive_Label(hWnd, "CKA_ID:", IDC_DRV_LBL_ID);
         s_hId = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_ID, NULL, NULL);

         s_hToken = DlgDerive_Check(hWnd, "Token", IDC_DRV_TOKEN);
         s_hPrivate = DlgDerive_Check(hWnd, "Private", IDC_DRV_PRIVATE);
         s_hSensitive = DlgDerive_Check(hWnd, "Sensitive", IDC_DRV_SENSITIVE);
         s_hExtractable = DlgDerive_Check(hWnd, "Extractable", IDC_DRV_EXTRACTABLE);
         s_hModifiable = DlgDerive_Check(hWnd, "Modifiable", IDC_DRV_MODIFIABLE);
         s_hEncrypt = DlgDerive_Check(hWnd, "Encrypt", IDC_DRV_ENCRYPT);
         s_hDecrypt = DlgDerive_Check(hWnd, "Decrypt", IDC_DRV_DECRYPT);
         s_hSign = DlgDerive_Check(hWnd, "Sign", IDC_DRV_SIGN);
         s_hVerify = DlgDerive_Check(hWnd, "Verify", IDC_DRV_VERIFY);
         s_hWrap = DlgDerive_Check(hWnd, "Wrap", IDC_DRV_WRAP);
         s_hUnwrap = DlgDerive_Check(hWnd, "Unwrap", IDC_DRV_UNWRAP);
         s_hDerive = DlgDerive_Check(hWnd, "Derive", IDC_DRV_DERIVE);

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_DRV_STATUS, NULL, NULL);
         CreateWindowA("BUTTON", "Derive",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_GO, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_DRV_CLOSE, NULL, NULL);

         SendMessageA(s_hLabel, EM_SETLIMITTEXT, DLG_MAX_LABEL - 1, 0);
         SendMessageA(s_hId, EM_SETLIMITTEXT, (DLG_CKA_ID_MAX * 2) - 1, 0);
         SendMessageA(s_hKdfLabel, EM_SETLIMITTEXT, (DLG_KDF_HEX_MAX * 2) - 1, 0);
         SendMessageA(s_hKdfCtx, EM_SETLIMITTEXT, (DLG_KDF_HEX_MAX * 2) - 1, 0);
         SendMessageA(s_hCounter, EM_SETLIMITTEXT, 10, 0);

         DlgDerive_FillTypes();
         DlgDerive_FillSizes();
         DlgDerive_FillMechs();
         DlgDerive_FillKdfTypes();
         DlgDerive_FillKdfSchemes();
         DlgDerive_CheckDefault(s_hToken);
         DlgDerive_CheckDefault(s_hPrivate);
         DlgDerive_CheckDefault(s_hSensitive);
         DlgDerive_CheckDefault(s_hExtractable);
         DlgDerive_CheckDefault(s_hModifiable);
         DlgDerive_CheckDefault(s_hEncrypt);
         DlgDerive_CheckDefault(s_hDecrypt);
         DlgDerive_CheckDefault(s_hSign);
         DlgDerive_CheckDefault(s_hVerify);
         DlgDerive_CheckDefault(s_hWrap);
         DlgDerive_CheckDefault(s_hUnwrap);
         DlgDerive_CheckDefault(s_hDerive);

         hLast = GUI_GetLastObjectHandle();
         if (hLast != 0)
         {
            memset(szHandle, 0, sizeof(szHandle));
            _snprintf(szHandle, sizeof(szHandle) - 1, "%lu", (unsigned long)hLast);
            SetWindowTextA(s_hHandle, szHandle);
         }

         for (hCtrl = GetWindow(hWnd, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
         {
            SendMessageA(hCtrl, WM_SETFONT, (WPARAM)s_hFont, TRUE);
         }
         GUI_ThemeMarkStatus(s_hStatus);
         DlgDerive_UpdateFields();
         DlgDerive_SetStatus("Master handle, or source label and/or CKA_ID. aes-encrypt-ecb needs KDF data (hex).");
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
      DlgDerive_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 620;
         pMin->ptMinTrackSize.y = 680;
      }
      return 0;

   case WM_COMMAND:
      if (HIWORD(wParam) == CBN_SELCHANGE)
      {
         if (LOWORD(wParam) == IDC_DRV_TYPE)
         {
            RECT rc;
            DlgDerive_FillSizes();
            /* The size combo may have been recreated; put it back in place. */
            GetClientRect(hWnd, &rc);
            DlgDerive_Layout(rc.right - rc.left, rc.bottom - rc.top);
         }
         else if (LOWORD(wParam) == IDC_DRV_MECH)
         {
            DlgDerive_UpdateFields();
         }
         return 0;
      }
      switch (LOWORD(wParam))
      {
      case IDC_DRV_GO:
         DlgDerive_DoDerive();
         return 0;
      case IDC_DRV_CLOSE:
      case IDCANCEL:
         DestroyWindow(hWnd);
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
      s_hHandle = NULL;
      s_hMasterLabel = NULL;
      s_hMasterId = NULL;
      s_hKdfData = NULL;
      s_hLabel = NULL;
      s_hType = NULL;
      s_hSize = NULL;
      s_hMech = NULL;
      s_hKdfType = NULL;
      s_hKdfScheme = NULL;
      s_hCounter = NULL;
      s_hKdfLabel = NULL;
      s_hKdfCtx = NULL;
      s_hId = NULL;
      s_hStatus = NULL;
      s_hToken = NULL;
      s_hPrivate = NULL;
      s_hSensitive = NULL;
      s_hExtractable = NULL;
      s_hModifiable = NULL;
      s_hEncrypt = NULL;
      s_hDecrypt = NULL;
      s_hSign = NULL;
      s_hVerify = NULL;
      s_hWrap = NULL;
      s_hUnwrap = NULL;
      s_hDerive = NULL;
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }
   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

void DlgDerive_Show(HWND hwndParent)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      MessageBoxA(hwndParent, "Not logged in.", "Derive key", MB_OK | MB_ICONWARNING);
      return;
   }

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgDerive_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_DERIVE_CLASS;
   RegisterClassExA(&wc);

   s_bDone = FALSE;
   if (hwndParent != NULL)
   {
      GetWindowRect(hwndParent, &rc);
   }
   else
   {
      rc.left = 180;
      rc.top = 80;
   }

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_DERIVE_CLASS,
      "Derive key",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 28, rc.top + 28, 640, 700,
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
