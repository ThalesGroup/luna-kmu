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

#define _DLG_MZMK_C

#ifdef OS_WIN32
#include <windows.h>
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
#include "gui.h"
#include "gui_theme.h"
#include "dlg_mzmk.h"

#define DLG_MZMK_CLASS            "LunaKmuMzmk"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               110
#define DLG_BROWSE_W              80
#define DLG_COMBO_DROP            240
#define DLG_MAX_LABEL             100
#define DLG_CKA_ID_MAX            256
#define DLG_CHK_W                 108
#define DLG_CHK_H                 18

#define IDC_MZMK_FILE             3401
#define IDC_MZMK_BROWSE           3402
#define IDC_MZMK_LABEL            3403
#define IDC_MZMK_TYPE             3404
#define IDC_MZMK_SIZE             3405
#define IDC_MZMK_ID               3406
#define IDC_MZMK_GO               3407
#define IDC_MZMK_CLOSE            3408
#define IDC_MZMK_STATUS           3409
#define IDC_MZMK_LBL_FILE         3420
#define IDC_MZMK_LBL_LABEL        3421
#define IDC_MZMK_LBL_TYPE         3422
#define IDC_MZMK_LBL_SIZE         3423
#define IDC_MZMK_LBL_ID           3424
#define IDC_MZMK_TOKEN            3440
#define IDC_MZMK_PRIVATE          3441
#define IDC_MZMK_SENSITIVE        3442
#define IDC_MZMK_EXTRACTABLE      3443
#define IDC_MZMK_MODIFIABLE       3444
#define IDC_MZMK_ENCRYPT          3445
#define IDC_MZMK_DECRYPT          3446
#define IDC_MZMK_SIGN             3447
#define IDC_MZMK_VERIFY           3448
#define IDC_MZMK_WRAP             3449
#define IDC_MZMK_UNWRAP           3450
#define IDC_MZMK_DERIVE           3451

static HWND s_hDlg = NULL;
static HWND s_hFile = NULL;
static HWND s_hLabel = NULL;
static HWND s_hType = NULL;
static HWND s_hSize = NULL;
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
static char s_szLabel[DLG_MAX_LABEL];
static char s_szCkaId[(DLG_CKA_ID_MAX * 2) + 2];

static void DlgMzmk_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static CK_BBOOL DlgMzmk_IsChecked(HWND hChk)
{
   return (SendMessageA(hChk, BM_GETCHECK, 0, 0) == BST_CHECKED) ? CK_TRUE : CK_FALSE;
}

static const char* DlgMzmk_ComboName(HWND hCombo)
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

static void DlgMzmk_SelectNamed(HWND hCombo, const char* sName)
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

static void DlgMzmk_AddSize(CK_ULONG size, CK_ULONG defSize)
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

static void DlgMzmk_FillSizes(void)
{
   const char* pType = DlgMzmk_ComboName(s_hType);

   SendMessageA(s_hSize, CB_RESETCONTENT, 0, 0);
   if ((pType != NULL) && (strcmp(pType, "des") == 0))
   {
      DlgMzmk_AddSize(24, 24);
   }
   else
   {
      DlgMzmk_AddSize(16, 32);
      DlgMzmk_AddSize(24, 32);
      DlgMzmk_AddSize(32, 32);
   }
   if ((int)SendMessageA(s_hSize, CB_GETCURSEL, 0, 0) < 0)
   {
      SendMessageA(s_hSize, CB_SETCURSEL, 0, 0);
   }
}

static void DlgMzmk_FillTypes(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetKeyTypeNameCount(KEY_TYPE_MZMK);
   char szDisp[48];

   SendMessageA(s_hType, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetKeyTypeNameAt(KEY_TYPE_MZMK, uLoop);
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
   DlgMzmk_SelectNamed(s_hType, "aes");
}

static CK_ULONG DlgMzmk_Size(void)
{
   int iSel = (int)SendMessageA(s_hSize, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel < 0)
   {
      return 0;
   }
   data = SendMessageA(s_hSize, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if (data == CB_ERR)
   {
      return 0;
   }
   return (CK_ULONG)data;
}

static void DlgMzmk_StripHex(char* s)
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

static BOOL DlgMzmk_PickFile(void)
{
   OPENFILENAMEA ofn;
   char szPath[GUI_PATH_MAX];

   memset(szPath, 0, sizeof(szPath));
   GetWindowTextA(s_hFile, szPath, sizeof(szPath));

   memset(&ofn, 0, sizeof(ofn));
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = s_hDlg;
   ofn.lpstrFilter = "All files (*.*)\0*.*\0Hex (*.hex;*.txt)\0*.hex;*.txt\0";
   ofn.lpstrFile = szPath;
   ofn.nMaxFile = sizeof(szPath);
   ofn.Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_NOCHANGEDIR | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
   ofn.lpstrTitle = "TMD EC public key";
   if (GetOpenFileNameA(&ofn) == FALSE)
   {
      return FALSE;
   }
   SetWindowTextA(s_hFile, szPath);
   return TRUE;
}

static void DlgMzmk_FillAttrs(P11_DERIVETEMPLATE* pTpl)
{
   pTpl->bCKA_Token = DlgMzmk_IsChecked(s_hToken);
   pTpl->bCKA_Private = DlgMzmk_IsChecked(s_hPrivate);
   pTpl->bCKA_Sensitive = DlgMzmk_IsChecked(s_hSensitive);
   pTpl->bCKA_Extractable = DlgMzmk_IsChecked(s_hExtractable);
   pTpl->bCKA_Modifiable = DlgMzmk_IsChecked(s_hModifiable);
   pTpl->bCKA_Encrypt = DlgMzmk_IsChecked(s_hEncrypt);
   pTpl->bCKA_Decrypt = DlgMzmk_IsChecked(s_hDecrypt);
   pTpl->bCKA_Sign = DlgMzmk_IsChecked(s_hSign);
   pTpl->bCKA_Verify = DlgMzmk_IsChecked(s_hVerify);
   pTpl->bCKA_Wrap = DlgMzmk_IsChecked(s_hWrap);
   pTpl->bCKA_Unwrap = DlgMzmk_IsChecked(s_hUnwrap);
   pTpl->bCKA_Derive = DlgMzmk_IsChecked(s_hDerive);
}

static void DlgMzmk_DoCreate(void)
{
   P11_DERIVETEMPLATE tpl;
   const char* pType;
   char szFile[GUI_PATH_MAX];
   char szErr[P11_QUERY_ERR_MAX];
   char szKcv[16];
   char szCsv[GUI_PATH_MAX];
   char szStatus[GUI_STATUS_TEXT_MAX];
   CK_OBJECT_HANDLE hKey = 0;
   CK_KEY_TYPE ckType;
   CK_LONG nIdLen = 0;

   memset(&tpl, 0, sizeof(tpl));
   memset(s_szLabel, 0, sizeof(s_szLabel));
   memset(s_szCkaId, 0, sizeof(s_szCkaId));
   memset(szFile, 0, sizeof(szFile));
   memset(szKcv, 0, sizeof(szKcv));
   memset(szCsv, 0, sizeof(szCsv));

   GetWindowTextA(s_hFile, szFile, sizeof(szFile));
   if (szFile[0] == 0)
   {
      DlgMzmk_SetStatus("Select the TMD public key file.");
      return;
   }

   GetWindowTextA(s_hLabel, s_szLabel, sizeof(s_szLabel));
   if (s_szLabel[0] == 0)
   {
      DlgMzmk_SetStatus("Label is required.");
      return;
   }
   tpl.pDerivedKeyLabel = (CK_CHAR_PTR)s_szLabel;

   pType = DlgMzmk_ComboName(s_hType);
   if (pType == NULL)
   {
      DlgMzmk_SetStatus("Select a key type.");
      return;
   }
   ckType = P11Util_GetCKType((CK_CHAR_PTR)pType, KEY_TYPE_MZMK);
   if (ckType == CK_NULL_ELEMENT)
   {
      DlgMzmk_SetStatus("Unknown key type.");
      return;
   }
   tpl.sderivedKeyType = ckType;
   tpl.sderivedKeyLength = (CK_LONG)DlgMzmk_Size();
   if (tpl.sderivedKeyLength == 0)
   {
      DlgMzmk_SetStatus("Select a key size.");
      return;
   }

   GetWindowTextA(s_hId, s_szCkaId, sizeof(s_szCkaId));
   DlgMzmk_StripHex(s_szCkaId);
   if (s_szCkaId[0] != 0)
   {
      nIdLen = (CK_LONG)str_StringtoByteArray((CK_CHAR_PTR)s_szCkaId, (CK_ULONG)strlen(s_szCkaId));
      if (nIdLen == 0)
      {
         DlgMzmk_SetStatus("CKA_ID must be hexadecimal.");
         return;
      }
      tpl.pCKA_ID = (CK_CHAR_PTR)s_szCkaId;
      tpl.uCKA_ID_Length = (CK_ULONG)nIdLen;
   }

   DlgMzmk_FillAttrs(&tpl);

   if (P11_QueryRemoteMzmk(&tpl, szFile, &hKey, szKcv, sizeof(szKcv),
      szCsv, sizeof(szCsv), szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgMzmk_SetStatus(szErr[0] != 0 ? szErr : "Remote MZMK failed.");
      return;
   }

   GUI_SetLastObjectHandle(hKey);
   memset(szStatus, 0, sizeof(szStatus));
   if (szCsv[0] != 0)
   {
      _snprintf(szStatus, sizeof(szStatus) - 1,
         "MZMK handle %lu, KCV %s. CSV: %s",
         (unsigned long)hKey, szKcv, szCsv);
   }
   else
   {
      _snprintf(szStatus, sizeof(szStatus) - 1,
         "MZMK handle %lu, KCV %s.",
         (unsigned long)hKey, szKcv);
   }
   DlgMzmk_SetStatus(szStatus);
}

static void DlgMzmk_Layout(int cx, int cy)
{
   int fieldX;
   int browseX;
   int fieldW;
   int y;
   int rowH = DLG_EDIT_H + 8;
   int chkY;
   int col;

   if (cx < 400)
   {
      cx = 400;
   }
   fieldX = DLG_MARGIN + DLG_LABEL_W + 8;
   browseX = cx - DLG_MARGIN - DLG_BROWSE_W;
   fieldW = browseX - 8 - fieldX;
   if (fieldW < 80)
   {
      fieldW = 80;
   }

   y = DLG_MARGIN;
   MoveWindow(GetDlgItem(s_hDlg, IDC_MZMK_LBL_FILE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hFile, fieldX, y, fieldW, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_MZMK_BROWSE), browseX, y, DLG_BROWSE_W, DLG_BTN_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_MZMK_LBL_LABEL), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hLabel, fieldX, y, cx - fieldX - DLG_MARGIN, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_MZMK_LBL_TYPE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hType, fieldX, y, 200, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_MZMK_LBL_SIZE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hSize, fieldX, y, 120, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_MZMK_LBL_ID), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hId, fieldX, y, cx - fieldX - DLG_MARGIN, DLG_EDIT_H, TRUE);

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
   MoveWindow(GetDlgItem(s_hDlg, IDC_MZMK_GO), cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, y, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_MZMK_CLOSE), cx - DLG_MARGIN - DLG_BTN_W, y, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static HWND DlgMzmk_Label(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("STATIC", sText, WS_CHILD | WS_VISIBLE,
      0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static HWND DlgMzmk_Check(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("BUTTON", sText,
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
      0, 0, DLG_CHK_W, DLG_CHK_H, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static void DlgMzmk_CheckDefault(HWND hChk)
{
   SendMessageA(hChk, BM_SETCHECK, BST_CHECKED, 0);
}

static LRESULT CALLBACK DlgMzmk_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      {
         HWND hCtrl;

         s_hDlg = hWnd;
         s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

         DlgMzmk_Label(hWnd, "TMD public key:", IDC_MZMK_LBL_FILE);
         s_hFile = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_MZMK_FILE, NULL, NULL);
         CreateWindowA("BUTTON", "Browse...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BROWSE_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_MZMK_BROWSE, NULL, NULL);
         DlgMzmk_Label(hWnd, "Label:", IDC_MZMK_LBL_LABEL);
         s_hLabel = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_MZMK_LABEL, NULL, NULL);
         DlgMzmk_Label(hWnd, "Type:", IDC_MZMK_LBL_TYPE);
         s_hType = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 200, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_MZMK_TYPE, NULL, NULL);
         DlgMzmk_Label(hWnd, "Size:", IDC_MZMK_LBL_SIZE);
         s_hSize = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 120, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_MZMK_SIZE, NULL, NULL);
         DlgMzmk_Label(hWnd, "CKA_ID:", IDC_MZMK_LBL_ID);
         s_hId = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_MZMK_ID, NULL, NULL);

         s_hToken = DlgMzmk_Check(hWnd, "Token", IDC_MZMK_TOKEN);
         s_hPrivate = DlgMzmk_Check(hWnd, "Private", IDC_MZMK_PRIVATE);
         s_hSensitive = DlgMzmk_Check(hWnd, "Sensitive", IDC_MZMK_SENSITIVE);
         s_hExtractable = DlgMzmk_Check(hWnd, "Extractable", IDC_MZMK_EXTRACTABLE);
         s_hModifiable = DlgMzmk_Check(hWnd, "Modifiable", IDC_MZMK_MODIFIABLE);
         s_hEncrypt = DlgMzmk_Check(hWnd, "Encrypt", IDC_MZMK_ENCRYPT);
         s_hDecrypt = DlgMzmk_Check(hWnd, "Decrypt", IDC_MZMK_DECRYPT);
         s_hSign = DlgMzmk_Check(hWnd, "Sign", IDC_MZMK_SIGN);
         s_hVerify = DlgMzmk_Check(hWnd, "Verify", IDC_MZMK_VERIFY);
         s_hWrap = DlgMzmk_Check(hWnd, "Wrap", IDC_MZMK_WRAP);
         s_hUnwrap = DlgMzmk_Check(hWnd, "Unwrap", IDC_MZMK_UNWRAP);
         s_hDerive = DlgMzmk_Check(hWnd, "Derive", IDC_MZMK_DERIVE);

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_MZMK_STATUS, NULL, NULL);
         CreateWindowA("BUTTON", "Create",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_MZMK_GO, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_MZMK_CLOSE, NULL, NULL);

         SendMessageA(s_hFile, EM_SETLIMITTEXT, GUI_PATH_MAX - 1, 0);
         SendMessageA(s_hLabel, EM_SETLIMITTEXT, DLG_MAX_LABEL - 1, 0);
         SendMessageA(s_hId, EM_SETLIMITTEXT, (DLG_CKA_ID_MAX * 2) - 1, 0);

         DlgMzmk_FillTypes();
         DlgMzmk_FillSizes();
         DlgMzmk_CheckDefault(s_hToken);
         DlgMzmk_CheckDefault(s_hPrivate);
         DlgMzmk_CheckDefault(s_hSensitive);
         DlgMzmk_CheckDefault(s_hExtractable);
         DlgMzmk_CheckDefault(s_hModifiable);
         DlgMzmk_CheckDefault(s_hEncrypt);
         DlgMzmk_CheckDefault(s_hDecrypt);
         DlgMzmk_CheckDefault(s_hSign);
         DlgMzmk_CheckDefault(s_hVerify);
         DlgMzmk_CheckDefault(s_hWrap);
         DlgMzmk_CheckDefault(s_hUnwrap);
         DlgMzmk_CheckDefault(s_hDerive);

         for (hCtrl = GetWindow(hWnd, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
         {
            SendMessageA(hCtrl, WM_SETFONT, (WPARAM)s_hFont, TRUE);
         }
         GUI_ThemeMarkStatus(s_hStatus);
         DlgMzmk_SetStatus("Hex-encoded TMD EC public key. CSV is written next to that file.");
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
      DlgMzmk_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 600;
         pMin->ptMinTrackSize.y = 460;
      }
      return 0;

   case WM_COMMAND:
      if ((HIWORD(wParam) == CBN_SELCHANGE) && (LOWORD(wParam) == IDC_MZMK_TYPE))
      {
         DlgMzmk_FillSizes();
         return 0;
      }
      switch (LOWORD(wParam))
      {
      case IDC_MZMK_BROWSE:
         DlgMzmk_PickFile();
         return 0;
      case IDC_MZMK_GO:
         DlgMzmk_DoCreate();
         return 0;
      case IDC_MZMK_CLOSE:
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
      s_hFile = NULL;
      s_hLabel = NULL;
      s_hType = NULL;
      s_hSize = NULL;
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

void DlgMzmk_Show(HWND hwndParent)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      MessageBoxA(hwndParent, "Not logged in.", "Remote MZMK", MB_OK | MB_ICONWARNING);
      return;
   }

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgMzmk_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_MZMK_CLASS;
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_MZMK_CLASS,
      "Remote MZMK",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 28, rc.top + 28, 620, 500,
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
