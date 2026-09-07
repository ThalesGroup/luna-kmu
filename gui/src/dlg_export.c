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

#define _DLG_EXPORT_C

#ifdef OS_WIN32
#include <windows.h>
#include <commdlg.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "p11util.h"
#include "p11query.h"
#include "gui.h"
#include "gui_theme.h"
#include "dlg_export.h"

#define DLG_EXP_CLASS             "LunaKmuExport"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               100
#define DLG_BROWSE_W              80
#define DLG_COMBO_DROP            240
#define DLG_PW_MAX                256

#define IDC_EXP_HANDLE            3001
#define IDC_EXP_FILE              3002
#define IDC_EXP_BROWSE            3003
#define IDC_EXP_FORMAT            3004
#define IDC_EXP_WRAPKEY           3005
#define IDC_EXP_ALGO              3006
#define IDC_EXP_IV                3007
#define IDC_EXP_AAD               3008
#define IDC_EXP_TAG               3009
#define IDC_EXP_HASH              3010
#define IDC_EXP_PASSWORD          3011
#define IDC_EXP_SALT              3012
#define IDC_EXP_ITER              3013
#define IDC_EXP_GO                3014
#define IDC_EXP_CLOSE             3015
#define IDC_EXP_STATUS            3016
#define IDC_EXP_LBL_HANDLE        3020
#define IDC_EXP_LBL_FILE          3021
#define IDC_EXP_LBL_FORMAT        3022
#define IDC_EXP_LBL_WRAPKEY       3023
#define IDC_EXP_LBL_ALGO          3024
#define IDC_EXP_LBL_IV            3025
#define IDC_EXP_LBL_AAD           3026
#define IDC_EXP_LBL_TAG           3027
#define IDC_EXP_LBL_HASH          3028
#define IDC_EXP_LBL_PASSWORD      3029
#define IDC_EXP_LBL_SALT          3030
#define IDC_EXP_LBL_ITER          3031
#define IDC_EXP_KEYLABEL          3032
#define IDC_EXP_KEYID             3033
#define IDC_EXP_WRAPLABEL         3034
#define IDC_EXP_WRAPID            3035
#define IDC_EXP_LBL_KEYLABEL      3036
#define IDC_EXP_LBL_KEYID         3037
#define IDC_EXP_LBL_WRAPLABEL     3038
#define IDC_EXP_LBL_WRAPID        3039

static HWND s_hDlg = NULL;
static HWND s_hHandle = NULL;
static HWND s_hKeyLabel = NULL;
static HWND s_hKeyId = NULL;
static HWND s_hFile = NULL;
static HWND s_hFormat = NULL;
static HWND s_hWrapKey = NULL;
static HWND s_hWrapLabel = NULL;
static HWND s_hWrapId = NULL;
static HWND s_hAlgo = NULL;
static HWND s_hIv = NULL;
static HWND s_hAad = NULL;
static HWND s_hTag = NULL;
static HWND s_hHash = NULL;
static HWND s_hPassword = NULL;
static HWND s_hSalt = NULL;
static HWND s_hIter = NULL;
static HWND s_hStatus = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static CK_OBJECT_CLASS s_ckClass = (CK_OBJECT_CLASS)-1;
static BOOL s_bAlgoIsPbe = FALSE;
static P11_ENCRYPTION_MECH s_mech;
static CK_BYTE s_ivBuf[32];
static CK_BYTE s_aadBuf[256];
static char s_szPassword[DLG_PW_MAX];

static void DlgExp_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static void DlgExp_Enable(HWND hCtrl, BOOL bOn)
{
   if (hCtrl != NULL)
   {
      EnableWindow(hCtrl, bOn);
   }
}

static void DlgExp_AddFmt(HWND hCombo, const char* sName, CK_BYTE fmt)
{
   int iItem = (int)SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)sName);
   if (iItem >= 0)
   {
      SendMessageA(hCombo, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)fmt);
   }
}

static CK_BYTE DlgExp_Format(void)
{
   int iSel = (int)SendMessageA(s_hFormat, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel < 0)
   {
      return P11_FILE_FORMAT_TEXT;
   }
   data = SendMessageA(s_hFormat, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if (data == CB_ERR)
   {
      return P11_FILE_FORMAT_TEXT;
   }
   return (CK_BYTE)data;
}

static const char* DlgExp_ComboName(HWND hCombo)
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

static void DlgExp_SelectNamed(HWND hCombo, const char* sName)
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

static void DlgExp_FillAlgos(CK_ULONG uFlag, const char* sDefault)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetEncryptionCount(uFlag);

   SendMessageA(s_hAlgo, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetEncryptionNameAt(uFlag, uLoop);
      int iItem;
      if (pName == NULL)
      {
         continue;
      }
      iItem = (int)SendMessageA(s_hAlgo, CB_ADDSTRING, 0, (LPARAM)pName);
      if (iItem >= 0)
      {
         SendMessageA(s_hAlgo, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)pName);
      }
   }
   if (sDefault != NULL)
   {
      DlgExp_SelectNamed(s_hAlgo, sDefault);
   }
   else
   {
      SendMessageA(s_hAlgo, CB_SETCURSEL, 0, 0);
   }
}

static void DlgExp_FillHash(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetHashCount(KEY_TYPE_IMPORT_EXPORTKEY);

   SendMessageA(s_hHash, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetHashNameAt(KEY_TYPE_IMPORT_EXPORTKEY, uLoop);
      int iItem;
      if (pName == NULL)
      {
         continue;
      }
      iItem = (int)SendMessageA(s_hHash, CB_ADDSTRING, 0, (LPARAM)pName);
      if (iItem >= 0)
      {
         SendMessageA(s_hHash, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)pName);
      }
   }
   DlgExp_SelectNamed(s_hHash, "sha256");
}

static void DlgExp_FillFormat(CK_OBJECT_CLASS ckClass)
{
   CK_BYTE cur = DlgExp_Format();

   SendMessageA(s_hFormat, CB_RESETCONTENT, 0, 0);
   DlgExp_AddFmt(s_hFormat, "text", P11_FILE_FORMAT_TEXT);
   DlgExp_AddFmt(s_hFormat, "bin", P11_FILE_FORMAT_BINARY);
   if (ckClass != CKO_SECRET_KEY)
   {
      DlgExp_AddFmt(s_hFormat, "pkcs8", P11_FILE_FORMAT_PKCS8);
   }
   if ((ckClass == CKO_SECRET_KEY) && (cur == P11_FILE_FORMAT_PKCS8))
   {
      cur = P11_FILE_FORMAT_TEXT;
   }
   {
      int iCount = (int)SendMessageA(s_hFormat, CB_GETCOUNT, 0, 0);
      int iLoop;
      for (iLoop = 0; iLoop < iCount; iLoop++)
      {
         if ((CK_BYTE)SendMessageA(s_hFormat, CB_GETITEMDATA, (WPARAM)iLoop, 0) == cur)
         {
            SendMessageA(s_hFormat, CB_SETCURSEL, (WPARAM)iLoop, 0);
            return;
         }
      }
   }
   SendMessageA(s_hFormat, CB_SETCURSEL, 0, 0);
}

static void DlgExp_UpdateFields(void)
{
   CK_OBJECT_HANDLE hKey;
   CK_BYTE fmt;
   const char* pAlgo;
   BOOL bPublic = FALSE;
   BOOL bPbe = FALSE;
   BOOL bWrap = FALSE;
   BOOL bIv = FALSE;
   BOOL bGcm = FALSE;
   BOOL bOaep = FALSE;
   CK_OBJECT_CLASS ckClass;

   hKey = GUI_ResolveKeyFromEdits(s_hHandle, s_hKeyLabel, s_hKeyId, NULL, 0);
   ckClass = (CK_OBJECT_CLASS)-1;
   if ((hKey != 0) && (P11_FindKeyObject(hKey) == CK_TRUE))
   {
      ckClass = P11_GetObjectClass(hKey);
   }
   if (ckClass != s_ckClass)
   {
      s_ckClass = ckClass;
      DlgExp_FillFormat(ckClass);
      if (ckClass == CKO_PRIVATE_KEY)
      {
         /* keep current format */
      }
   }

   fmt = DlgExp_Format();
   bPublic = (ckClass == CKO_PUBLIC_KEY);
   bPbe = ((ckClass == CKO_PRIVATE_KEY) && (fmt == P11_FILE_FORMAT_PKCS8));
   bWrap = ((bPublic == FALSE) && (bPbe == FALSE) && (ckClass != (CK_OBJECT_CLASS)-1));

   if (bPbe != FALSE)
   {
      if (s_bAlgoIsPbe == FALSE)
      {
         DlgExp_FillAlgos(KEY_TYPE_PBE, "pbkdf2_aes256_cbc");
         s_bAlgoIsPbe = TRUE;
      }
   }
   else if (bWrap != FALSE)
   {
      if (s_bAlgoIsPbe != FALSE)
      {
         DlgExp_FillAlgos(KEY_TYPE_IMPORT_EXPORTKEY, "aes_cbc_pad");
         s_bAlgoIsPbe = FALSE;
      }
   }

   pAlgo = DlgExp_ComboName(s_hAlgo);
   if ((bWrap != FALSE) && (pAlgo != NULL))
   {
      if ((strcmp(pAlgo, "aes_cbc") == 0) || (strcmp(pAlgo, "aes_cbc_pad") == 0) ||
         (strcmp(pAlgo, "aes_cbc_pad_ipsec") == 0))
      {
         bIv = TRUE;
      }
      else if (strcmp(pAlgo, "aes_gcm") == 0)
      {
         bIv = TRUE;
         bGcm = TRUE;
      }
      else if (strcmp(pAlgo, "rsa_oaep") == 0)
      {
         bOaep = TRUE;
      }
   }

   DlgExp_Enable(s_hWrapKey, bWrap);
   DlgExp_Enable(s_hWrapLabel, bWrap);
   DlgExp_Enable(s_hWrapId, bWrap);
   DlgExp_Enable(s_hAlgo, (bWrap || bPbe) ? TRUE : FALSE);
   DlgExp_Enable(s_hIv, (bIv || bPbe) ? TRUE : FALSE);
   DlgExp_Enable(s_hAad, bGcm);
   DlgExp_Enable(s_hTag, bGcm);
   DlgExp_Enable(s_hHash, bOaep);
   DlgExp_Enable(s_hPassword, bPbe);
   DlgExp_Enable(s_hSalt, bPbe);
   DlgExp_Enable(s_hIter, bPbe);
}

static BOOL DlgExp_PickFile(char* szPath, unsigned int pathSize)
{
   OPENFILENAMEA ofn;

   if ((szPath == NULL) || (pathSize < 8))
   {
      return FALSE;
   }
   memset(szPath, 0, pathSize);
   GetWindowTextA(s_hFile, szPath, (int)pathSize);
   if (szPath[0] == 0)
   {
      strncpy(szPath, "export.txt", pathSize - 1);
   }

   memset(&ofn, 0, sizeof(ofn));
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = s_hDlg;
   ofn.lpstrFilter = "All files (*.*)\0*.*\0Text (*.txt)\0*.txt\0Binary (*.bin)\0*.bin\0PEM (*.pem)\0*.pem\0";
   ofn.lpstrFile = szPath;
   ofn.nMaxFile = pathSize;
   ofn.Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_NOCHANGEDIR | OFN_OVERWRITEPROMPT;
   ofn.lpstrTitle = "Export to file";
   return (GetSaveFileNameA(&ofn) != FALSE) ? TRUE : FALSE;
}

static void DlgExp_DoExport(void)
{
   P11_WRAPTEMPLATE tpl;
   char szPath[GUI_PATH_MAX];
   char szIv[80];
   char szAad[520];
   char szTag[32];
   char szSalt[80];
   char szIter[32];
   char szErr[P11_QUERY_ERR_MAX];
   char szStatus[GUI_STATUS_TEXT_MAX];
   CK_BYTE fmt;
   CK_ULONG uWritten = 0;
   CK_ULONG tagBits = 0;
   CK_LONG lIter = -1;
   const char* pAlgo;
   const char* pHash;
   CK_OBJECT_HANDLE hKey;
   CK_OBJECT_CLASS ckClass;

   memset(&tpl, 0, sizeof(tpl));
   memset(szPath, 0, sizeof(szPath));
   memset(szIv, 0, sizeof(szIv));
   memset(szAad, 0, sizeof(szAad));
   memset(szTag, 0, sizeof(szTag));
   memset(szSalt, 0, sizeof(szSalt));
   memset(szIter, 0, sizeof(szIter));
   memset(s_szPassword, 0, sizeof(s_szPassword));
   memset(&s_mech, 0, sizeof(s_mech));

   hKey = GUI_ResolveKeyFromEdits(s_hHandle, s_hKeyLabel, s_hKeyId, szErr, sizeof(szErr));
   if (hKey == 0)
   {
      DlgExp_SetStatus(szErr[0] != 0 ? szErr : "Enter a handle, or a label and/or CKA_ID.");
      return;
   }
   GetWindowTextA(s_hFile, szPath, sizeof(szPath));
   if (szPath[0] == 0)
   {
      DlgExp_SetStatus("Choose an output file.");
      return;
   }

   tpl.hKeyToExport = hKey;
   fmt = DlgExp_Format();
   if (P11_FindKeyObject(hKey) != CK_TRUE)
   {
      DlgExp_SetStatus("Key to export was not found.");
      return;
   }
   ckClass = P11_GetObjectClass(hKey);

   GetWindowTextA(s_hIv, szIv, sizeof(szIv));
   GetWindowTextA(s_hAad, szAad, sizeof(szAad));
   GetWindowTextA(s_hTag, szTag, sizeof(szTag));
   GetWindowTextA(s_hPassword, s_szPassword, sizeof(s_szPassword));
   GetWindowTextA(s_hSalt, szSalt, sizeof(szSalt));
   GetWindowTextA(s_hIter, szIter, sizeof(szIter));
   if (szTag[0] != 0)
   {
      tagBits = (CK_ULONG)strtoul(szTag, NULL, 10);
   }
   if (szIter[0] != 0)
   {
      lIter = (CK_LONG)strtol(szIter, NULL, 10);
   }
   pAlgo = DlgExp_ComboName(s_hAlgo);
   pHash = DlgExp_ComboName(s_hHash);

   if (ckClass == CKO_PUBLIC_KEY)
   {
      /* wrap mech unused */
   }
   else if ((ckClass == CKO_PRIVATE_KEY) && (fmt == P11_FILE_FORMAT_PKCS8))
   {
      if (P11_QueryBuildPbeMech(pAlgo, s_szPassword, szSalt, lIter, szIv,
         &s_mech, szErr, sizeof(szErr)) != CK_TRUE)
      {
         DlgExp_SetStatus(szErr[0] != 0 ? szErr : "Invalid PBE parameters.");
         GUI_SecureClear(s_szPassword, sizeof(s_szPassword));
         return;
      }
      tpl.bPbe = CK_TRUE;
      tpl.wrap_key_mech = &s_mech;
   }
   else
   {
      tpl.hWrappingKey = GUI_ResolveKeyFromEdits(s_hWrapKey, s_hWrapLabel, s_hWrapId,
         szErr, sizeof(szErr));
      if (tpl.hWrappingKey == 0)
      {
         DlgExp_SetStatus(szErr[0] != 0 ? szErr : "Enter a wrapping key handle, label, or CKA_ID.");
         return;
      }
      if (P11_QueryBuildWrapMech(pAlgo, KEY_TYPE_IMPORT_EXPORTKEY, szIv, szAad, tagBits, pHash,
         &s_mech, s_ivBuf, sizeof(s_ivBuf), s_aadBuf, sizeof(s_aadBuf),
         szErr, sizeof(szErr)) != CK_TRUE)
      {
         DlgExp_SetStatus(szErr[0] != 0 ? szErr : "Invalid wrap algorithm.");
         return;
      }
      tpl.wrap_key_mech = &s_mech;
   }

   DlgExp_SetStatus("Exporting...");
   UpdateWindow(s_hStatus);
   if (P11_QueryExportKey(&tpl, szPath, fmt, &uWritten, szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgExp_SetStatus(szErr[0] != 0 ? szErr : "Export failed.");
      GUI_SecureClear(s_szPassword, sizeof(s_szPassword));
      return;
   }
   memset(szStatus, 0, sizeof(szStatus));
   _snprintf(szStatus, sizeof(szStatus) - 1, "Exported handle %lu. %lu bytes written to %s",
      (unsigned long)hKey, (unsigned long)uWritten, szPath);
   DlgExp_SetStatus(szStatus);
   GUI_SecureClear(s_szPassword, sizeof(s_szPassword));
}

static void DlgExp_Layout(int cx, int cy)
{
   int y;
   int fieldX;
   int fieldW;
   int browseX;
   int rowH = DLG_EDIT_H + 8;

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
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_HANDLE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hHandle, fieldX, y, 72, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_KEYLABEL), fieldX + 80, y + 3, 40, 16, TRUE);
   MoveWindow(s_hKeyLabel, fieldX + 120, y, 140, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_KEYID), fieldX + 268, y + 3, 22, 16, TRUE);
   MoveWindow(s_hKeyId, fieldX + 292, y, 120, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_FILE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hFile, fieldX, y, fieldW, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_BROWSE), browseX, y, DLG_BROWSE_W, DLG_BTN_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_FORMAT), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hFormat, fieldX, y, 160, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_WRAPKEY), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hWrapKey, fieldX, y, 72, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_WRAPLABEL), fieldX + 80, y + 3, 40, 16, TRUE);
   MoveWindow(s_hWrapLabel, fieldX + 120, y, 140, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_WRAPID), fieldX + 268, y + 3, 22, 16, TRUE);
   MoveWindow(s_hWrapId, fieldX + 292, y, 120, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_ALGO), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hAlgo, fieldX, y, 220, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_IV), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hIv, fieldX, y, fieldW + DLG_BROWSE_W + 8, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_AAD), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hAad, fieldX, y, fieldW + DLG_BROWSE_W + 8, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_TAG), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hTag, fieldX, y, 80, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_HASH), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hHash, fieldX, y, 160, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_PASSWORD), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hPassword, fieldX, y, 220, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_SALT), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hSalt, fieldX, y, 220, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_LBL_ITER), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hIter, fieldX, y, 80, DLG_EDIT_H, TRUE);

   y = cy - DLG_MARGIN - DLG_BTN_H;
   MoveWindow(s_hStatus, DLG_MARGIN, y - 26, cx - (2 * DLG_MARGIN), 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_GO), cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, y, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_EXP_CLOSE), cx - DLG_MARGIN - DLG_BTN_W, y, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static HWND DlgExp_Label(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("STATIC", sText, WS_CHILD | WS_VISIBLE,
      0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static LRESULT CALLBACK DlgExp_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
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
         s_ckClass = (CK_OBJECT_CLASS)-1;
         s_bAlgoIsPbe = FALSE;

         DlgExp_Label(hWnd, "Handle:", IDC_EXP_LBL_HANDLE);
         s_hHandle = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 72, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_HANDLE, NULL, NULL);
         DlgExp_Label(hWnd, "Label:", IDC_EXP_LBL_KEYLABEL);
         s_hKeyLabel = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 140, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_KEYLABEL, NULL, NULL);
         DlgExp_Label(hWnd, "ID:", IDC_EXP_LBL_KEYID);
         s_hKeyId = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 120, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_KEYID, NULL, NULL);
         DlgExp_Label(hWnd, "Output file:", IDC_EXP_LBL_FILE);
         s_hFile = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_FILE, NULL, NULL);
         CreateWindowA("BUTTON", "Browse...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BROWSE_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_BROWSE, NULL, NULL);
         DlgExp_Label(hWnd, "Format:", IDC_EXP_LBL_FORMAT);
         s_hFormat = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 160, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_EXP_FORMAT, NULL, NULL);
         DlgExp_Label(hWnd, "Wrap key:", IDC_EXP_LBL_WRAPKEY);
         s_hWrapKey = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 72, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_WRAPKEY, NULL, NULL);
         DlgExp_Label(hWnd, "Label:", IDC_EXP_LBL_WRAPLABEL);
         s_hWrapLabel = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 140, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_WRAPLABEL, NULL, NULL);
         DlgExp_Label(hWnd, "ID:", IDC_EXP_LBL_WRAPID);
         s_hWrapId = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 120, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_WRAPID, NULL, NULL);
         DlgExp_Label(hWnd, "Algorithm:", IDC_EXP_LBL_ALGO);
         s_hAlgo = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 220, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_EXP_ALGO, NULL, NULL);
         DlgExp_Label(hWnd, "IV (hex):", IDC_EXP_LBL_IV);
         s_hIv = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_IV, NULL, NULL);
         DlgExp_Label(hWnd, "GCM AAD:", IDC_EXP_LBL_AAD);
         s_hAad = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_AAD, NULL, NULL);
         DlgExp_Label(hWnd, "Tag bits:", IDC_EXP_LBL_TAG);
         s_hTag = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 80, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_TAG, NULL, NULL);
         DlgExp_Label(hWnd, "OAEP hash:", IDC_EXP_LBL_HASH);
         s_hHash = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 160, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_EXP_HASH, NULL, NULL);
         DlgExp_Label(hWnd, "Password:", IDC_EXP_LBL_PASSWORD);
         s_hPassword = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            0, 0, 220, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_PASSWORD, NULL, NULL);
         DlgExp_Label(hWnd, "Salt (hex):", IDC_EXP_LBL_SALT);
         s_hSalt = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 220, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_SALT, NULL, NULL);
         DlgExp_Label(hWnd, "Iterations:", IDC_EXP_LBL_ITER);
         s_hIter = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 80, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_ITER, NULL, NULL);
         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_EXP_STATUS, NULL, NULL);
         CreateWindowA("BUTTON", "Export",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_GO, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_EXP_CLOSE, NULL, NULL);

         SendMessageA(s_hFile, EM_SETLIMITTEXT, GUI_PATH_MAX - 1, 0);
         SendMessageA(s_hPassword, EM_SETLIMITTEXT, DLG_PW_MAX - 1, 0);
         DlgExp_FillFormat((CK_OBJECT_CLASS)-1);
         DlgExp_FillAlgos(KEY_TYPE_IMPORT_EXPORTKEY, "aes_cbc_pad");
         DlgExp_FillHash();
         SetWindowTextA(s_hIter, "10000");

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
         DlgExp_UpdateFields();
         DlgExp_SetStatus("Handle, or label and/or CKA_ID. PKCS#8 private keys use pbkdf2_* and a password.");
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
      DlgExp_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 620;
         pMin->ptMinTrackSize.y = 520;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_EXP_HANDLE:
      case IDC_EXP_KEYLABEL:
      case IDC_EXP_KEYID:
         if (HIWORD(wParam) == EN_KILLFOCUS)
         {
            DlgExp_UpdateFields();
         }
         return 0;
      case IDC_EXP_FORMAT:
      case IDC_EXP_ALGO:
         if (HIWORD(wParam) == CBN_SELCHANGE)
         {
            DlgExp_UpdateFields();
         }
         return 0;
      case IDC_EXP_BROWSE:
         {
            char szPath[GUI_PATH_MAX];
            if (DlgExp_PickFile(szPath, sizeof(szPath)) != FALSE)
            {
               SetWindowTextA(s_hFile, szPath);
            }
         }
         return 0;
      case IDC_EXP_GO:
      case IDOK:
         DlgExp_DoExport();
         return 0;
      case IDC_EXP_CLOSE:
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
      GUI_SecureClear(s_szPassword, sizeof(s_szPassword));
      s_hDlg = NULL;
      s_hHandle = NULL;
      s_hKeyLabel = NULL;
      s_hKeyId = NULL;
      s_hFile = NULL;
      s_hFormat = NULL;
      s_hWrapKey = NULL;
      s_hWrapLabel = NULL;
      s_hWrapId = NULL;
      s_hAlgo = NULL;
      s_hIv = NULL;
      s_hAad = NULL;
      s_hTag = NULL;
      s_hHash = NULL;
      s_hPassword = NULL;
      s_hSalt = NULL;
      s_hIter = NULL;
      s_hStatus = NULL;
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }
   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

void DlgExport_Show(HWND hwndParent)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgExp_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_EXP_CLASS;
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_EXP_CLASS,
      "Export key",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 28, rc.top + 28, 640, 560,
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
