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

#define _DLG_CRYPT_C

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
#include "dlg_crypt.h"

#define DLG_CRYPT_CLASS           "LunaKmuCrypt"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               100
#define DLG_BROWSE_W              80
#define DLG_COMBO_DROP            240

#define IDC_CRYPT_HANDLE          3101
#define IDC_CRYPT_IN              3102
#define IDC_CRYPT_IN_BROWSE       3103
#define IDC_CRYPT_OUT             3104
#define IDC_CRYPT_OUT_BROWSE      3105
#define IDC_CRYPT_FORMAT          3106
#define IDC_CRYPT_ALGO            3107
#define IDC_CRYPT_IV              3108
#define IDC_CRYPT_AAD             3109
#define IDC_CRYPT_TAG             3110
#define IDC_CRYPT_HASH            3111
#define IDC_CRYPT_GO              3112
#define IDC_CRYPT_CLOSE           3113
#define IDC_CRYPT_STATUS          3114
#define IDC_CRYPT_IV_GEN          3115
#define IDC_CRYPT_LBL_HANDLE      3120
#define IDC_CRYPT_LBL_IN          3121
#define IDC_CRYPT_LBL_OUT         3122
#define IDC_CRYPT_LBL_FORMAT      3123
#define IDC_CRYPT_LBL_ALGO        3124
#define IDC_CRYPT_LBL_IV          3125
#define IDC_CRYPT_LBL_AAD         3126
#define IDC_CRYPT_LBL_TAG         3127
#define IDC_CRYPT_LBL_HASH        3128
#define IDC_CRYPT_LABEL           3129
#define IDC_CRYPT_ID              3130
#define IDC_CRYPT_LBL_LABEL       3131
#define IDC_CRYPT_LBL_ID          3132

static HWND s_hDlg = NULL;
static HWND s_hHandle = NULL;
static HWND s_hKeyLabel = NULL;
static HWND s_hKeyId = NULL;
static HWND s_hIn = NULL;
static HWND s_hOut = NULL;
static HWND s_hFormat = NULL;
static HWND s_hAlgo = NULL;
static HWND s_hIv = NULL;
static HWND s_hAad = NULL;
static HWND s_hTag = NULL;
static HWND s_hHash = NULL;
static HWND s_hStatus = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static CK_BBOOL s_bDecrypt = CK_FALSE;
static P11_ENCRYPTION_MECH s_mech;
static CK_BYTE s_ivBuf[32];
static CK_BYTE s_aadBuf[256];

static void DlgCrypt_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static void DlgCrypt_Enable(HWND hCtrl, BOOL bOn)
{
   if (hCtrl != NULL)
   {
      EnableWindow(hCtrl, bOn);
   }
}

static const char* DlgCrypt_Title(void)
{
   return (s_bDecrypt == CK_TRUE) ? "Decrypt file" : "Encrypt file";
}

static void DlgCrypt_AddFmt(HWND hCombo, const char* sName, CK_BYTE fmt)
{
   int iItem = (int)SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)sName);
   if (iItem >= 0)
   {
      SendMessageA(hCombo, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)fmt);
   }
}

static CK_BYTE DlgCrypt_Format(void)
{
   int iSel = (int)SendMessageA(s_hFormat, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel < 0)
   {
      return P11_FILE_FORMAT_BINARY;
   }
   data = SendMessageA(s_hFormat, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if (data == CB_ERR)
   {
      return P11_FILE_FORMAT_BINARY;
   }
   return (CK_BYTE)data;
}

static const char* DlgCrypt_ComboName(HWND hCombo)
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

static void DlgCrypt_SelectNamed(HWND hCombo, const char* sName)
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

static void DlgCrypt_FillAlgos(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetEncryptionCount(KEY_TYPE_ENCRYPT);

   SendMessageA(s_hAlgo, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetEncryptionNameAt(KEY_TYPE_ENCRYPT, uLoop);
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
   DlgCrypt_SelectNamed(s_hAlgo, "aes_cbc_pad");
}

static void DlgCrypt_FillHash(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetHashCount(KEY_TYPE_ENCRYPT);

   SendMessageA(s_hHash, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetHashNameAt(KEY_TYPE_ENCRYPT, uLoop);
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
   DlgCrypt_SelectNamed(s_hHash, "sha256");
}

static void DlgCrypt_FillFormat(void)
{
   SendMessageA(s_hFormat, CB_RESETCONTENT, 0, 0);
   DlgCrypt_AddFmt(s_hFormat, "hex text", P11_FILE_FORMAT_TEXT);
   DlgCrypt_AddFmt(s_hFormat, "binary", P11_FILE_FORMAT_BINARY);
   SendMessageA(s_hFormat, CB_SETCURSEL, 1, 0);
}

static void DlgCrypt_UpdateFields(void)
{
   const char* pAlgo;
   BOOL bIv = FALSE;
   BOOL bGcm = FALSE;
   BOOL bOaep = FALSE;

   pAlgo = DlgCrypt_ComboName(s_hAlgo);
   if (pAlgo != NULL)
   {
      if ((strcmp(pAlgo, "aes_cbc") == 0) || (strcmp(pAlgo, "aes_cbc_pad") == 0) ||
         (strcmp(pAlgo, "aes_cbc_pad_ipsec") == 0) || (strcmp(pAlgo, "aes_cfb8") == 0) ||
         (strcmp(pAlgo, "aes_cfb128") == 0) || (strcmp(pAlgo, "aes_ofb") == 0))
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

   DlgCrypt_Enable(s_hIv, bIv);
   /* A random IV only makes sense when encrypting; decrypt must reuse the original IV. */
   DlgCrypt_Enable(GetDlgItem(s_hDlg, IDC_CRYPT_IV_GEN),
      (bIv != FALSE) && (s_bDecrypt == CK_FALSE));
   DlgCrypt_Enable(s_hAad, bGcm);
   DlgCrypt_Enable(s_hTag, bGcm);
   DlgCrypt_Enable(s_hHash, bOaep);
}

static void DlgCrypt_GenerateIv(void)
{
   const char* pAlgo;
   CK_BYTE iv[16];
   char szHex[40];
   CK_ULONG uLen;
   CK_ULONG uLoop;

   pAlgo = DlgCrypt_ComboName(s_hAlgo);
   if ((pAlgo == NULL) || (pAlgo[0] == 0))
   {
      DlgCrypt_SetStatus("Select an algorithm first.");
      return;
   }
   /* 96-bit IV for GCM (recommended), 16 bytes for the AES CBC/CFB/OFB modes. */
   uLen = (strcmp(pAlgo, "aes_gcm") == 0) ? 12 : 16;
   if (P11_GenerateRandom(iv, uLen) != CK_TRUE)
   {
      DlgCrypt_SetStatus("Cannot generate a random IV.");
      return;
   }
   memset(szHex, 0, sizeof(szHex));
   for (uLoop = 0; uLoop < uLen; uLoop++)
   {
      _snprintf(&szHex[uLoop * 2], 3, "%02X", iv[uLoop]);
   }
   SetWindowTextA(s_hIv, szHex);
   DlgCrypt_SetStatus("Random IV generated. Keep a copy: the same IV is needed to decrypt.");
}

static BOOL DlgCrypt_PickFile(BOOL bSave, char* szPath, unsigned int pathSize)
{
   OPENFILENAMEA ofn;

   if ((szPath == NULL) || (pathSize < 8))
   {
      return FALSE;
   }
   memset(szPath, 0, pathSize);
   GetWindowTextA(bSave ? s_hOut : s_hIn, szPath, (int)pathSize);
   if ((bSave != FALSE) && (szPath[0] == 0))
   {
      strncpy(szPath, (s_bDecrypt == CK_TRUE) ? "decrypted.bin" : "encrypted.bin", pathSize - 1);
   }

   memset(&ofn, 0, sizeof(ofn));
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = s_hDlg;
   ofn.lpstrFilter = "All files (*.*)\0*.*\0Text (*.txt)\0*.txt\0Binary (*.bin)\0*.bin\0";
   ofn.lpstrFile = szPath;
   ofn.nMaxFile = pathSize;
   ofn.Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
   if (bSave != FALSE)
   {
      ofn.Flags |= OFN_OVERWRITEPROMPT;
      ofn.lpstrTitle = "Output file";
      return (GetSaveFileNameA(&ofn) != FALSE) ? TRUE : FALSE;
   }
   ofn.Flags |= OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
   ofn.lpstrTitle = "Input file";
   return (GetOpenFileNameA(&ofn) != FALSE) ? TRUE : FALSE;
}

static void DlgCrypt_DoCrypt(void)
{
   char szIn[GUI_PATH_MAX];
   char szOut[GUI_PATH_MAX];
   char szIv[80];
   char szAad[520];
   char szTag[32];
   char szErr[P11_QUERY_ERR_MAX];
   char szStatus[GUI_STATUS_TEXT_MAX];
   CK_BYTE fmt;
   CK_ULONG uWritten = 0;
   CK_ULONG tagBits = 0;
   const char* pAlgo;
   const char* pHash;
   CK_OBJECT_HANDLE hKey;

   memset(szIn, 0, sizeof(szIn));
   memset(szOut, 0, sizeof(szOut));
   memset(szIv, 0, sizeof(szIv));
   memset(szAad, 0, sizeof(szAad));
   memset(szTag, 0, sizeof(szTag));
   memset(&s_mech, 0, sizeof(s_mech));

   hKey = GUI_ResolveKeyFromEdits(s_hHandle, s_hKeyLabel, s_hKeyId, szErr, sizeof(szErr));
   if (hKey == 0)
   {
      DlgCrypt_SetStatus(szErr[0] != 0 ? szErr : "Enter a handle, or a label and/or CKA_ID.");
      return;
   }
   GetWindowTextA(s_hIn, szIn, sizeof(szIn));
   GetWindowTextA(s_hOut, szOut, sizeof(szOut));
   if (szIn[0] == 0)
   {
      DlgCrypt_SetStatus("Choose an input file.");
      return;
   }
   if (szOut[0] == 0)
   {
      /* Default the output path next to the input so a round trip needs no typing. */
      if (strlen(szIn) + 5 >= sizeof(szOut))
      {
         DlgCrypt_SetStatus("Choose an output file.");
         return;
      }
      _snprintf(szOut, sizeof(szOut) - 1, "%s.%s", szIn, (s_bDecrypt == CK_FALSE) ? "enc" : "dec");
      SetWindowTextA(s_hOut, szOut);
   }

   pAlgo = DlgCrypt_ComboName(s_hAlgo);
   if ((pAlgo == NULL) || (pAlgo[0] == 0))
   {
      DlgCrypt_SetStatus("Select an algorithm.");
      return;
   }
   pHash = DlgCrypt_ComboName(s_hHash);
   GetWindowTextA(s_hIv, szIv, sizeof(szIv));
   GetWindowTextA(s_hAad, szAad, sizeof(szAad));
   GetWindowTextA(s_hTag, szTag, sizeof(szTag));
   if (szTag[0] != 0)
   {
      tagBits = (CK_ULONG)strtoul(szTag, NULL, 10);
   }

   if (P11_QueryBuildWrapMech(pAlgo, KEY_TYPE_ENCRYPT, szIv, szAad, tagBits, pHash,
      &s_mech, s_ivBuf, sizeof(s_ivBuf), s_aadBuf, sizeof(s_aadBuf),
      szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgCrypt_SetStatus(szErr[0] != 0 ? szErr : "Invalid algorithm.");
      return;
   }

   fmt = DlgCrypt_Format();
   DlgCrypt_SetStatus((s_bDecrypt == CK_TRUE) ? "Decrypting..." : "Encrypting...");
   UpdateWindow(s_hStatus);
   if (P11_QueryCryptFile(s_bDecrypt, hKey, &s_mech, szIn, szOut, fmt,
      &uWritten, szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgCrypt_SetStatus(szErr[0] != 0 ? szErr : ((s_bDecrypt == CK_TRUE) ? "Decrypt failed." : "Encrypt failed."));
      return;
   }
   memset(szStatus, 0, sizeof(szStatus));
   _snprintf(szStatus, sizeof(szStatus) - 1, "%s handle %lu. %lu bytes written to %s",
      (s_bDecrypt == CK_TRUE) ? "Decrypted with" : "Encrypted with",
      (unsigned long)hKey, (unsigned long)uWritten, szOut);
   DlgCrypt_SetStatus(szStatus);
}

static void DlgCrypt_Layout(int cx, int cy)
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
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_HANDLE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hHandle, fieldX, y, 72, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_LABEL), fieldX + 80, y + 3, 40, 16, TRUE);
   MoveWindow(s_hKeyLabel, fieldX + 120, y, 140, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_ID), fieldX + 268, y + 3, 22, 16, TRUE);
   MoveWindow(s_hKeyId, fieldX + 292, y, 120, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_IN), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hIn, fieldX, y, fieldW, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_IN_BROWSE), browseX, y, DLG_BROWSE_W, DLG_BTN_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_OUT), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hOut, fieldX, y, fieldW, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_OUT_BROWSE), browseX, y, DLG_BROWSE_W, DLG_BTN_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_FORMAT), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hFormat, fieldX, y, 160, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_ALGO), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hAlgo, fieldX, y, 220, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_IV), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hIv, fieldX, y, fieldW, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_IV_GEN), browseX, y, DLG_BROWSE_W, DLG_BTN_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_AAD), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hAad, fieldX, y, fieldW + DLG_BROWSE_W + 8, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_TAG), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hTag, fieldX, y, 80, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_LBL_HASH), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hHash, fieldX, y, 160, DLG_COMBO_DROP, TRUE);

   y = cy - DLG_MARGIN - DLG_BTN_H;
   MoveWindow(s_hStatus, DLG_MARGIN, y - 26, cx - (2 * DLG_MARGIN), 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_GO), cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, y, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CRYPT_CLOSE), cx - DLG_MARGIN - DLG_BTN_W, y, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static HWND DlgCrypt_Label(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("STATIC", sText, WS_CHILD | WS_VISIBLE,
      0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static LRESULT CALLBACK DlgCrypt_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
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

         DlgCrypt_Label(hWnd, "Handle:", IDC_CRYPT_LBL_HANDLE);
         s_hHandle = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 72, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_HANDLE, NULL, NULL);
         DlgCrypt_Label(hWnd, "Label:", IDC_CRYPT_LBL_LABEL);
         s_hKeyLabel = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 140, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_LABEL, NULL, NULL);
         DlgCrypt_Label(hWnd, "ID:", IDC_CRYPT_LBL_ID);
         s_hKeyId = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 120, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_ID, NULL, NULL);
         DlgCrypt_Label(hWnd, "Input file:", IDC_CRYPT_LBL_IN);
         s_hIn = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_IN, NULL, NULL);
         CreateWindowA("BUTTON", "Browse...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BROWSE_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_IN_BROWSE, NULL, NULL);
         DlgCrypt_Label(hWnd, "Output file (optional):", IDC_CRYPT_LBL_OUT);
         s_hOut = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_OUT, NULL, NULL);
         CreateWindowA("BUTTON", "Browse...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BROWSE_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_OUT_BROWSE, NULL, NULL);
         DlgCrypt_Label(hWnd, "Format:", IDC_CRYPT_LBL_FORMAT);
         s_hFormat = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 160, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_FORMAT, NULL, NULL);
         DlgCrypt_Label(hWnd, "Algorithm:", IDC_CRYPT_LBL_ALGO);
         s_hAlgo = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 220, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_ALGO, NULL, NULL);
         DlgCrypt_Label(hWnd, "IV (hex):", IDC_CRYPT_LBL_IV);
         s_hIv = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_IV, NULL, NULL);
         CreateWindowA("BUTTON", "Random",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BROWSE_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_IV_GEN, NULL, NULL);
         DlgCrypt_Label(hWnd, "GCM AAD:", IDC_CRYPT_LBL_AAD);
         s_hAad = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_AAD, NULL, NULL);
         DlgCrypt_Label(hWnd, "Tag bits:", IDC_CRYPT_LBL_TAG);
         s_hTag = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 80, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_TAG, NULL, NULL);
         DlgCrypt_Label(hWnd, "OAEP hash:", IDC_CRYPT_LBL_HASH);
         s_hHash = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 160, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_HASH, NULL, NULL);
         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_STATUS, NULL, NULL);
         CreateWindowA("BUTTON", (s_bDecrypt == CK_TRUE) ? "Decrypt" : "Encrypt",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_GO, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CRYPT_CLOSE, NULL, NULL);

         SendMessageA(s_hIn, EM_SETLIMITTEXT, GUI_PATH_MAX - 1, 0);
         SendMessageA(s_hOut, EM_SETLIMITTEXT, GUI_PATH_MAX - 1, 0);
         DlgCrypt_FillFormat();
         DlgCrypt_FillAlgos();
         DlgCrypt_FillHash();

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
         DlgCrypt_UpdateFields();
         DlgCrypt_SetStatus("Handle, or label and/or CKA_ID. Leave IV empty to use the default.");
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
      DlgCrypt_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 620;
         pMin->ptMinTrackSize.y = 420;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_CRYPT_ALGO:
         if (HIWORD(wParam) == CBN_SELCHANGE)
         {
            DlgCrypt_UpdateFields();
         }
         return 0;
      case IDC_CRYPT_IN_BROWSE:
         {
            char szPath[GUI_PATH_MAX];
            if (DlgCrypt_PickFile(FALSE, szPath, sizeof(szPath)) != FALSE)
            {
               SetWindowTextA(s_hIn, szPath);
            }
         }
         return 0;
      case IDC_CRYPT_OUT_BROWSE:
         {
            char szPath[GUI_PATH_MAX];
            if (DlgCrypt_PickFile(TRUE, szPath, sizeof(szPath)) != FALSE)
            {
               SetWindowTextA(s_hOut, szPath);
            }
         }
         return 0;
      case IDC_CRYPT_IV_GEN:
         DlgCrypt_GenerateIv();
         return 0;
      case IDC_CRYPT_GO:
      case IDOK:
         DlgCrypt_DoCrypt();
         return 0;
      case IDC_CRYPT_CLOSE:
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
      s_hKeyLabel = NULL;
      s_hKeyId = NULL;
      s_hIn = NULL;
      s_hOut = NULL;
      s_hFormat = NULL;
      s_hAlgo = NULL;
      s_hIv = NULL;
      s_hAad = NULL;
      s_hTag = NULL;
      s_hHash = NULL;
      s_hStatus = NULL;
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }
   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

void DlgCrypt_Show(HWND hwndParent, CK_BBOOL bDecrypt)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      MessageBoxA(hwndParent, "Not logged in.",
         (bDecrypt == CK_TRUE) ? "Decrypt file" : "Encrypt file",
         MB_OK | MB_ICONWARNING);
      return;
   }

   s_bDecrypt = bDecrypt;

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgCrypt_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_CRYPT_CLASS;
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_CRYPT_CLASS,
      DlgCrypt_Title(),
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 28, rc.top + 28, 640, 460,
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
