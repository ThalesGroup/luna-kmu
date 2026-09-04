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

#define _DLG_SIGN_C

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
#include "dlg_sign.h"

#define DLG_SIGN_CLASS            "LunaKmuSign"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               110
#define DLG_BROWSE_W              80
#define DLG_COMBO_DROP            240

#define IDC_SIGN_HANDLE           3201
#define IDC_SIGN_IN               3202
#define IDC_SIGN_IN_BROWSE        3203
#define IDC_SIGN_SIG              3204
#define IDC_SIGN_SIG_BROWSE       3205
#define IDC_SIGN_FORMAT           3206
#define IDC_SIGN_ALGO             3207
#define IDC_SIGN_HASH             3208
#define IDC_SIGN_GO               3209
#define IDC_SIGN_CLOSE            3210
#define IDC_SIGN_STATUS           3211
#define IDC_SIGN_LBL_HANDLE       3220
#define IDC_SIGN_LBL_IN           3221
#define IDC_SIGN_LBL_SIG          3222
#define IDC_SIGN_LBL_FORMAT       3223
#define IDC_SIGN_LBL_ALGO         3224
#define IDC_SIGN_LBL_HASH         3225

static HWND s_hDlg = NULL;
static HWND s_hHandle = NULL;
static HWND s_hIn = NULL;
static HWND s_hSig = NULL;
static HWND s_hFormat = NULL;
static HWND s_hAlgo = NULL;
static HWND s_hHash = NULL;
static HWND s_hStatus = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static CK_BBOOL s_bVerify = CK_FALSE;
static P11_SIGN_MECH s_mech;

static void DlgSign_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static void DlgSign_Enable(HWND hCtrl, BOOL bOn)
{
   if (hCtrl != NULL)
   {
      EnableWindow(hCtrl, bOn);
   }
}

static const char* DlgSign_Title(void)
{
   return (s_bVerify == CK_TRUE) ? "Verify signature" : "Sign file";
}

static CK_OBJECT_HANDLE DlgSign_ParseHandle(HWND hEdit)
{
   char sz[32];
   char* pEnd = NULL;
   unsigned long v;

   memset(sz, 0, sizeof(sz));
   GetWindowTextA(hEdit, sz, sizeof(sz));
   if (sz[0] == 0)
   {
      return 0;
   }
   v = strtoul(sz, &pEnd, 10);
   if ((pEnd == sz) || (*pEnd != 0))
   {
      return 0;
   }
   return (CK_OBJECT_HANDLE)v;
}

static void DlgSign_AddFmt(HWND hCombo, const char* sName, CK_BYTE fmt)
{
   int iItem = (int)SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)sName);
   if (iItem >= 0)
   {
      SendMessageA(hCombo, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)fmt);
   }
}

static CK_BYTE DlgSign_Format(void)
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

static const char* DlgSign_ComboName(HWND hCombo)
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

static void DlgSign_SelectNamed(HWND hCombo, const char* sName)
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

static void DlgSign_FillAlgos(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetSignCount(KEY_TYPE_SIGN);

   SendMessageA(s_hAlgo, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetSignNameAt(KEY_TYPE_SIGN, uLoop);
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
   DlgSign_SelectNamed(s_hAlgo, "sha256_rsa_pkcs");
}

static void DlgSign_FillHash(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetHashCount(KEY_TYPE_HASH);

   SendMessageA(s_hHash, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetHashNameAt(KEY_TYPE_HASH, uLoop);
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
   DlgSign_SelectNamed(s_hHash, "sha256");
}

static void DlgSign_FillFormat(void)
{
   SendMessageA(s_hFormat, CB_RESETCONTENT, 0, 0);
   DlgSign_AddFmt(s_hFormat, "hex text", P11_FILE_FORMAT_TEXT);
   DlgSign_AddFmt(s_hFormat, "binary", P11_FILE_FORMAT_BINARY);
   /* Default binary: a normal file (e.g. .txt) is raw bytes, not hexadecimal. */
   SendMessageA(s_hFormat, CB_SETCURSEL, 1, 0);
}

static void DlgSign_UpdateFields(void)
{
   const char* pAlgo;
   BOOL bPss = FALSE;

   pAlgo = DlgSign_ComboName(s_hAlgo);
   if ((pAlgo != NULL) && (strcmp(pAlgo, "rsa_pkcs_pss") == 0))
   {
      bPss = TRUE;
   }
   DlgSign_Enable(s_hHash, bPss);
}

static BOOL DlgSign_PickFile(BOOL bSave, char* szPath, unsigned int pathSize)
{
   OPENFILENAMEA ofn;

   if ((szPath == NULL) || (pathSize < 8))
   {
      return FALSE;
   }
   memset(szPath, 0, pathSize);
   GetWindowTextA(bSave ? s_hSig : s_hIn, szPath, (int)pathSize);
   if ((bSave != FALSE) && (szPath[0] == 0))
   {
      strncpy(szPath, "signature.bin", pathSize - 1);
   }

   memset(&ofn, 0, sizeof(ofn));
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = s_hDlg;
   ofn.lpstrFilter = "All files (*.*)\0*.*\0Text (*.txt)\0*.txt\0Binary (*.bin)\0*.bin\0Signature (*.sig)\0*.sig\0";
   ofn.lpstrFile = szPath;
   ofn.nMaxFile = pathSize;
   ofn.Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
   if (bSave != FALSE)
   {
      ofn.Flags |= OFN_OVERWRITEPROMPT;
      ofn.lpstrTitle = "Signature file";
      return (GetSaveFileNameA(&ofn) != FALSE) ? TRUE : FALSE;
   }
   ofn.Flags |= OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
   ofn.lpstrTitle = (s_bVerify == CK_TRUE) ? "Input file" : "Input file";
   return (GetOpenFileNameA(&ofn) != FALSE) ? TRUE : FALSE;
}

static BOOL DlgSign_PickSigFile(void)
{
   char szPath[GUI_PATH_MAX];
   OPENFILENAMEA ofn;
   BOOL bSave;

   memset(szPath, 0, sizeof(szPath));
   GetWindowTextA(s_hSig, szPath, sizeof(szPath));
   bSave = (s_bVerify == CK_TRUE) ? FALSE : TRUE;
   if ((bSave != FALSE) && (szPath[0] == 0))
   {
      strncpy(szPath, "signature.bin", sizeof(szPath) - 1);
   }

   memset(&ofn, 0, sizeof(ofn));
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = s_hDlg;
   ofn.lpstrFilter = "All files (*.*)\0*.*\0Signature (*.sig)\0*.sig\0Binary (*.bin)\0*.bin\0Text (*.txt)\0*.txt\0";
   ofn.lpstrFile = szPath;
   ofn.nMaxFile = sizeof(szPath);
   ofn.Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
   ofn.lpstrTitle = "Signature file";
   if (bSave != FALSE)
   {
      ofn.Flags |= OFN_OVERWRITEPROMPT;
      if (GetSaveFileNameA(&ofn) == FALSE)
      {
         return FALSE;
      }
   }
   else
   {
      ofn.Flags |= OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
      if (GetOpenFileNameA(&ofn) == FALSE)
      {
         return FALSE;
      }
   }
   SetWindowTextA(s_hSig, szPath);
   return TRUE;
}

static void DlgSign_DoOp(void)
{
   char szIn[GUI_PATH_MAX];
   char szSig[GUI_PATH_MAX];
   char szErr[P11_QUERY_ERR_MAX];
   char szStatus[GUI_STATUS_TEXT_MAX];
   CK_BYTE fmt;
   CK_ULONG uWritten = 0;
   const char* pAlgo;
   const char* pHash;
   CK_OBJECT_HANDLE hKey;

   memset(szIn, 0, sizeof(szIn));
   memset(szSig, 0, sizeof(szSig));
   memset(&s_mech, 0, sizeof(s_mech));

   hKey = DlgSign_ParseHandle(s_hHandle);
   if (hKey == 0)
   {
      DlgSign_SetStatus("Enter the handle of the signature key.");
      return;
   }
   GetWindowTextA(s_hIn, szIn, sizeof(szIn));
   GetWindowTextA(s_hSig, szSig, sizeof(szSig));
   if (szIn[0] == 0)
   {
      DlgSign_SetStatus("Choose an input file.");
      return;
   }
   if (szSig[0] == 0)
   {
      /* Verify needs an existing signature; sign can default next to the input. */
      if ((s_bVerify != CK_FALSE) || (strlen(szIn) + 5 >= sizeof(szSig)))
      {
         DlgSign_SetStatus("Choose a signature file.");
         return;
      }
      _snprintf(szSig, sizeof(szSig) - 1, "%s.sig", szIn);
      SetWindowTextA(s_hSig, szSig);
   }

   pAlgo = DlgSign_ComboName(s_hAlgo);
   if ((pAlgo == NULL) || (pAlgo[0] == 0))
   {
      DlgSign_SetStatus("Select an algorithm.");
      return;
   }
   pHash = DlgSign_ComboName(s_hHash);
   if (P11_QueryBuildSignMech(pAlgo, pHash, &s_mech, szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgSign_SetStatus(szErr[0] != 0 ? szErr : "Invalid algorithm.");
      return;
   }

   fmt = DlgSign_Format();
   if (s_bVerify == CK_TRUE)
   {
      DlgSign_SetStatus("Verifying...");
      UpdateWindow(s_hStatus);
      if (P11_QueryVerifyFile(hKey, &s_mech, szIn, szSig, fmt, szErr, sizeof(szErr)) != CK_TRUE)
      {
         DlgSign_SetStatus(szErr[0] != 0 ? szErr : "Verify failed.");
         return;
      }
      DlgSign_SetStatus("Signature is valid.");
      return;
   }

   DlgSign_SetStatus("Signing...");
   UpdateWindow(s_hStatus);
   if (P11_QuerySignFile(hKey, &s_mech, szIn, szSig, fmt, &uWritten, szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgSign_SetStatus(szErr[0] != 0 ? szErr : "Sign failed.");
      return;
   }
   memset(szStatus, 0, sizeof(szStatus));
   _snprintf(szStatus, sizeof(szStatus) - 1, "Signed with handle %lu. %lu bytes written to %s",
      (unsigned long)hKey, (unsigned long)uWritten, szSig);
   DlgSign_SetStatus(szStatus);
}

static void DlgSign_Layout(int cx, int cy)
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
   MoveWindow(GetDlgItem(s_hDlg, IDC_SIGN_LBL_HANDLE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hHandle, fieldX, y, 120, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_SIGN_LBL_IN), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hIn, fieldX, y, fieldW, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_SIGN_IN_BROWSE), browseX, y, DLG_BROWSE_W, DLG_BTN_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_SIGN_LBL_SIG), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hSig, fieldX, y, fieldW, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_SIGN_SIG_BROWSE), browseX, y, DLG_BROWSE_W, DLG_BTN_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_SIGN_LBL_FORMAT), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hFormat, fieldX, y, 160, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_SIGN_LBL_ALGO), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hAlgo, fieldX, y, 240, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_SIGN_LBL_HASH), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hHash, fieldX, y, 160, DLG_COMBO_DROP, TRUE);

   y = cy - DLG_MARGIN - DLG_BTN_H;
   MoveWindow(s_hStatus, DLG_MARGIN, y - 26, cx - (2 * DLG_MARGIN), 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_SIGN_GO), cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, y, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_SIGN_CLOSE), cx - DLG_MARGIN - DLG_BTN_W, y, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static HWND DlgSign_Label(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("STATIC", sText, WS_CHILD | WS_VISIBLE,
      0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static LRESULT CALLBACK DlgSign_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
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

         DlgSign_Label(hWnd, "Handle:", IDC_SIGN_LBL_HANDLE);
         s_hHandle = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 120, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_SIGN_HANDLE, NULL, NULL);
         DlgSign_Label(hWnd, "Input file:", IDC_SIGN_LBL_IN);
         s_hIn = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_SIGN_IN, NULL, NULL);
         CreateWindowA("BUTTON", "Browse...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BROWSE_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_SIGN_IN_BROWSE, NULL, NULL);
         DlgSign_Label(hWnd, (s_bVerify == CK_FALSE) ? "Signature file (optional):" : "Signature file:", IDC_SIGN_LBL_SIG);
         s_hSig = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_SIGN_SIG, NULL, NULL);
         CreateWindowA("BUTTON", "Browse...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BROWSE_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_SIGN_SIG_BROWSE, NULL, NULL);
         DlgSign_Label(hWnd, "Format:", IDC_SIGN_LBL_FORMAT);
         s_hFormat = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 160, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_SIGN_FORMAT, NULL, NULL);
         DlgSign_Label(hWnd, "Algorithm:", IDC_SIGN_LBL_ALGO);
         s_hAlgo = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 240, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_SIGN_ALGO, NULL, NULL);
         DlgSign_Label(hWnd, "PSS hash:", IDC_SIGN_LBL_HASH);
         s_hHash = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 160, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_SIGN_HASH, NULL, NULL);
         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_SIGN_STATUS, NULL, NULL);
         CreateWindowA("BUTTON", (s_bVerify == CK_TRUE) ? "Verify" : "Sign",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_SIGN_GO, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_SIGN_CLOSE, NULL, NULL);

         SendMessageA(s_hIn, EM_SETLIMITTEXT, GUI_PATH_MAX - 1, 0);
         SendMessageA(s_hSig, EM_SETLIMITTEXT, GUI_PATH_MAX - 1, 0);
         DlgSign_FillFormat();
         DlgSign_FillAlgos();
         DlgSign_FillHash();

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
         DlgSign_UpdateFields();
         DlgSign_SetStatus((s_bVerify == CK_TRUE)
            ? "Private/secret keys sign; public/secret keys verify. Use binary for a raw file; hex text for hexadecimal."
            : "Hashed RSA/ECDSA sign the file. Use binary for a raw .txt; hex text only if the file is hexadecimal.");
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
      DlgSign_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 560;
         pMin->ptMinTrackSize.y = 340;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_SIGN_ALGO:
         if (HIWORD(wParam) == CBN_SELCHANGE)
         {
            DlgSign_UpdateFields();
         }
         return 0;
      case IDC_SIGN_IN_BROWSE:
         {
            char szPath[GUI_PATH_MAX];
            if (DlgSign_PickFile(FALSE, szPath, sizeof(szPath)) != FALSE)
            {
               SetWindowTextA(s_hIn, szPath);
            }
         }
         return 0;
      case IDC_SIGN_SIG_BROWSE:
         DlgSign_PickSigFile();
         return 0;
      case IDC_SIGN_GO:
      case IDOK:
         DlgSign_DoOp();
         return 0;
      case IDC_SIGN_CLOSE:
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
      s_hIn = NULL;
      s_hSig = NULL;
      s_hFormat = NULL;
      s_hAlgo = NULL;
      s_hHash = NULL;
      s_hStatus = NULL;
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }
   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

void DlgSign_Show(HWND hwndParent, CK_BBOOL bVerify)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      MessageBoxA(hwndParent, "Not logged in.",
         (bVerify == CK_TRUE) ? "Verify signature" : "Sign file",
         MB_OK | MB_ICONWARNING);
      return;
   }

   s_bVerify = bVerify;

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgSign_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_SIGN_CLASS;
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_SIGN_CLASS,
      DlgSign_Title(),
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 28, rc.top + 28, 580, 370,
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
