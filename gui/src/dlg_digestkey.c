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

#define _DLG_DIGESTKEY_C

#ifdef OS_WIN32
#include <windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "p11util.h"
#include "p11query.h"
#include "str.h"
#include "gui.h"
#include "gui_theme.h"
#include "dlg_digestkey.h"

#define DLG_DIG_CLASS             "LunaKmuDigestKey"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               72
#define DLG_RESULT_H              48

#define IDC_DIG_LBL_HANDLE        2601
#define IDC_DIG_HANDLE            2602
#define IDC_DIG_LBL_HASH          2603
#define IDC_DIG_HASH              2604
#define IDC_DIG_LBL_RESULT        2605
#define IDC_DIG_RESULT            2606
#define IDC_DIG_COMPUTE           2607
#define IDC_DIG_COPY              2608
#define IDC_DIG_CLOSE             2609
#define IDC_DIG_STATUS            2610

static HWND s_hDlg = NULL;
static HWND s_hHash = NULL;
static HWND s_hResult = NULL;
static HWND s_hStatus = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static CK_OBJECT_HANDLE s_hKey = 0;

static void DlgDigestKey_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static void DlgDigestKey_CopyResult(void)
{
   int nLen;
   HGLOBAL hMem;
   char* pMem;

   if (s_hResult == NULL)
   {
      return;
   }
   nLen = GetWindowTextLengthA(s_hResult);
   if (nLen <= 0)
   {
      DlgDigestKey_SetStatus("Nothing to copy.");
      return;
   }
   hMem = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)nLen + 1);
   if (hMem == NULL)
   {
      DlgDigestKey_SetStatus("Copy failed.");
      return;
   }
   pMem = (char*)GlobalLock(hMem);
   if (pMem == NULL)
   {
      GlobalFree(hMem);
      DlgDigestKey_SetStatus("Copy failed.");
      return;
   }
   GetWindowTextA(s_hResult, pMem, nLen + 1);
   GlobalUnlock(hMem);
   if (OpenClipboard(s_hDlg) == FALSE)
   {
      GlobalFree(hMem);
      DlgDigestKey_SetStatus("Copy failed.");
      return;
   }
   EmptyClipboard();
   SetClipboardData(CF_TEXT, hMem);
   CloseClipboard();
   DlgDigestKey_SetStatus("Copied.");
}

static void DlgDigestKey_FillHash(void)
{
   CK_ULONG ulCount;
   CK_ULONG ulLoop;
   CK_CHAR_PTR pName;
   int iItem;
   int iDefault = 0;

   if (s_hHash == NULL)
   {
      return;
   }
   SendMessageA(s_hHash, CB_RESETCONTENT, 0, 0);
   ulCount = P11Util_GetHashCount(KEY_TYPE_HASH);
   for (ulLoop = 0; ulLoop < ulCount; ulLoop++)
   {
      pName = P11Util_GetHashNameAt(KEY_TYPE_HASH, ulLoop);
      if (pName == NULL)
      {
         continue;
      }
      iItem = (int)SendMessageA(s_hHash, CB_ADDSTRING, 0, (LPARAM)pName);
      if (iItem >= 0)
      {
         SendMessageA(s_hHash, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)pName);
      }
      if (strcmp((const char*)pName, "sha256") == 0)
      {
         iDefault = iItem;
      }
   }
   SendMessageA(s_hHash, CB_SETCURSEL, (WPARAM)iDefault, 0);
}

static P11_HASH_MECH* DlgDigestKey_GetHash(void)
{
   int iSel;
   LPARAM data;
   CK_CHAR_PTR pName;

   iSel = (int)SendMessageA(s_hHash, CB_GETCURSEL, 0, 0);
   if (iSel < 0)
   {
      return NULL;
   }
   data = SendMessageA(s_hHash, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if ((data == 0) || (data == CB_ERR))
   {
      return NULL;
   }
   pName = (CK_CHAR_PTR)data;
   return P11Util_GetHash(pName, KEY_TYPE_HASH);
}

static void DlgDigestKey_Compute(void)
{
   P11_HASH_MECH* pHash;
   CK_BYTE* pDigest = NULL;
   CK_ULONG ulLen = 0;
   CK_RV rv = CKR_GENERAL_ERROR;
   CK_ULONG ulClass = 0;
   CK_CHAR_PTR pHex;
   char szStatus[192];

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      DlgDigestKey_SetStatus("Not logged in.");
      return;
   }
   if (s_hKey == 0)
   {
      DlgDigestKey_SetStatus("No key handle.");
      return;
   }
   if (P11_QueryAttrUlong(s_hKey, CKA_CLASS, &ulClass) != CK_TRUE)
   {
      DlgDigestKey_SetStatus("Key not found.");
      return;
   }
   if (ulClass != CKO_SECRET_KEY)
   {
      DlgDigestKey_SetStatus("Object is not a secret key.");
      return;
   }

   pHash = DlgDigestKey_GetHash();
   if (pHash == NULL)
   {
      DlgDigestKey_SetStatus("Select a hash.");
      return;
   }

   SetWindowTextA(s_hResult, "");
   DlgDigestKey_SetStatus("Computing digest...");
   UpdateWindow(s_hStatus);

   if (P11_QueryDigestKey(s_hKey, pHash, &pDigest, &ulLen, &rv) != CK_TRUE)
   {
      memset(szStatus, 0, sizeof(szStatus));
      if (rv == CKR_KEY_TYPE_INCONSISTENT)
      {
         _snprintf(szStatus, sizeof(szStatus) - 1, "Object is not a secret key.");
      }
      else
      {
         _snprintf(szStatus, sizeof(szStatus) - 1, "Digest failed: %s",
            (const char*)P11Util_DisplayErrorName(rv));
      }
      DlgDigestKey_SetStatus(szStatus);
      return;
   }

   pHex = str_ByteArraytoString((CK_CHAR_PTR)pDigest, (CK_LONG)ulLen);
   free(pDigest);
   pDigest = NULL;
   if (pHex == NULL)
   {
      DlgDigestKey_SetStatus("Out of memory.");
      return;
   }
   SetWindowTextA(s_hResult, (const char*)pHex);
   free(pHex);
   DlgDigestKey_SetStatus("Digest computed.");
}

static void DlgDigestKey_Layout(int cx, int cy)
{
   int editX;
   int editW;
   int y;
   int yBtn;
   int resultH;

   if (cx < 360)
   {
      cx = 360;
   }
   if (cy < 200)
   {
      cy = 200;
   }

   editX = DLG_MARGIN + DLG_LABEL_W + 8;
   editW = cx - editX - DLG_MARGIN;
   if (editW < 120)
   {
      editW = 120;
   }

   y = DLG_MARGIN;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DIG_LBL_HANDLE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_DIG_HANDLE), editX, y, editW, DLG_EDIT_H, TRUE);
   y += DLG_EDIT_H + 8;

   MoveWindow(GetDlgItem(s_hDlg, IDC_DIG_LBL_HASH), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hHash, editX, y, 160, 200, TRUE);
   y += DLG_EDIT_H + 10;

   yBtn = cy - DLG_MARGIN - DLG_BTN_H;
   resultH = yBtn - 22 - y - 18;
   if (resultH < DLG_RESULT_H)
   {
      resultH = DLG_RESULT_H;
   }
   MoveWindow(GetDlgItem(s_hDlg, IDC_DIG_LBL_RESULT), DLG_MARGIN, y, DLG_LABEL_W, 16, TRUE);
   y += 18;
   MoveWindow(s_hResult, DLG_MARGIN, y, cx - (2 * DLG_MARGIN), resultH, TRUE);

   MoveWindow(s_hStatus, DLG_MARGIN, yBtn - 22, cx - (2 * DLG_MARGIN) - (3 * DLG_BTN_W) - 24, 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_DIG_COMPUTE),
      cx - DLG_MARGIN - (3 * DLG_BTN_W) - 16, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_DIG_COPY),
      cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_DIG_CLOSE),
      cx - DLG_MARGIN - DLG_BTN_W, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static LRESULT CALLBACK DlgDigestKey_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      {
         HWND hCtrl;
         char szHandle[32];

         s_hDlg = hWnd;
         s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

         CreateWindowA("STATIC", "Handle:",
            WS_CHILD | WS_VISIBLE, 0, 0, DLG_LABEL_W, 16,
            hWnd, (HMENU)(INT_PTR)IDC_DIG_LBL_HANDLE, NULL, NULL);
         CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 120, DLG_EDIT_H,
            hWnd, (HMENU)(INT_PTR)IDC_DIG_HANDLE, NULL, NULL);

         CreateWindowA("STATIC", "Hash:",
            WS_CHILD | WS_VISIBLE, 0, 0, DLG_LABEL_W, 16,
            hWnd, (HMENU)(INT_PTR)IDC_DIG_LBL_HASH, NULL, NULL);
         s_hHash = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 160, 200, hWnd, (HMENU)(INT_PTR)IDC_DIG_HASH, NULL, NULL);

         CreateWindowA("STATIC", "Digest:",
            WS_CHILD | WS_VISIBLE, 0, 0, DLG_LABEL_W, 16,
            hWnd, (HMENU)(INT_PTR)IDC_DIG_LBL_RESULT, NULL, NULL);
         s_hResult = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | WS_VSCROLL |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 0, 200, DLG_RESULT_H, hWnd, (HMENU)(INT_PTR)IDC_DIG_RESULT, NULL, NULL);

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_DIG_STATUS, NULL, NULL);

         CreateWindowA("BUTTON", "Compute",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_DIG_COMPUTE, NULL, NULL);
         CreateWindowA("BUTTON", "Copy",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_DIG_COPY, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_DIG_CLOSE, NULL, NULL);

         memset(szHandle, 0, sizeof(szHandle));
         _snprintf(szHandle, sizeof(szHandle) - 1, "%lu", (unsigned long)s_hKey);
         SetWindowTextA(GetDlgItem(hWnd, IDC_DIG_HANDLE), szHandle);

         DlgDigestKey_FillHash();

         for (hCtrl = GetWindow(hWnd, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
         {
            SendMessageA(hCtrl, WM_SETFONT, (WPARAM)s_hFont, TRUE);
         }
         GUI_ThemeMarkStatus(s_hStatus);
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
      DlgDigestKey_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 440;
         pMin->ptMinTrackSize.y = 240;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_DIG_COMPUTE:
      case IDOK:
         DlgDigestKey_Compute();
         return 0;
      case IDC_DIG_COPY:
         DlgDigestKey_CopyResult();
         return 0;
      case IDC_DIG_CLOSE:
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
      s_hHash = NULL;
      s_hResult = NULL;
      s_hStatus = NULL;
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }

   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

/*
    FUNCTION:        void DlgDigestKey_Show(HWND hwndParent, CK_OBJECT_HANDLE hKey)
*/
void DlgDigestKey_Show(HWND hwndParent, CK_OBJECT_HANDLE hKey)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      MessageBoxA(hwndParent, "Not logged in.", "Digest key", MB_OK | MB_ICONWARNING);
      return;
   }
   if (hKey == 0)
   {
      MessageBoxA(hwndParent, "Select a secret key.", "Digest key", MB_OK | MB_ICONWARNING);
      return;
   }

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgDigestKey_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_DIG_CLASS;
   RegisterClassExA(&wc);

   s_hKey = hKey;
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_DIG_CLASS, "Digest key",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 48, rc.top + 48, 520, 280,
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
   s_hKey = 0;
}
