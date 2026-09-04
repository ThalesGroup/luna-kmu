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

#define _DLG_COMPUTEKCV_C

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
#include "dlg_computekcv.h"

#define DLG_KCV_CLASS             "LunaKmuComputeKcv"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               72

#define IDC_KCV_LBL_HANDLE        2701
#define IDC_KCV_HANDLE            2702
#define IDC_KCV_LBL_METHOD        2703
#define IDC_KCV_METHOD            2704
#define IDC_KCV_LBL_RESULT        2705
#define IDC_KCV_RESULT            2706
#define IDC_KCV_COMPUTE           2707
#define IDC_KCV_COPY              2708
#define IDC_KCV_CLOSE             2709
#define IDC_KCV_STATUS            2710

static HWND s_hDlg = NULL;
static HWND s_hMethod = NULL;
static HWND s_hResult = NULL;
static HWND s_hStatus = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static CK_OBJECT_HANDLE s_hKey = 0;

static void DlgComputeKcv_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static void DlgComputeKcv_CopyResult(void)
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
      DlgComputeKcv_SetStatus("Nothing to copy.");
      return;
   }
   hMem = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)nLen + 1);
   if (hMem == NULL)
   {
      DlgComputeKcv_SetStatus("Copy failed.");
      return;
   }
   pMem = (char*)GlobalLock(hMem);
   if (pMem == NULL)
   {
      GlobalFree(hMem);
      DlgComputeKcv_SetStatus("Copy failed.");
      return;
   }
   GetWindowTextA(s_hResult, pMem, nLen + 1);
   GlobalUnlock(hMem);
   if (OpenClipboard(s_hDlg) == FALSE)
   {
      GlobalFree(hMem);
      DlgComputeKcv_SetStatus("Copy failed.");
      return;
   }
   EmptyClipboard();
   SetClipboardData(CF_TEXT, hMem);
   CloseClipboard();
   DlgComputeKcv_SetStatus("Copied.");
}

static void DlgComputeKcv_SelectNamed(const char* sName)
{
   int iCount;
   int iLoop;
   char sz[64];

   if ((s_hMethod == NULL) || (sName == NULL))
   {
      return;
   }
   iCount = (int)SendMessageA(s_hMethod, CB_GETCOUNT, 0, 0);
   for (iLoop = 0; iLoop < iCount; iLoop++)
   {
      memset(sz, 0, sizeof(sz));
      SendMessageA(s_hMethod, CB_GETLBTEXT, (WPARAM)iLoop, (LPARAM)sz);
      if (strcmp(sz, sName) == 0)
      {
         SendMessageA(s_hMethod, CB_SETCURSEL, (WPARAM)iLoop, 0);
         return;
      }
   }
   SendMessageA(s_hMethod, CB_SETCURSEL, 0, 0);
}

static void DlgComputeKcv_FillMethod(void)
{
   CK_ULONG ulCount;
   CK_ULONG ulLoop;
   CK_CHAR_PTR pName;
   BYTE bMethod;
   int iItem;
   CK_ULONG ulType = 0;
   const char* sDefault = "pci";

   if (s_hMethod == NULL)
   {
      return;
   }
   SendMessageA(s_hMethod, CB_RESETCONTENT, 0, 0);
   ulCount = P11Util_GetKCVMethodCount();
   for (ulLoop = 0; ulLoop < ulCount; ulLoop++)
   {
      pName = P11Util_GetKCVMethodNameAt(ulLoop);
      if (pName == NULL)
      {
         continue;
      }
      bMethod = P11Util_GetKCVMethod(pName);
      iItem = (int)SendMessageA(s_hMethod, CB_ADDSTRING, 0, (LPARAM)pName);
      if (iItem >= 0)
      {
         SendMessageA(s_hMethod, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)bMethod);
      }
   }

   if (P11_QueryAttrUlong(s_hKey, CKA_KEY_TYPE, &ulType) == CK_TRUE)
   {
      if (ulType == CKK_GENERIC_SECRET)
      {
         sDefault = "hmac-sha-256";
      }
   }
   DlgComputeKcv_SelectNamed(sDefault);
}

static BYTE DlgComputeKcv_GetMethod(void)
{
   int iSel;
   LPARAM data;

   iSel = (int)SendMessageA(s_hMethod, CB_GETCURSEL, 0, 0);
   if (iSel < 0)
   {
      return 0;
   }
   data = SendMessageA(s_hMethod, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if ((data == 0) || (data == CB_ERR))
   {
      return 0;
   }
   return (BYTE)data;
}

static void DlgComputeKcv_Compute(void)
{
   BYTE bMethod;
   CK_BYTE* pKcv = NULL;
   CK_ULONG ulLen = 0;
   CK_RV rv = CKR_GENERAL_ERROR;
   CK_ULONG ulClass = 0;
   CK_CHAR_PTR pHex;
   char szStatus[192];

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      DlgComputeKcv_SetStatus("Not logged in.");
      return;
   }
   if (s_hKey == 0)
   {
      DlgComputeKcv_SetStatus("No key handle.");
      return;
   }
   if (P11_QueryAttrUlong(s_hKey, CKA_CLASS, &ulClass) != CK_TRUE)
   {
      DlgComputeKcv_SetStatus("Key not found.");
      return;
   }
   if (ulClass != CKO_SECRET_KEY)
   {
      DlgComputeKcv_SetStatus("Object is not a secret key.");
      return;
   }

   bMethod = DlgComputeKcv_GetMethod();
   if (bMethod == 0)
   {
      DlgComputeKcv_SetStatus("Select a KCV method.");
      return;
   }

   SetWindowTextA(s_hResult, "");
   DlgComputeKcv_SetStatus("Computing KCV...");
   UpdateWindow(s_hStatus);

   if (P11_QueryComputeKCV(s_hKey, bMethod, &pKcv, &ulLen, &rv) != CK_TRUE)
   {
      memset(szStatus, 0, sizeof(szStatus));
      if (rv == CKR_KEY_TYPE_INCONSISTENT)
      {
         _snprintf(szStatus, sizeof(szStatus) - 1,
            "Unsupported key type for KCV (AES, DES, or HMAC/generic).");
      }
      else if (rv == CKR_ARGUMENTS_BAD)
      {
         _snprintf(szStatus, sizeof(szStatus) - 1, "Select a KCV method.");
      }
      else
      {
         _snprintf(szStatus, sizeof(szStatus) - 1, "KCV failed: %s",
            (const char*)P11Util_DisplayErrorName(rv));
      }
      DlgComputeKcv_SetStatus(szStatus);
      return;
   }

   pHex = str_ByteArraytoString((CK_CHAR_PTR)pKcv, (CK_LONG)ulLen);
   free(pKcv);
   pKcv = NULL;
   if (pHex == NULL)
   {
      DlgComputeKcv_SetStatus("Out of memory.");
      return;
   }
   SetWindowTextA(s_hResult, (const char*)pHex);
   free(pHex);
   DlgComputeKcv_SetStatus("KCV computed.");
}

static void DlgComputeKcv_Layout(int cx, int cy)
{
   int editX;
   int editW;
   int y;
   int yBtn;

   if (cx < 360)
   {
      cx = 360;
   }
   if (cy < 180)
   {
      cy = 180;
   }

   editX = DLG_MARGIN + DLG_LABEL_W + 8;
   editW = cx - editX - DLG_MARGIN;
   if (editW < 120)
   {
      editW = 120;
   }

   y = DLG_MARGIN;
   MoveWindow(GetDlgItem(s_hDlg, IDC_KCV_LBL_HANDLE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_KCV_HANDLE), editX, y, editW, DLG_EDIT_H, TRUE);
   y += DLG_EDIT_H + 8;

   MoveWindow(GetDlgItem(s_hDlg, IDC_KCV_LBL_METHOD), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hMethod, editX, y, 180, 200, TRUE);
   y += DLG_EDIT_H + 10;

   MoveWindow(GetDlgItem(s_hDlg, IDC_KCV_LBL_RESULT), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hResult, editX, y, editW, DLG_EDIT_H, TRUE);

   yBtn = cy - DLG_MARGIN - DLG_BTN_H;
   MoveWindow(s_hStatus, DLG_MARGIN, yBtn - 22, cx - (2 * DLG_MARGIN) - (3 * DLG_BTN_W) - 24, 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_KCV_COMPUTE),
      cx - DLG_MARGIN - (3 * DLG_BTN_W) - 16, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_KCV_COPY),
      cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_KCV_CLOSE),
      cx - DLG_MARGIN - DLG_BTN_W, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static LRESULT CALLBACK DlgComputeKcv_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
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
            hWnd, (HMENU)(INT_PTR)IDC_KCV_LBL_HANDLE, NULL, NULL);
         CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 120, DLG_EDIT_H,
            hWnd, (HMENU)(INT_PTR)IDC_KCV_HANDLE, NULL, NULL);

         CreateWindowA("STATIC", "Method:",
            WS_CHILD | WS_VISIBLE, 0, 0, DLG_LABEL_W, 16,
            hWnd, (HMENU)(INT_PTR)IDC_KCV_LBL_METHOD, NULL, NULL);
         s_hMethod = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 180, 200, hWnd, (HMENU)(INT_PTR)IDC_KCV_METHOD, NULL, NULL);

         CreateWindowA("STATIC", "KCV:",
            WS_CHILD | WS_VISIBLE, 0, 0, DLG_LABEL_W, 16,
            hWnd, (HMENU)(INT_PTR)IDC_KCV_LBL_RESULT, NULL, NULL);
         s_hResult = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_READONLY | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_KCV_RESULT, NULL, NULL);

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_KCV_STATUS, NULL, NULL);

         CreateWindowA("BUTTON", "Compute",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_KCV_COMPUTE, NULL, NULL);
         CreateWindowA("BUTTON", "Copy",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_KCV_COPY, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_KCV_CLOSE, NULL, NULL);

         memset(szHandle, 0, sizeof(szHandle));
         _snprintf(szHandle, sizeof(szHandle) - 1, "%lu", (unsigned long)s_hKey);
         SetWindowTextA(GetDlgItem(hWnd, IDC_KCV_HANDLE), szHandle);

         DlgComputeKcv_FillMethod();

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
      DlgComputeKcv_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 440;
         pMin->ptMinTrackSize.y = 210;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_KCV_COMPUTE:
      case IDOK:
         DlgComputeKcv_Compute();
         return 0;
      case IDC_KCV_COPY:
         DlgComputeKcv_CopyResult();
         return 0;
      case IDC_KCV_CLOSE:
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
      s_hMethod = NULL;
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
    FUNCTION:        void DlgComputeKcv_Show(HWND hwndParent, CK_OBJECT_HANDLE hKey)
*/
void DlgComputeKcv_Show(HWND hwndParent, CK_OBJECT_HANDLE hKey)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      MessageBoxA(hwndParent, "Not logged in.", "Compute KCV", MB_OK | MB_ICONWARNING);
      return;
   }
   if (hKey == 0)
   {
      MessageBoxA(hwndParent, "Select a secret key.", "Compute KCV", MB_OK | MB_ICONWARNING);
      return;
   }

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgComputeKcv_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_KCV_CLASS;
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_KCV_CLASS, "Compute KCV",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 48, rc.top + 48, 500, 230,
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
