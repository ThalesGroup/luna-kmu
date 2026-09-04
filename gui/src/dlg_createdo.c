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

#define _DLG_CREATEDO_C

#ifdef OS_WIN32
#include <windows.h>
#include <commctrl.h>
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
#include "dlg_createdo.h"

#define DLG_DO_CLASS              "LunaKmuCreateDO"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               86
#define DLG_MAX_LABEL             100
#define DLG_APP_MAX               256
#define DLG_HEX_MAX               8192

#define IDC_DO_LBL_LABEL          2501
#define IDC_DO_LABEL              2502
#define IDC_DO_LBL_APP            2503
#define IDC_DO_APP                2504
#define IDC_DO_LBL_VALUE          2505
#define IDC_DO_VALUE              2506
#define IDC_DO_TOKEN              2507
#define IDC_DO_PRIVATE            2508
#define IDC_DO_MODIFIABLE         2509
#define IDC_DO_CREATE             2510
#define IDC_DO_CLOSE              2511
#define IDC_DO_STATUS             2512

static HWND s_hDlg = NULL;
static HWND s_hLabel = NULL;
static HWND s_hApp = NULL;
static HWND s_hValue = NULL;
static HWND s_hToken = NULL;
static HWND s_hPrivate = NULL;
static HWND s_hModifiable = NULL;
static HWND s_hStatus = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;

static void DlgCreateDO_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static CK_BBOOL DlgCreateDO_IsChecked(HWND hChk)
{
   if (hChk == NULL)
   {
      return CK_FALSE;
   }
   return (SendMessageA(hChk, BM_GETCHECK, 0, 0) == BST_CHECKED) ? CK_TRUE : CK_FALSE;
}

static void DlgCreateDO_StripHex(char* s)
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

static void DlgCreateDO_Layout(int cx, int cy)
{
   int y;
   int editX;
   int editW;
   int yBtn;

   if (cx < 360)
   {
      cx = 360;
   }
   if (cy < 220)
   {
      cy = 220;
   }

   editX = DLG_MARGIN + DLG_LABEL_W + 8;
   editW = cx - editX - DLG_MARGIN;
   if (editW < 120)
   {
      editW = 120;
   }

   y = DLG_MARGIN;
   MoveWindow(GetDlgItem(s_hDlg, IDC_DO_LBL_LABEL), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hLabel, editX, y, editW, DLG_EDIT_H, TRUE);
   y += DLG_EDIT_H + 8;

   MoveWindow(GetDlgItem(s_hDlg, IDC_DO_LBL_APP), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hApp, editX, y, editW, DLG_EDIT_H, TRUE);
   y += DLG_EDIT_H + 8;

   MoveWindow(GetDlgItem(s_hDlg, IDC_DO_LBL_VALUE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hValue, editX, y, editW, DLG_EDIT_H, TRUE);
   y += DLG_EDIT_H + 10;

   MoveWindow(s_hToken, DLG_MARGIN, y, 70, 18, TRUE);
   MoveWindow(s_hPrivate, DLG_MARGIN + 78, y, 70, 18, TRUE);
   MoveWindow(s_hModifiable, DLG_MARGIN + 156, y, 90, 18, TRUE);

   yBtn = cy - DLG_MARGIN - DLG_BTN_H;
   MoveWindow(s_hStatus, DLG_MARGIN, yBtn - 22, cx - (2 * DLG_MARGIN) - (2 * DLG_BTN_W) - 16, 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_DO_CREATE),
      cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_DO_CLOSE),
      cx - DLG_MARGIN - DLG_BTN_W, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static void DlgCreateDO_DoCreate(void)
{
   char szLabel[DLG_MAX_LABEL];
   char szApp[DLG_APP_MAX];
   char szValue[DLG_HEX_MAX + 2];
   char szStatus[192];
   P11_DOTEMPLATE tpl;
   CK_OBJECT_HANDLE hObj = 0;
   CK_RV rv = CKR_GENERAL_ERROR;
   CK_LONG nValLen = 0;

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      DlgCreateDO_SetStatus("Not logged in.");
      return;
   }

   memset(szLabel, 0, sizeof(szLabel));
   memset(szApp, 0, sizeof(szApp));
   memset(szValue, 0, sizeof(szValue));
   GetWindowTextA(s_hLabel, szLabel, sizeof(szLabel));
   GetWindowTextA(s_hApp, szApp, sizeof(szApp));
   GetWindowTextA(s_hValue, szValue, sizeof(szValue));

   if (szLabel[0] == 0)
   {
      DlgCreateDO_SetStatus("Label is required.");
      SetFocus(s_hLabel);
      return;
   }

   DlgCreateDO_StripHex(szValue);
   if (szValue[0] != 0)
   {
      nValLen = (CK_LONG)str_StringtoByteArray((CK_CHAR_PTR)szValue, (CK_ULONG)strlen(szValue));
      if (nValLen == 0)
      {
         DlgCreateDO_SetStatus("Value must be hexadecimal.");
         SetFocus(s_hValue);
         return;
      }
   }

   memset(&tpl, 0, sizeof(tpl));
   tpl.bCKA_Token = DlgCreateDO_IsChecked(s_hToken);
   tpl.bCKA_Private = DlgCreateDO_IsChecked(s_hPrivate);
   tpl.bCKA_Modifiable = DlgCreateDO_IsChecked(s_hModifiable);
   tpl.pLabel = (CK_CHAR_PTR)szLabel;
   tpl.pApplication = (CK_CHAR_PTR)szApp;
   tpl.pValue = (nValLen > 0) ? (CK_CHAR_PTR)szValue : NULL;
   tpl.upValueLength = nValLen;

   DlgCreateDO_SetStatus("Creating data object...");
   UpdateWindow(s_hStatus);

   if (P11_QueryCreateDO(&tpl, &hObj, &rv) != CK_TRUE)
   {
      memset(szStatus, 0, sizeof(szStatus));
      _snprintf(szStatus, sizeof(szStatus) - 1, "Create failed: %s",
         (const char*)P11Util_DisplayErrorName(rv));
      DlgCreateDO_SetStatus(szStatus);
      return;
   }

   memset(szStatus, 0, sizeof(szStatus));
   _snprintf(szStatus, sizeof(szStatus) - 1,
      "Data object created, handle is %lu.", (unsigned long)hObj);
   DlgCreateDO_SetStatus(szStatus);
}

static HWND DlgCreateDO_CreateLabel(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("STATIC", sText, WS_CHILD | WS_VISIBLE,
      0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static HWND DlgCreateDO_CreateEdit(HWND hWnd, int id)
{
   return CreateWindowA("EDIT", "",
      WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
      0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static HWND DlgCreateDO_CreateCheck(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("BUTTON", sText,
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
      0, 0, 90, 18, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static LRESULT CALLBACK DlgCreateDO_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      {
         HWND hCtrl;

         s_hDlg = hWnd;
         s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

         DlgCreateDO_CreateLabel(hWnd, "Label:", IDC_DO_LBL_LABEL);
         s_hLabel = DlgCreateDO_CreateEdit(hWnd, IDC_DO_LABEL);
         DlgCreateDO_CreateLabel(hWnd, "Application:", IDC_DO_LBL_APP);
         s_hApp = DlgCreateDO_CreateEdit(hWnd, IDC_DO_APP);
         DlgCreateDO_CreateLabel(hWnd, "Value (hex):", IDC_DO_LBL_VALUE);
         s_hValue = DlgCreateDO_CreateEdit(hWnd, IDC_DO_VALUE);

         s_hToken = DlgCreateDO_CreateCheck(hWnd, "Token", IDC_DO_TOKEN);
         s_hPrivate = DlgCreateDO_CreateCheck(hWnd, "Private", IDC_DO_PRIVATE);
         s_hModifiable = DlgCreateDO_CreateCheck(hWnd, "Modifiable", IDC_DO_MODIFIABLE);
         SendMessageA(s_hToken, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hPrivate, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hModifiable, BM_SETCHECK, BST_CHECKED, 0);

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_DO_STATUS, NULL, NULL);

         CreateWindowA("BUTTON", "Create",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_DO_CREATE, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_DO_CLOSE, NULL, NULL);

         SendMessageA(s_hLabel, EM_SETLIMITTEXT, DLG_MAX_LABEL - 1, 0);
         SendMessageA(s_hApp, EM_SETLIMITTEXT, DLG_APP_MAX - 1, 0);
         SendMessageA(s_hValue, EM_SETLIMITTEXT, DLG_HEX_MAX - 1, 0);

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
      DlgCreateDO_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 420;
         pMin->ptMinTrackSize.y = 240;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_DO_CREATE:
      case IDOK:
         DlgCreateDO_DoCreate();
         return 0;
      case IDC_DO_CLOSE:
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
      s_hLabel = NULL;
      s_hApp = NULL;
      s_hValue = NULL;
      s_hToken = NULL;
      s_hPrivate = NULL;
      s_hModifiable = NULL;
      s_hStatus = NULL;
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }

   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

/*
    FUNCTION:        void DlgCreateDO_Show(HWND hwndParent)
*/
void DlgCreateDO_Show(HWND hwndParent)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      MessageBoxA(hwndParent, "Not logged in.", "Create data object", MB_OK | MB_ICONWARNING);
      return;
   }

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgCreateDO_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_DO_CLASS;
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_DO_CLASS, "Create data object",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 40, rc.top + 40, 480, 250,
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
