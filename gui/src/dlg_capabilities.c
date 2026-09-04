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

#define _DLG_CAPABILITIES_C

#ifdef OS_WIN32
#include <windows.h>
#include <commctrl.h>
#endif
#include <stdio.h>
#include <string.h>
#include "p11.h"
#include "p11util.h"
#include "p11query.h"
#include "gui.h"
#include "gui_theme.h"
#include "dlg_capabilities.h"

#define DLG_CAP_CLASS             "LunaKmuCapabilities"
#define DLG_MARGIN                10
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24

#define IDC_CAP_SLOT              2801
#define IDC_CAP_LIST              2802
#define IDC_CAP_STATUS            2803
#define IDC_CAP_REFRESH           2804
#define IDC_CAP_CLOSE             2805

static HWND s_hDlg = NULL;
static HWND s_hSlot = NULL;
static HWND s_hList = NULL;
static HWND s_hStatus = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static CK_SLOT_ID s_slotId = 0;
static char s_szLabel[P11_SLOT_LABEL_MAX + 1];

static void DlgCap_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static void DlgCap_Load(void)
{
   P11_CAP_ROW rows[P11_CAP_MAX_ROWS];
   CK_ULONG ulCount = 0;
   CK_ULONG ulLoop;
   CK_RV rv = CKR_GENERAL_ERROR;
   LVITEMA item;
   char szType[64];
   char szMin[32];
   char szMax[32];
   char szStatus[192];
   int iItem;

   if (s_hList == NULL)
   {
      return;
   }

   SendMessageA(s_hList, LVM_DELETEALLITEMS, 0, 0);
   DlgCap_SetStatus("Querying slot...");
   UpdateWindow(s_hStatus);

   memset(rows, 0, sizeof(rows));
   if (P11_QueryCapabilities(s_slotId, rows, P11_CAP_MAX_ROWS, &ulCount, &rv) != CK_TRUE)
   {
      memset(szStatus, 0, sizeof(szStatus));
      _snprintf(szStatus, sizeof(szStatus) - 1, "Invalid slot: %s",
         (const char*)P11Util_DisplayErrorName(rv));
      DlgCap_SetStatus(szStatus);
      return;
   }

   SendMessageA(s_hList, WM_SETREDRAW, FALSE, 0);
   for (ulLoop = 0; ulLoop < ulCount; ulLoop++)
   {
      memset(szType, 0, sizeof(szType));
      GUI_FormatKeyTypeCliName((const char*)rows[ulLoop].name, szType, sizeof(szType));
      if (szType[0] == 0)
      {
         strncpy(szType, (const char*)rows[ulLoop].name, sizeof(szType) - 1);
      }

      memset(&item, 0, sizeof(item));
      item.mask = LVIF_TEXT;
      item.iItem = (int)ulLoop;
      item.pszText = szType;
      iItem = (int)SendMessageA(s_hList, LVM_INSERTITEMA, 0, (LPARAM)&item);
      if (iItem < 0)
      {
         continue;
      }

      ListView_SetItemText(s_hList, iItem, 1,
         (LPSTR)((rows[ulLoop].bSupported == CK_TRUE) ? "Yes" : "No"));

      memset(szMin, 0, sizeof(szMin));
      memset(szMax, 0, sizeof(szMax));
      if ((rows[ulLoop].bSupported == CK_TRUE) && (rows[ulLoop].bNoKeySize != CK_TRUE))
      {
         _snprintf(szMin, sizeof(szMin) - 1, "%lu", (unsigned long)rows[ulLoop].ulMinKeySize);
         _snprintf(szMax, sizeof(szMax) - 1, "%lu", (unsigned long)rows[ulLoop].ulMaxKeySize);
      }
      ListView_SetItemText(s_hList, iItem, 2, szMin);
      ListView_SetItemText(s_hList, iItem, 3, szMax);
      ListView_SetItemText(s_hList, iItem, 4, (LPSTR)rows[ulLoop].note);
   }
   SendMessageA(s_hList, WM_SETREDRAW, TRUE, 0);
   InvalidateRect(s_hList, NULL, TRUE);

   memset(szStatus, 0, sizeof(szStatus));
   _snprintf(szStatus, sizeof(szStatus) - 1, "%lu key-generation mechanism(s).",
      (unsigned long)ulCount);
   DlgCap_SetStatus(szStatus);
}

static void DlgCap_Layout(int cx, int cy)
{
   int listH;
   int yBtn;

   if (cx < 400)
   {
      cx = 400;
   }
   if (cy < 240)
   {
      cy = 240;
   }

   yBtn = cy - DLG_MARGIN - DLG_BTN_H;
   listH = yBtn - DLG_MARGIN - 22 - 22 - DLG_MARGIN;
   if (listH < 80)
   {
      listH = 80;
   }

   MoveWindow(s_hSlot, DLG_MARGIN, DLG_MARGIN, cx - (2 * DLG_MARGIN), 18, TRUE);
   MoveWindow(s_hList, DLG_MARGIN, DLG_MARGIN + 22, cx - (2 * DLG_MARGIN), listH, TRUE);
   ListView_SetColumnWidth(s_hList, 4, cx - (2 * DLG_MARGIN) - 110 - 72 - 64 - 64 - 28);

   MoveWindow(s_hStatus, DLG_MARGIN, listH + DLG_MARGIN + 26, cx - (2 * DLG_MARGIN) - (2 * DLG_BTN_W) - 16, 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CAP_REFRESH),
      cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CAP_CLOSE),
      cx - DLG_MARGIN - DLG_BTN_W, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static LRESULT CALLBACK DlgCap_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      {
         HWND hCtrl;
         LVCOLUMNA col;
         char szSlot[96];

         s_hDlg = hWnd;
         s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

         memset(szSlot, 0, sizeof(szSlot));
         if (s_szLabel[0] != 0)
         {
            _snprintf(szSlot, sizeof(szSlot) - 1, "Slot %lu  %s",
               (unsigned long)s_slotId, s_szLabel);
         }
         else
         {
            _snprintf(szSlot, sizeof(szSlot) - 1, "Slot %lu",
               (unsigned long)s_slotId);
         }

         s_hSlot = CreateWindowA("STATIC", szSlot,
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_CAP_SLOT, NULL, NULL);

         s_hList = CreateWindowA(WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
            LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0, 0, 100, 100, hWnd, (HMENU)(INT_PTR)IDC_CAP_LIST, NULL, NULL);

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_CAP_STATUS, NULL, NULL);

         CreateWindowA("BUTTON", "Refresh",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CAP_REFRESH, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CAP_CLOSE, NULL, NULL);

         for (hCtrl = GetWindow(hWnd, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
         {
            SendMessageA(hCtrl, WM_SETFONT, (WPARAM)s_hFont, TRUE);
         }

         GUI_ThemeMarkStatus(s_hStatus);
         GUI_ThemeStyleList(s_hList);

         memset(&col, 0, sizeof(col));
         col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
         col.cx = 110;
         col.pszText = "Type";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
         col.cx = 72;
         col.iSubItem = 1;
         col.pszText = "Supported";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
         col.cx = 64;
         col.iSubItem = 2;
         col.pszText = "Min";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);
         col.cx = 64;
         col.iSubItem = 3;
         col.pszText = "Max";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);
         col.cx = 260;
         col.iSubItem = 4;
         col.pszText = "Notes";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 4, (LPARAM)&col);

         PostMessageA(hWnd, WM_COMMAND, MAKEWPARAM(IDC_CAP_REFRESH, BN_CLICKED), 0);
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
      DlgCap_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 560;
         pMin->ptMinTrackSize.y = 280;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_CAP_REFRESH:
         DlgCap_Load();
         return 0;
      case IDC_CAP_CLOSE:
      case IDOK:
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
      s_hSlot = NULL;
      s_hList = NULL;
      s_hStatus = NULL;
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }

   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

/*
    FUNCTION:        void DlgCapabilities_Show(...)
*/
void DlgCapabilities_Show(HWND hwndParent, CK_SLOT_ID slotId, const char* sLabel)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   if (GUI_IsLibraryLoaded() != CK_TRUE)
   {
      MessageBoxA(hwndParent, "PKCS#11 is not loaded.", "Get capabilities",
         MB_OK | MB_ICONWARNING);
      return;
   }

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgCap_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_CAP_CLASS;
   RegisterClassExA(&wc);

   s_slotId = slotId;
   memset(s_szLabel, 0, sizeof(s_szLabel));
   if (sLabel != NULL)
   {
      strncpy(s_szLabel, sLabel, sizeof(s_szLabel) - 1);
   }
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_CAP_CLASS,
      "Get capabilities",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 36, rc.top + 36, 720, 420,
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
