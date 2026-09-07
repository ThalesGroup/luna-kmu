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

#define _DLG_CONVERT_C

#ifdef OS_WIN32
#include <windows.h>
#include <commdlg.h>
#endif
#include <stdio.h>
#include <string.h>
#include "p11.h"
#include "p11query.h"
#include "gui.h"
#include "gui_theme.h"
#include "dlg_convert.h"

#define DLG_CONV_CLASS            "LunaKmuConvert"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               90
#define DLG_BROWSE_W              80

#define IDC_CONV_IN               2901
#define IDC_CONV_IN_BROWSE        2902
#define IDC_CONV_IN_FMT           2903
#define IDC_CONV_OUT              2904
#define IDC_CONV_OUT_BROWSE       2905
#define IDC_CONV_OUT_FMT          2906
#define IDC_CONV_GO               2907
#define IDC_CONV_CLOSE            2908
#define IDC_CONV_STATUS           2909

static HWND s_hDlg = NULL;
static HWND s_hIn = NULL;
static HWND s_hInFmt = NULL;
static HWND s_hOut = NULL;
static HWND s_hOutFmt = NULL;
static HWND s_hStatus = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;

static void DlgConv_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static void DlgConv_AddFmt(HWND hCombo, const char* sName, CK_BYTE fmt)
{
   int iItem = (int)SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)sName);
   if (iItem >= 0)
   {
      SendMessageA(hCombo, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)fmt);
   }
}

static CK_BYTE DlgConv_Fmt(HWND hCombo)
{
   int iSel = (int)SendMessageA(hCombo, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel < 0)
   {
      return P11_FILE_FORMAT_TEXT;
   }
   data = SendMessageA(hCombo, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if (data == CB_ERR)
   {
      return P11_FILE_FORMAT_TEXT;
   }
   return (CK_BYTE)data;
}

static BOOL DlgConv_PickFile(BOOL bSave, char* szPath, unsigned int pathSize)
{
   OPENFILENAMEA ofn;

   if ((szPath == NULL) || (pathSize < 8))
   {
      return FALSE;
   }
   memset(szPath, 0, pathSize);
   GetWindowTextA(bSave ? s_hOut : s_hIn, szPath, (int)pathSize);

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

static void DlgConv_DoConvert(void)
{
   char szIn[GUI_PATH_MAX];
   char szOut[GUI_PATH_MAX];
   char szErr[P11_QUERY_ERR_MAX];
   char szStatus[GUI_STATUS_TEXT_MAX];
   CK_BYTE inFmt;
   CK_BYTE outFmt;
   CK_ULONG uWritten = 0;

   memset(szIn, 0, sizeof(szIn));
   memset(szOut, 0, sizeof(szOut));
   GetWindowTextA(s_hIn, szIn, sizeof(szIn));
   GetWindowTextA(s_hOut, szOut, sizeof(szOut));
   inFmt = DlgConv_Fmt(s_hInFmt);
   outFmt = DlgConv_Fmt(s_hOutFmt);

   if (P11_QueryConvertFile(szIn, inFmt, szOut, outFmt, &uWritten, szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgConv_SetStatus(szErr[0] != 0 ? szErr : "Convert failed.");
      return;
   }
   memset(szStatus, 0, sizeof(szStatus));
   _snprintf(szStatus, sizeof(szStatus) - 1, "%lu bytes written to %s",
      (unsigned long)uWritten, szOut);
   DlgConv_SetStatus(szStatus);
}

static void DlgConv_Layout(int cx, int cy)
{
   int y;
   int editW;
   int browseX;
   int fmtX;
   int fmtW = 90;

   if (cx < 360)
   {
      cx = 360;
   }
   y = DLG_MARGIN;
   browseX = cx - DLG_MARGIN - DLG_BROWSE_W;
   fmtX = browseX - 8 - fmtW;
   editW = fmtX - DLG_MARGIN - DLG_LABEL_W - 16;
   if (editW < 80)
   {
      editW = 80;
   }

   MoveWindow(GetDlgItem(s_hDlg, 2910), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hIn, DLG_MARGIN + DLG_LABEL_W + 8, y, editW, DLG_EDIT_H, TRUE);
   MoveWindow(s_hInFmt, fmtX, y, fmtW, 200, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CONV_IN_BROWSE), browseX, y, DLG_BROWSE_W, DLG_BTN_H, TRUE);

   y += DLG_EDIT_H + 10;
   MoveWindow(GetDlgItem(s_hDlg, 2911), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hOut, DLG_MARGIN + DLG_LABEL_W + 8, y, editW, DLG_EDIT_H, TRUE);
   MoveWindow(s_hOutFmt, fmtX, y, fmtW, 200, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CONV_OUT_BROWSE), browseX, y, DLG_BROWSE_W, DLG_BTN_H, TRUE);

   y = cy - DLG_MARGIN - DLG_BTN_H;
   MoveWindow(s_hStatus, DLG_MARGIN, y - 26, cx - (2 * DLG_MARGIN), 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CONV_GO), cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, y, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_CONV_CLOSE), cx - DLG_MARGIN - DLG_BTN_W, y, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static LRESULT CALLBACK DlgConv_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      {
         HWND hCtrl;

         s_hDlg = hWnd;
         s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

         CreateWindowA("STATIC", "Input:", WS_CHILD | WS_VISIBLE,
            0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)2910, NULL, NULL);
         s_hIn = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_CONV_IN, NULL, NULL);
         s_hInFmt = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 90, 200, hWnd, (HMENU)(INT_PTR)IDC_CONV_IN_FMT, NULL, NULL);
         CreateWindowA("BUTTON", "Browse...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BROWSE_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CONV_IN_BROWSE, NULL, NULL);

         CreateWindowA("STATIC", "Output:", WS_CHILD | WS_VISIBLE,
            0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)2911, NULL, NULL);
         s_hOut = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_CONV_OUT, NULL, NULL);
         s_hOutFmt = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 90, 200, hWnd, (HMENU)(INT_PTR)IDC_CONV_OUT_FMT, NULL, NULL);
         CreateWindowA("BUTTON", "Browse...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BROWSE_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CONV_OUT_BROWSE, NULL, NULL);

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_CONV_STATUS, NULL, NULL);
         CreateWindowA("BUTTON", "Convert",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CONV_GO, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_CONV_CLOSE, NULL, NULL);

         DlgConv_AddFmt(s_hInFmt, "text", P11_FILE_FORMAT_TEXT);
         DlgConv_AddFmt(s_hInFmt, "bin", P11_FILE_FORMAT_BINARY);
         DlgConv_AddFmt(s_hOutFmt, "text", P11_FILE_FORMAT_TEXT);
         DlgConv_AddFmt(s_hOutFmt, "bin", P11_FILE_FORMAT_BINARY);
         SendMessageA(s_hInFmt, CB_SETCURSEL, 0, 0);
         SendMessageA(s_hOutFmt, CB_SETCURSEL, 1, 0);
         SendMessageA(s_hIn, EM_SETLIMITTEXT, GUI_PATH_MAX - 1, 0);
         SendMessageA(s_hOut, EM_SETLIMITTEXT, GUI_PATH_MAX - 1, 0);

         for (hCtrl = GetWindow(hWnd, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
         {
            SendMessageA(hCtrl, WM_SETFONT, (WPARAM)s_hFont, TRUE);
         }
         GUI_ThemeMarkStatus(s_hStatus);
         DlgConv_SetStatus("Converts hex text to binary, or binary to hex text. No slot login required.");
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
      DlgConv_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 520;
         pMin->ptMinTrackSize.y = 200;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_CONV_IN_BROWSE:
         {
            char szPath[GUI_PATH_MAX];
            if (DlgConv_PickFile(FALSE, szPath, sizeof(szPath)) != FALSE)
            {
               SetWindowTextA(s_hIn, szPath);
            }
         }
         return 0;
      case IDC_CONV_OUT_BROWSE:
         {
            char szPath[GUI_PATH_MAX];
            if (DlgConv_PickFile(TRUE, szPath, sizeof(szPath)) != FALSE)
            {
               SetWindowTextA(s_hOut, szPath);
            }
         }
         return 0;
      case IDC_CONV_GO:
      case IDOK:
         DlgConv_DoConvert();
         return 0;
      case IDC_CONV_CLOSE:
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
      s_hIn = NULL;
      s_hInFmt = NULL;
      s_hOut = NULL;
      s_hOutFmt = NULL;
      s_hStatus = NULL;
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }
   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

void DlgConvert_Show(HWND hwndParent)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgConv_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_CONV_CLASS;
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_CONV_CLASS,
      "Convert file",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 36, rc.top + 36, 560, 210,
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
