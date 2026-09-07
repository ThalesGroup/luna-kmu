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

#define _DLG_LISTKEYS_C

#ifdef OS_WIN32
#include <windows.h>
#include <commctrl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "p11util.h"
#include "p11query.h"
#include "gui.h"
#include "gui_theme.h"
#include "dlg_listkeys.h"
#include "dlg_attributes.h"
#include "dlg_digestkey.h"
#include "dlg_computekcv.h"
#include "dlg_crypt.h"
#include "dlg_sign.h"
#include "dlg_export.h"

#define DLG_LIST_CLASS            "LunaKmuListKeys"
#define DLG_MARGIN                10
#define DLG_BTN_W                 80
#define DLG_BTN_ATTR_W            88
#define DLG_BTN_DIG_W             72
#define DLG_BTN_KCV_W             56
#define DLG_BTN_LOAD_W            88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define IDC_LISTKEYS_LIST         2001
#define IDC_LISTKEYS_LIMIT        2002
#define IDC_LISTKEYS_REFRESH      2003
#define IDC_LISTKEYS_CLOSE        2004
#define IDC_LISTKEYS_STATUS       2005
#define IDC_LISTKEYS_LBL_LIMIT    2006
#define IDC_LISTKEYS_MORE         2007
#define IDC_LISTKEYS_DELETE       2008
#define IDC_LISTKEYS_ATTR         2009
#define IDC_LISTKEYS_DIGEST       2010
#define IDC_LISTKEYS_KCV          2011
#define IDC_LISTKEYS_USE          2012
#define IDM_LIST_ENCRYPT          2501
#define IDM_LIST_DECRYPT          2502
#define IDM_LIST_SIGN             2503
#define IDM_LIST_VERIFY           2504
#define IDM_LIST_EXPORT           2505

static HWND s_hDlg = NULL;
static HWND s_hList = NULL;
static HWND s_hLimit = NULL;
static HWND s_hMore = NULL;
static HWND s_hUse = NULL;
static HWND s_hStatus = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static BOOL s_bLoading = FALSE;
static CK_BBOOL s_bHasMore = CK_FALSE;
static CK_ULONG s_ulShown = 0;

static void DlgListKeys_UpdateMore(void);

static void DlgListKeys_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static int DlgListKeys_GetSelectedIndex(void)
{
   if (s_hList == NULL)
   {
      return -1;
   }
   return (int)SendMessageA(s_hList, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
}

static CK_OBJECT_HANDLE DlgListKeys_GetSelectedHandle(void)
{
   int iItem;
   LVITEMA item;

   iItem = DlgListKeys_GetSelectedIndex();
   if (iItem < 0)
   {
      return 0;
   }
   memset(&item, 0, sizeof(item));
   item.mask = LVIF_PARAM;
   item.iItem = iItem;
   if (SendMessageA(s_hList, LVM_GETITEMA, 0, (LPARAM)&item) == FALSE)
   {
      return 0;
   }
   return (CK_OBJECT_HANDLE)item.lParam;
}

static void DlgListKeys_EnableAction(int id, BOOL bEnable)
{
   HWND hCtrl;

   if (s_hDlg == NULL)
   {
      return;
   }
   hCtrl = GetDlgItem(s_hDlg, id);
   if (hCtrl != NULL)
   {
      EnableWindow(hCtrl, bEnable);
   }
}

static void DlgListKeys_UpdateActions(void)
{
   BOOL bEnable;

   bEnable = (s_bLoading == FALSE) && (DlgListKeys_GetSelectedIndex() >= 0) &&
      (P11_IsLoggedIn() == CK_TRUE);
   DlgListKeys_EnableAction(IDC_LISTKEYS_DELETE, bEnable);
   DlgListKeys_EnableAction(IDC_LISTKEYS_ATTR, bEnable);
   DlgListKeys_EnableAction(IDC_LISTKEYS_DIGEST, bEnable);
   DlgListKeys_EnableAction(IDC_LISTKEYS_KCV, bEnable);
   DlgListKeys_EnableAction(IDC_LISTKEYS_USE, bEnable);
   if (bEnable != FALSE)
   {
      CK_OBJECT_HANDLE hSel = DlgListKeys_GetSelectedHandle();
      if (hSel != 0)
      {
         GUI_SetLastObjectHandle(hSel);
      }
   }
}

static void DlgListKeys_PauseFind(void)
{
   P11_QueryObjectsClose();
   s_bHasMore = CK_FALSE;
   DlgListKeys_UpdateMore();
}

static CK_LONG DlgListKeys_GetLimit(void)
{
   char szLimit[32];
   char* pEnd = NULL;
   long lValue;

   memset(szLimit, 0, sizeof(szLimit));
   if (s_hLimit != NULL)
   {
      GetWindowTextA(s_hLimit, szLimit, sizeof(szLimit));
   }
   if (szLimit[0] == 0)
   {
      return CK_NULL_ELEMENT;
   }

   lValue = strtol(szLimit, &pEnd, 10);
   if ((pEnd == szLimit) || (*pEnd != 0) || (lValue <= 0))
   {
      return -2;
   }
   return (CK_LONG)lValue;
}

static void DlgListKeys_UpdateMore(void)
{
   if (s_hMore != NULL)
   {
      EnableWindow(s_hMore, (s_bLoading == FALSE) && (s_bHasMore == CK_TRUE));
   }
}

static void DlgListKeys_SetBusy(BOOL bBusy)
{
   s_bLoading = bBusy;
   if (s_hLimit != NULL)
   {
      EnableWindow(s_hLimit, (bBusy == FALSE));
   }
   EnableWindow(GetDlgItem(s_hDlg, IDC_LISTKEYS_REFRESH), (bBusy == FALSE));
   DlgListKeys_UpdateMore();
   DlgListKeys_UpdateActions();
}

static BOOL DlgListKeys_Pump(void)
{
   MSG msg;

   while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
   {
      if (msg.message == WM_QUIT)
      {
         s_bDone = TRUE;
         PostQuitMessage((int)msg.wParam);
         return FALSE;
      }
      if ((s_hDlg == NULL) || (IsDialogMessageA(s_hDlg, &msg) == FALSE))
      {
         TranslateMessage(&msg);
         DispatchMessageA(&msg);
      }
      if ((s_bDone != FALSE) || (s_hDlg == NULL))
      {
         return FALSE;
      }
   }
   return TRUE;
}

static void DlgListKeys_Append(const P11_OBJECT_ROW* rows, CK_ULONG ulCount)
{
   CK_ULONG ulLoop;
   LVITEMA item;
   char szHandle[32];
   char szClass[64];
   char szType[64];
   const char* pName;
   int iItem;

   if ((s_hList == NULL) || (rows == NULL) || (ulCount == 0))
   {
      return;
   }

   SendMessageA(s_hList, WM_SETREDRAW, FALSE, 0);
   for (ulLoop = 0; ulLoop < ulCount; ulLoop++)
   {
      memset(szHandle, 0, sizeof(szHandle));
      memset(szClass, 0, sizeof(szClass));
      memset(szType, 0, sizeof(szType));
      sprintf(szHandle, "%lu", (unsigned long)rows[ulLoop].handle);

      pName = (const char*)P11Util_DisplayClassName(rows[ulLoop].ckClass);
      if (pName != NULL)
      {
         strncpy(szClass, pName, sizeof(szClass) - 1);
      }
      if (rows[ulLoop].keyType != P11_KEY_TYPE_NONE)
      {
         GUI_FormatKeyTypeName(rows[ulLoop].keyType, szType, sizeof(szType));
      }

      iItem = (int)s_ulShown + (int)ulLoop;
      memset(&item, 0, sizeof(item));
      item.mask = LVIF_TEXT | LVIF_PARAM;
      item.iItem = iItem;
      item.pszText = szHandle;
      item.lParam = (LPARAM)rows[ulLoop].handle;
      SendMessageA(s_hList, LVM_INSERTITEMA, 0, (LPARAM)&item);
      ListView_SetItemText(s_hList, iItem, 1, szClass);
      ListView_SetItemText(s_hList, iItem, 2, szType);
      ListView_SetItemText(s_hList, iItem, 3, (LPSTR)rows[ulLoop].label);
   }
   SendMessageA(s_hList, WM_SETREDRAW, TRUE, 0);
   InvalidateRect(s_hList, NULL, TRUE);
   s_ulShown += ulCount;
}

static void DlgListKeys_ShowCount(void)
{
   char sz[96];

   memset(sz, 0, sizeof(sz));
   if (s_ulShown == 0)
   {
      DlgListKeys_SetStatus(s_bHasMore == CK_TRUE ? "No objects in this page." : "No objects found.");
      return;
   }
   if (s_bHasMore == CK_TRUE)
   {
      _snprintf(sz, sizeof(sz) - 1, "%lu object(s). Load more for the next page.", (unsigned long)s_ulShown);
   }
   else
   {
      _snprintf(sz, sizeof(sz) - 1, "%lu object(s).", (unsigned long)s_ulShown);
   }
   DlgListKeys_SetStatus(sz);
}

static CK_ULONG DlgListKeys_PageSize(CK_LONG lLimit)
{
   CK_ULONG ulPage;

   if ((lLimit != CK_NULL_ELEMENT) && (lLimit > 0))
   {
      ulPage = (CK_ULONG)lLimit;
   }
   else
   {
      ulPage = (CK_ULONG)P11_OBJECT_PAGE_DEFAULT;
   }
   if (ulPage > 256)
   {
      ulPage = 256;
   }
   return ulPage;
}

static CK_BBOOL DlgListKeys_NextPage(CK_ULONG ulPage)
{
   P11_OBJECT_ROW* pRows;
   CK_ULONG ulCount = 0;
   CK_BBOOL bHasMore = CK_FALSE;

   pRows = (P11_OBJECT_ROW*)calloc(ulPage, sizeof(P11_OBJECT_ROW));
   if (pRows == NULL)
   {
      DlgListKeys_SetStatus("Out of memory.");
      return CK_FALSE;
   }

   if (P11_QueryObjectsNext(pRows, ulPage, &ulCount, &bHasMore) != CK_TRUE)
   {
      free(pRows);
      DlgListKeys_SetStatus("Failed to list objects.");
      s_bHasMore = CK_FALSE;
      return CK_FALSE;
   }

   DlgListKeys_Append(pRows, ulCount);
   free(pRows);
   s_bHasMore = bHasMore;
   return CK_TRUE;
}

static void DlgListKeys_More(void)
{
   CK_LONG lLimit;
   CK_ULONG ulPage;

   if ((s_bLoading != FALSE) || (s_bHasMore != CK_TRUE))
   {
      return;
   }

   lLimit = DlgListKeys_GetLimit();
   if (lLimit == -2)
   {
      DlgListKeys_SetStatus("Limit must be a positive integer, or empty.");
      return;
   }

   ulPage = DlgListKeys_PageSize(lLimit);
   DlgListKeys_SetBusy(TRUE);
   DlgListKeys_SetStatus("Loading more...");
   if (DlgListKeys_NextPage(ulPage) == CK_TRUE)
   {
      DlgListKeys_ShowCount();
   }
   if (s_bHasMore != CK_TRUE)
   {
      P11_QueryObjectsClose();
   }
   DlgListKeys_SetBusy(FALSE);
}

static void DlgListKeys_Refresh(void)
{
   CK_LONG lLimit;
   CK_ULONG ulPage;
   CK_BBOOL bLoadAll;

   if (s_bLoading != FALSE)
   {
      return;
   }

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      DlgListKeys_SetStatus("Not logged in.");
      return;
   }

   lLimit = DlgListKeys_GetLimit();
   if (lLimit == -2)
   {
      DlgListKeys_SetStatus("Limit must be a positive integer, or empty.");
      return;
   }

   bLoadAll = (lLimit == CK_NULL_ELEMENT) ? CK_TRUE : CK_FALSE;
   ulPage = DlgListKeys_PageSize(lLimit);

   P11_QueryObjectsClose();
   if (s_hList != NULL)
   {
      SendMessageA(s_hList, LVM_DELETEALLITEMS, 0, 0);
   }
   s_ulShown = 0;
   s_bHasMore = CK_FALSE;

   if (P11_QueryObjectsOpen() != CK_TRUE)
   {
      DlgListKeys_SetStatus("Failed to list objects.");
      return;
   }

   DlgListKeys_SetBusy(TRUE);
   DlgListKeys_SetStatus("Loading objects...");

   if (bLoadAll == CK_TRUE)
   {
      do
      {
         if (DlgListKeys_NextPage(ulPage) != CK_TRUE)
         {
            break;
         }
         {
            char sz[80];
            memset(sz, 0, sizeof(sz));
            _snprintf(sz, sizeof(sz) - 1, "Loading... %lu object(s).", (unsigned long)s_ulShown);
            DlgListKeys_SetStatus(sz);
         }
         if (DlgListKeys_Pump() == FALSE)
         {
            P11_QueryObjectsClose();
            return;
         }
      } while (s_bHasMore == CK_TRUE);
   }
   else if (DlgListKeys_NextPage(ulPage) != CK_TRUE)
   {
      P11_QueryObjectsClose();
      DlgListKeys_SetBusy(FALSE);
      return;
   }

   if (s_bHasMore != CK_TRUE)
   {
      P11_QueryObjectsClose();
   }

   DlgListKeys_ShowCount();
   DlgListKeys_SetBusy(FALSE);
}

static void DlgListKeys_Delete(void)
{
   int iItem;
   CK_OBJECT_HANDLE hObj;
   char szHandle[32];
   char szClass[64];
   char szLabel[128];
   char szMsg[384];
   CK_RV rv = CKR_GENERAL_ERROR;

   if (s_bLoading != FALSE)
   {
      return;
   }
   iItem = DlgListKeys_GetSelectedIndex();
   hObj = DlgListKeys_GetSelectedHandle();
   if ((iItem < 0) || (hObj == 0))
   {
      DlgListKeys_SetStatus("Select an object to delete.");
      return;
   }

   memset(szHandle, 0, sizeof(szHandle));
   memset(szClass, 0, sizeof(szClass));
   memset(szLabel, 0, sizeof(szLabel));
   ListView_GetItemText(s_hList, iItem, 0, szHandle, (int)sizeof(szHandle));
   ListView_GetItemText(s_hList, iItem, 1, szClass, (int)sizeof(szClass));
   ListView_GetItemText(s_hList, iItem, 3, szLabel, (int)sizeof(szLabel));

   memset(szMsg, 0, sizeof(szMsg));
   _snprintf(szMsg, sizeof(szMsg) - 1,
      "Delete object handle %s?\n\nClass: %s\nLabel: %s\n\nThis cannot be undone.",
      szHandle,
      (szClass[0] != 0) ? szClass : "(unknown)",
      (szLabel[0] != 0) ? szLabel : "(none)");
   if (MessageBoxA(s_hDlg, szMsg, "Delete object",
      MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
   {
      return;
   }

   P11_QueryObjectsClose();
   if (P11_QueryDestroyObject(hObj, &rv) != CK_TRUE)
   {
      memset(szMsg, 0, sizeof(szMsg));
      _snprintf(szMsg, sizeof(szMsg) - 1, "Delete failed: %s",
         (const char*)P11Util_DisplayErrorName(rv));
      DlgListKeys_SetStatus(szMsg);
      MessageBoxA(s_hDlg, szMsg, "Delete object", MB_OK | MB_ICONERROR);
      return;
   }

   DlgListKeys_Refresh();
   memset(szMsg, 0, sizeof(szMsg));
   _snprintf(szMsg, sizeof(szMsg) - 1, "Deleted handle %s.", szHandle);
   DlgListKeys_SetStatus(szMsg);
}

static void DlgListKeys_Attributes(void)
{
   CK_OBJECT_HANDLE hObj;

   if (s_bLoading != FALSE)
   {
      return;
   }
   hObj = DlgListKeys_GetSelectedHandle();
   if (hObj == 0)
   {
      DlgListKeys_SetStatus("Select an object to view attributes.");
      return;
   }

   P11_QueryObjectsClose();
   DlgAttributes_Show(s_hDlg, hObj);
   DlgListKeys_Refresh();
}

static void DlgListKeys_Digest(void)
{
   CK_OBJECT_HANDLE hObj;

   if (s_bLoading != FALSE)
   {
      return;
   }
   hObj = DlgListKeys_GetSelectedHandle();
   if (hObj == 0)
   {
      DlgListKeys_SetStatus("Select a secret key to digest.");
      return;
   }

   DlgListKeys_PauseFind();
   DlgListKeys_ShowCount();
   DlgDigestKey_Show(s_hDlg, hObj);
}

static void DlgListKeys_ComputeKcv(void)
{
   CK_OBJECT_HANDLE hObj;

   if (s_bLoading != FALSE)
   {
      return;
   }
   hObj = DlgListKeys_GetSelectedHandle();
   if (hObj == 0)
   {
      DlgListKeys_SetStatus("Select a secret key to compute KCV.");
      return;
   }

   DlgListKeys_PauseFind();
   DlgListKeys_ShowCount();
   DlgComputeKcv_Show(s_hDlg, hObj);
}

static void DlgListKeys_ShowUse(void)
{
   HMENU hPop;
   RECT rc;
   UINT cmd;
   CK_OBJECT_HANDLE hObj;

   if (s_bLoading != FALSE)
   {
      return;
   }
   hObj = DlgListKeys_GetSelectedHandle();
   if (hObj == 0)
   {
      DlgListKeys_SetStatus("Select an object first.");
      return;
   }
   GUI_SetLastObjectHandle(hObj);

   hPop = CreatePopupMenu();
   if (hPop == NULL)
   {
      return;
   }
   AppendMenuA(hPop, MF_STRING, IDM_LIST_ENCRYPT, "&Encrypt...");
   AppendMenuA(hPop, MF_STRING, IDM_LIST_DECRYPT, "&Decrypt...");
   AppendMenuA(hPop, MF_SEPARATOR, 0, NULL);
   AppendMenuA(hPop, MF_STRING, IDM_LIST_SIGN, "&Sign...");
   AppendMenuA(hPop, MF_STRING, IDM_LIST_VERIFY, "&Verify...");
   AppendMenuA(hPop, MF_SEPARATOR, 0, NULL);
   AppendMenuA(hPop, MF_STRING, IDM_LIST_EXPORT, "E&xport...");
   if (s_hUse != NULL)
   {
      GetWindowRect(s_hUse, &rc);
   }
   else
   {
      GetWindowRect(s_hDlg, &rc);
   }
   cmd = (UINT)TrackPopupMenu(hPop,
      TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
      rc.left, rc.top, 0, s_hDlg, NULL);
   DestroyMenu(hPop);

   if (cmd == 0)
   {
      return;
   }

   DlgListKeys_PauseFind();
   DlgListKeys_ShowCount();
   if (cmd == IDM_LIST_ENCRYPT)
   {
      DlgCrypt_Show(s_hDlg, CK_FALSE);
   }
   else if (cmd == IDM_LIST_DECRYPT)
   {
      DlgCrypt_Show(s_hDlg, CK_TRUE);
   }
   else if (cmd == IDM_LIST_SIGN)
   {
      DlgSign_Show(s_hDlg, CK_FALSE);
   }
   else if (cmd == IDM_LIST_VERIFY)
   {
      DlgSign_Show(s_hDlg, CK_TRUE);
   }
   else if (cmd == IDM_LIST_EXPORT)
   {
      DlgExport_Show(s_hDlg);
   }
}

static void DlgListKeys_Layout(int cx, int cy)
{
   int listH;
   int yBtn;
   int xRight;

   if (cx < 360)
   {
      cx = 360;
   }
   if (cy < 220)
   {
      cy = 220;
   }

   yBtn = cy - DLG_MARGIN - DLG_BTN_H;
   listH = yBtn - DLG_MARGIN - 22 - DLG_MARGIN - DLG_MARGIN;
   if (listH < 80)
   {
      listH = 80;
   }

   MoveWindow(s_hList, DLG_MARGIN, DLG_MARGIN, cx - (2 * DLG_MARGIN), listH, TRUE);
   ListView_SetColumnWidth(s_hList, 3, cx - (2 * DLG_MARGIN) - 72 - 100 - 100 - 28);

   MoveWindow(s_hStatus, DLG_MARGIN, listH + DLG_MARGIN + 4, cx - (2 * DLG_MARGIN), 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_LISTKEYS_LBL_LIMIT), DLG_MARGIN, yBtn + 4, 36, 16, TRUE);
   MoveWindow(s_hLimit, DLG_MARGIN + 38, yBtn, 48, DLG_EDIT_H, TRUE);
   MoveWindow(s_hMore, DLG_MARGIN + 92, yBtn, DLG_BTN_LOAD_W, DLG_BTN_H, TRUE);

   xRight = cx - DLG_MARGIN - DLG_BTN_W;
   MoveWindow(GetDlgItem(s_hDlg, IDC_LISTKEYS_CLOSE), xRight, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   xRight -= DLG_BTN_W + 8;
   MoveWindow(GetDlgItem(s_hDlg, IDC_LISTKEYS_REFRESH), xRight, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   xRight -= DLG_BTN_W + 8;
   MoveWindow(GetDlgItem(s_hDlg, IDC_LISTKEYS_DELETE), xRight, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   xRight -= DLG_BTN_ATTR_W + 8;
   MoveWindow(GetDlgItem(s_hDlg, IDC_LISTKEYS_ATTR), xRight, yBtn, DLG_BTN_ATTR_W, DLG_BTN_H, TRUE);
   xRight -= DLG_BTN_KCV_W + 8;
   MoveWindow(GetDlgItem(s_hDlg, IDC_LISTKEYS_KCV), xRight, yBtn, DLG_BTN_KCV_W, DLG_BTN_H, TRUE);
   xRight -= DLG_BTN_DIG_W + 8;
   MoveWindow(GetDlgItem(s_hDlg, IDC_LISTKEYS_DIGEST), xRight, yBtn, DLG_BTN_DIG_W, DLG_BTN_H, TRUE);
   xRight -= DLG_BTN_W + 8;
   MoveWindow(s_hUse, xRight, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static LRESULT CALLBACK DlgListKeys_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      {
         LVCOLUMNA col;
         HWND hCtrl;

         s_hDlg = hWnd;
         s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

         s_hList = CreateWindowA(WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
            LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0, 0, 100, 100, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_LIST, NULL, NULL);

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 100, 18, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_STATUS, NULL, NULL);

         CreateWindowA("STATIC", "Limit:",
            WS_CHILD | WS_VISIBLE,
            0, 0, 36, 16, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_LBL_LIMIT, NULL, NULL);

         s_hLimit = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL,
            0, 0, 48, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_LIMIT, NULL, NULL);
         SetWindowTextA(s_hLimit, "50");

         s_hMore = CreateWindowA("BUTTON", "Load more",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_LOAD_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_MORE, NULL, NULL);
         EnableWindow(s_hMore, FALSE);

         s_hUse = CreateWindowA("BUTTON", "Use",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_USE, NULL, NULL);
         EnableWindow(s_hUse, FALSE);

         CreateWindowA("BUTTON", "Digest",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_DIG_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_DIGEST, NULL, NULL);
         EnableWindow(GetDlgItem(hWnd, IDC_LISTKEYS_DIGEST), FALSE);

         CreateWindowA("BUTTON", "KCV",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_KCV_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_KCV, NULL, NULL);
         EnableWindow(GetDlgItem(hWnd, IDC_LISTKEYS_KCV), FALSE);

         CreateWindowA("BUTTON", "Attributes",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_ATTR_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_ATTR, NULL, NULL);
         EnableWindow(GetDlgItem(hWnd, IDC_LISTKEYS_ATTR), FALSE);

         CreateWindowA("BUTTON", "Delete",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_DELETE, NULL, NULL);
         EnableWindow(GetDlgItem(hWnd, IDC_LISTKEYS_DELETE), FALSE);

         CreateWindowA("BUTTON", "Refresh",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_REFRESH, NULL, NULL);

         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_LISTKEYS_CLOSE, NULL, NULL);

         for (hCtrl = GetWindow(hWnd, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
         {
            SendMessageA(hCtrl, WM_SETFONT, (WPARAM)s_hFont, TRUE);
         }

         GUI_ThemeMarkStatus(s_hStatus);
         GUI_ThemeStyleList(s_hList);
         memset(&col, 0, sizeof(col));
         col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
         col.cx = 72;
         col.pszText = "Handle";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
         col.cx = 100;
         col.iSubItem = 1;
         col.pszText = "Class";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
         col.cx = 100;
         col.iSubItem = 2;
         col.pszText = "Type";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);
         col.cx = 180;
         col.iSubItem = 3;
         col.pszText = "Label";
         SendMessageA(s_hList, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);

         PostMessageA(hWnd, WM_COMMAND, MAKEWPARAM(IDC_LISTKEYS_REFRESH, BN_CLICKED), 0);
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
      DlgListKeys_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 920;
         pMin->ptMinTrackSize.y = 280;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_LISTKEYS_REFRESH:
      case IDOK:
         DlgListKeys_Refresh();
         return 0;
      case IDC_LISTKEYS_MORE:
         DlgListKeys_More();
         return 0;
      case IDC_LISTKEYS_USE:
         DlgListKeys_ShowUse();
         return 0;
      case IDC_LISTKEYS_DELETE:
         DlgListKeys_Delete();
         return 0;
      case IDC_LISTKEYS_ATTR:
         DlgListKeys_Attributes();
         return 0;
      case IDC_LISTKEYS_DIGEST:
         DlgListKeys_Digest();
         return 0;
      case IDC_LISTKEYS_KCV:
         DlgListKeys_ComputeKcv();
         return 0;
      case IDC_LISTKEYS_CLOSE:
      case IDCANCEL:
         DestroyWindow(hWnd);
         return 0;
      default:
         break;
      }
      break;

   case WM_NOTIFY:
      if (((LPNMHDR)lParam)->idFrom == IDC_LISTKEYS_LIST)
      {
         if (((LPNMHDR)lParam)->code == LVN_ITEMCHANGED)
         {
            DlgListKeys_UpdateActions();
            return 0;
         }
         if (((LPNMHDR)lParam)->code == NM_DBLCLK)
         {
            DlgListKeys_Attributes();
            return 0;
         }
         if (((LPNMHDR)lParam)->code == LVN_KEYDOWN)
         {
            if (((LPNMLVKEYDOWN)lParam)->wVKey == VK_DELETE)
            {
               DlgListKeys_Delete();
               return 0;
            }
         }
      }
      break;

   case WM_CLOSE:
      DestroyWindow(hWnd);
      return 0;

   case WM_DESTROY:
      P11_QueryObjectsClose();
      s_hDlg = NULL;
      s_hList = NULL;
      s_hLimit = NULL;
      s_hMore = NULL;
      s_hUse = NULL;
      s_hStatus = NULL;
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }

   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

/*
    FUNCTION:        void DlgListKeys_Show(HWND hwndParent)
*/
void DlgListKeys_Show(HWND hwndParent)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgListKeys_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_LIST_CLASS;
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_LIST_CLASS, "List objects",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 40, rc.top + 40, 960, 380,
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
