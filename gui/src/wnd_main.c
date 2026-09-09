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

#define _WND_MAIN_C

#ifdef OS_WIN32
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "p11.h"
#include "p11util.h"
#include "gui.h"
#include "gui_theme.h"
#include "wnd_main.h"
#include "dlg_listkeys.h"
#include "dlg_generate.h"
#include "dlg_createdo.h"
#include "dlg_capabilities.h"
#include "dlg_import.h"
#include "dlg_export.h"
#include "dlg_convert.h"
#include "dlg_crypt.h"
#include "dlg_sign.h"
#include "dlg_derive.h"
#include "dlg_mzmk.h"
#include "resource.h"

#define GUI_MAX_SLOTS             128
#define GUI_MARGIN                12
#define GUI_BTN_W                 88
#define GUI_ACTION_BTN_W          108
#define GUI_CREATEDO_BTN_W        132
#define GUI_IO_BTN_W              80
#define GUI_MORE_BTN_W            72
#define GUI_BTN_H                 26
#define GUI_EDIT_H                24
#define GUI_STATUS_H              22
#define GUI_COL_SLOT_W            64
#define GUI_COL_MODEL_W           130
#define GUI_COL_FW_W              80
#define GUI_COL_SW_W              80
#define GUI_COL_SERIAL_W          130
#define GUI_PATH_LABEL_H          18

static HWND      s_hWnd = NULL;
static HWND      s_hLblPath = NULL;
static HWND      s_hPath = NULL;
static HWND      s_hBrowse = NULL;
static HWND      s_hList = NULL;
static HWND      s_hRefresh = NULL;
static HWND      s_hLblPassword = NULL;
static HWND      s_hPassword = NULL;
static HWND      s_hCryptoUser = NULL;
static HWND      s_hLogin = NULL;
static HWND      s_hLogout = NULL;
static HWND      s_hListKeys = NULL;
static HWND      s_hGenerate = NULL;
static HWND      s_hCreateDO = NULL;
static HWND      s_hImport = NULL;
static HWND      s_hExport = NULL;
static HWND      s_hMore = NULL;
static HWND      s_hStatus = NULL;
static HFONT     s_hFont = NULL;
static CK_BBOOL  s_bHasSelection = CK_FALSE;
static CK_SLOT_ID s_selectedSlot = 0;
static char      s_selectedLabel[P11_SLOT_LABEL_MAX + 1];
static CK_BBOOL  s_bLoggedInAsCu = CK_FALSE;
static P11_SLOT_ROW s_slotRows[GUI_MAX_SLOTS];
static CK_ULONG  s_slotCount = 0;
static char      s_szLastRefreshPath[GUI_PATH_MAX];

static void WndMain_RefreshSlots(void);
static void WndMain_Layout(int cx, int cy);

static void WndMain_Relayout(void)
{
   RECT rc;

   if (s_hWnd == NULL)
   {
      return;
   }
   GetClientRect(s_hWnd, &rc);
   WndMain_Layout(rc.right - rc.left, rc.bottom - rc.top);
}

static void WndMain_SetStatus(const char* sFormat, ...)
{
   char szText[GUI_STATUS_TEXT_MAX];
   va_list args;

   if (s_hStatus == NULL)
   {
      return;
   }

   memset(szText, 0, sizeof(szText));
   va_start(args, sFormat);
   _vsnprintf(szText, sizeof(szText) - 1, sFormat, args);
   va_end(args);
   SetWindowTextA(s_hStatus, szText);
}

static void WndMain_ApplyFont(HWND hCtrl)
{
   if ((s_hFont != NULL) && (hCtrl != NULL))
   {
      SendMessageA(hCtrl, WM_SETFONT, (WPARAM)s_hFont, TRUE);
   }
}

static void WndMain_UpdateTitle(void)
{
   char szTitle[256];

   if (s_hWnd == NULL)
   {
      return;
   }

   memset(szTitle, 0, sizeof(szTitle));
   if ((P11_IsLoggedIn() == CK_TRUE) && (s_bHasSelection == CK_TRUE))
   {
      _snprintf(szTitle, sizeof(szTitle) - 1, "%s - %s on slot %lu",
         GUI_APP_TITLE,
         (s_bLoggedInAsCu == CK_TRUE) ? "Crypto User" : "Crypto Officer",
         (unsigned long)s_selectedSlot);
   }
   else
   {
      strncpy(szTitle, GUI_APP_TITLE, sizeof(szTitle) - 1);
   }
   SetWindowTextA(s_hWnd, szTitle);
}

static CK_BBOOL WndMain_SlotNeedsPassword(CK_SLOT_ID slotId)
{
   CK_ULONG ulLoop;

   for (ulLoop = 0; ulLoop < s_slotCount; ulLoop++)
   {
      if (s_slotRows[ulLoop].slotId == slotId)
      {
         return s_slotRows[ulLoop].bPasswordRequired;
      }
   }
   return CK_TRUE;
}

static void WndMain_UpdateCapMenu(void)
{
   HMENU hMenu;
   UINT uFlags;

   if (s_hWnd == NULL)
   {
      return;
   }
   hMenu = GetMenu(s_hWnd);
   if (hMenu == NULL)
   {
      return;
   }

   uFlags = MF_BYCOMMAND | MF_GRAYED;
   if ((GUI_IsLibraryLoaded() == CK_TRUE) &&
      (GUI_IsLoadInProgress() != CK_TRUE) &&
      (s_bHasSelection == CK_TRUE))
   {
      uFlags = MF_BYCOMMAND | MF_ENABLED;
   }
   EnableMenuItem(hMenu, IDM_FILE_CAPABILITIES, uFlags);
}

static void WndMain_UpdateButtons(void)
{
   CK_BBOOL bLoggedIn = CK_FALSE;
   CK_BBOOL bLib = GUI_IsLibraryLoaded();
   CK_BBOOL bBusy = GUI_IsLoadInProgress();
   BOOL bCanLogin;

   if (bBusy == CK_TRUE)
   {
      EnableWindow(s_hList, FALSE);
      EnableWindow(s_hLogin, FALSE);
      EnableWindow(s_hLogout, FALSE);
      EnableWindow(s_hListKeys, FALSE);
      EnableWindow(s_hGenerate, FALSE);
      EnableWindow(s_hCreateDO, FALSE);
      EnableWindow(s_hImport, FALSE);
      EnableWindow(s_hExport, FALSE);
      EnableWindow(s_hMore, FALSE);
      EnableWindow(s_hPassword, FALSE);
      EnableWindow(s_hCryptoUser, FALSE);
      EnableWindow(s_hPath, FALSE);
      EnableWindow(s_hBrowse, FALSE);
      EnableWindow(s_hRefresh, FALSE);
      WndMain_UpdateCapMenu();
      return;
   }

   bLoggedIn = P11_IsLoggedIn();
   bCanLogin = ((bLib == CK_TRUE) && (bLoggedIn == CK_FALSE) && (s_bHasSelection == CK_TRUE));

   EnableWindow(s_hList, (bLoggedIn == CK_FALSE));
   EnableWindow(s_hLogin, bCanLogin);
   EnableWindow(s_hLogout, (bLoggedIn == CK_TRUE));
   EnableWindow(s_hListKeys, (bLoggedIn == CK_TRUE));
   EnableWindow(s_hGenerate, (bLoggedIn == CK_TRUE));
   EnableWindow(s_hCreateDO, (bLoggedIn == CK_TRUE));
   EnableWindow(s_hImport, (bLoggedIn == CK_TRUE));
   EnableWindow(s_hExport, (bLoggedIn == CK_TRUE));
   EnableWindow(s_hMore, (bLoggedIn == CK_TRUE));
   EnableWindow(s_hPassword, (bLoggedIn == CK_FALSE) && (bLib == CK_TRUE));
   EnableWindow(s_hCryptoUser, (bLoggedIn == CK_FALSE) && (bLib == CK_TRUE));
   EnableWindow(s_hPath, (bLoggedIn == CK_FALSE));
   EnableWindow(s_hBrowse, (bLoggedIn == CK_FALSE));
   EnableWindow(s_hRefresh, TRUE);

   ShowWindow(s_hLogin, (bLoggedIn == CK_TRUE) ? SW_HIDE : SW_SHOW);
   ShowWindow(s_hLogout, (bLoggedIn == CK_TRUE) ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hLblPassword, (bLoggedIn == CK_TRUE) ? SW_HIDE : SW_SHOW);
   ShowWindow(s_hPassword, (bLoggedIn == CK_TRUE) ? SW_HIDE : SW_SHOW);
   ShowWindow(s_hCryptoUser, (bLoggedIn == CK_TRUE) ? SW_HIDE : SW_SHOW);
   ShowWindow(s_hListKeys, (bLoggedIn == CK_TRUE) ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hGenerate, (bLoggedIn == CK_TRUE) ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hCreateDO, (bLoggedIn == CK_TRUE) ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hImport, (bLoggedIn == CK_TRUE) ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hExport, (bLoggedIn == CK_TRUE) ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hMore, (bLoggedIn == CK_TRUE) ? SW_SHOW : SW_HIDE);

   WndMain_UpdateTitle();
   WndMain_Relayout();
   WndMain_UpdateCapMenu();
}

static void WndMain_GetClientPath(char* buffer, unsigned int bufferSize)
{
   if ((buffer == NULL) || (bufferSize == 0) || (s_hPath == NULL))
   {
      return;
   }
   memset(buffer, 0, bufferSize);
   GetWindowTextA(s_hPath, buffer, (int)bufferSize);
}

static void WndMain_PrefillClientPath(void)
{
   char szPath[GUI_PATH_MAX];

   memset(szPath, 0, sizeof(szPath));
   GUI_SuggestDefaultChrystokiPath(szPath, sizeof(szPath));
   if (s_hPath != NULL)
   {
      SetWindowTextA(s_hPath, szPath);
   }
}

static CK_BBOOL WndMain_PathChangedSinceRefresh(void)
{
   char szPath[GUI_PATH_MAX];

   memset(szPath, 0, sizeof(szPath));
   WndMain_GetClientPath(szPath, sizeof(szPath));
   if (lstrcmpiA(szPath, s_szLastRefreshPath) == 0)
   {
      return CK_FALSE;
   }
   return CK_TRUE;
}

static void WndMain_RememberRefreshPath(void)
{
   memset(s_szLastRefreshPath, 0, sizeof(s_szLastRefreshPath));
   WndMain_GetClientPath(s_szLastRefreshPath, sizeof(s_szLastRefreshPath));
}

static void WndMain_OnPathFinished(void)
{
   if ((P11_IsLoggedIn() == CK_TRUE) || (GUI_IsLoadInProgress() == CK_TRUE))
   {
      return;
   }
   if (WndMain_PathChangedSinceRefresh() != CK_TRUE)
   {
      return;
   }
   WndMain_RefreshSlots();
}

static int CALLBACK WndMain_BrowseCallback(HWND hWnd, UINT uMsg, LPARAM lParam, LPARAM lpData)
{
   (void)lParam;
   if ((uMsg == BFFM_INITIALIZED) && (lpData != 0))
   {
      SendMessageA(hWnd, BFFM_SETSELECTIONA, TRUE, lpData);
   }
   return 0;
}

static CK_BBOOL WndMain_BrowseClientPath(void)
{
   BROWSEINFOA bi;
   LPITEMIDLIST pidl;
   char szDisplay[MAX_PATH];
   char szPath[MAX_PATH];
   char szCurrent[GUI_PATH_MAX];
   CK_BBOOL bPicked = CK_FALSE;

   memset(&bi, 0, sizeof(bi));
   memset(szDisplay, 0, sizeof(szDisplay));
   memset(szPath, 0, sizeof(szPath));
   memset(szCurrent, 0, sizeof(szCurrent));
   WndMain_GetClientPath(szCurrent, sizeof(szCurrent));

   bi.hwndOwner = s_hWnd;
   bi.pszDisplayName = szDisplay;
   bi.lpszTitle = "Select the ChrystokiConfigurationPath folder";
   bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_NONEWFOLDERBUTTON;
   bi.lpfn = WndMain_BrowseCallback;
   if (szCurrent[0] != 0)
   {
      bi.lParam = (LPARAM)szCurrent;
   }

   pidl = SHBrowseForFolderA(&bi);
   if (pidl == NULL)
   {
      return CK_FALSE;
   }

   if (SHGetPathFromIDListA(pidl, szPath) != FALSE)
   {
      SetWindowTextA(s_hPath, szPath);
      bPicked = CK_TRUE;
   }
   CoTaskMemFree(pidl);
   return bPicked;
}

static CK_BBOOL WndMain_ApplyClientPath(void)
{
   char szPath[GUI_PATH_MAX];

   memset(szPath, 0, sizeof(szPath));
   WndMain_GetClientPath(szPath, sizeof(szPath));
   if (szPath[0] == 0)
   {
      WndMain_SetStatus("Set ChrystokiConfigurationPath (paste or Browse). Slots refresh when you leave the field.");
      return CK_FALSE;
   }

   if (GUI_SetChrystokiPath(szPath) != CK_TRUE)
   {
      WndMain_SetStatus("Set ChrystokiConfigurationPath (paste or Browse). Slots refresh when you leave the field.");
      return CK_FALSE;
   }

   return CK_TRUE;
}

static CK_BBOOL WndMain_GetSelectedSlot(CK_SLOT_ID* pSlotId, char* sLabel, unsigned int uLabelSize)
{
   int iSel;
   LVITEMA item;

   if (pSlotId == NULL)
   {
      return CK_FALSE;
   }

   iSel = ListView_GetNextItem(s_hList, -1, LVNI_SELECTED);
   if (iSel < 0)
   {
      s_bHasSelection = CK_FALSE;
      return CK_FALSE;
   }

   memset(&item, 0, sizeof(item));
   item.mask = LVIF_PARAM;
   item.iItem = iSel;
   if (SendMessageA(s_hList, LVM_GETITEMA, 0, (LPARAM)&item) == FALSE)
   {
      s_bHasSelection = CK_FALSE;
      return CK_FALSE;
   }

   *pSlotId = (CK_SLOT_ID)item.lParam;
   s_bHasSelection = CK_TRUE;
   s_selectedSlot = *pSlotId;

   if ((sLabel != NULL) && (uLabelSize > 0))
   {
      memset(sLabel, 0, uLabelSize);
      ListView_GetItemText(s_hList, iSel, 1, sLabel, (int)uLabelSize);
      strncpy(s_selectedLabel, sLabel, sizeof(s_selectedLabel) - 1);
   }

   return CK_TRUE;
}

static void WndMain_SelectSlotId(CK_SLOT_ID slotId)
{
   int iCount;
   int iLoop;
   LVITEMA item;

   iCount = ListView_GetItemCount(s_hList);
   for (iLoop = 0; iLoop < iCount; iLoop++)
   {
      memset(&item, 0, sizeof(item));
      item.mask = LVIF_PARAM;
      item.iItem = iLoop;
      if (SendMessageA(s_hList, LVM_GETITEMA, 0, (LPARAM)&item) == FALSE)
      {
         continue;
      }
      if ((CK_SLOT_ID)item.lParam == slotId)
      {
         ListView_SetItemState(s_hList, iLoop, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
         return;
      }
   }

   if (iCount > 0)
   {
      ListView_SetItemState(s_hList, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
   }
}

static void WndMain_OnSlotSelected(void)
{
   if (WndMain_GetSelectedSlot(&s_selectedSlot, s_selectedLabel, sizeof(s_selectedLabel)) != CK_TRUE)
   {
      WndMain_UpdateButtons();
      return;
   }

   WndMain_UpdateButtons();

   if ((P11_IsLoggedIn() == CK_TRUE) || (GUI_IsLoadInProgress() == CK_TRUE))
   {
      return;
   }

   if (WndMain_SlotNeedsPassword(s_selectedSlot) != CK_TRUE)
   {
      WndMain_SetStatus("Selected slot %lu (%s). This token uses a PED; leave the password empty or type a PIN to force password login.",
         (unsigned long)s_selectedSlot,
         s_selectedLabel);
   }
   else
   {
      WndMain_SetStatus("Selected slot %lu (%s).",
         (unsigned long)s_selectedSlot,
         s_selectedLabel);
   }
}

static void WndMain_ClearSlots(void)
{
   SendMessageA(s_hList, LVM_DELETEALLITEMS, 0, 0);
   s_bHasSelection = CK_FALSE;
   s_slotCount = 0;
   memset(s_slotRows, 0, sizeof(s_slotRows));
}

static void WndMain_FillSlots(const P11_SLOT_ROW* rows, CK_ULONG ulCount)
{
   CK_ULONG ulLoop;
   LVITEMA item;
   char szId[32];
   CK_SLOT_ID previousSlot = s_selectedSlot;
   CK_BBOOL bHadSelection = s_bHasSelection;

   memset(s_slotRows, 0, sizeof(s_slotRows));
   s_slotCount = 0;
   if ((rows != NULL) && (ulCount > 0))
   {
      if (ulCount > GUI_MAX_SLOTS)
      {
         ulCount = GUI_MAX_SLOTS;
      }
      memcpy(s_slotRows, rows, ulCount * sizeof(P11_SLOT_ROW));
      s_slotCount = ulCount;
   }

   SendMessageA(s_hList, WM_SETREDRAW, FALSE, 0);
   SendMessageA(s_hList, LVM_DELETEALLITEMS, 0, 0);

   for (ulLoop = 0; ulLoop < ulCount; ulLoop++)
   {
      memset(szId, 0, sizeof(szId));
      sprintf(szId, "%lu", (unsigned long)rows[ulLoop].slotId);

      memset(&item, 0, sizeof(item));
      item.mask = LVIF_TEXT | LVIF_PARAM;
      item.iItem = (int)ulLoop;
      item.iSubItem = 0;
      item.pszText = szId;
      item.lParam = (LPARAM)rows[ulLoop].slotId;
      SendMessageA(s_hList, LVM_INSERTITEMA, 0, (LPARAM)&item);
      ListView_SetItemText(s_hList, (int)ulLoop, 1, (LPSTR)rows[ulLoop].label);
      ListView_SetItemText(s_hList, (int)ulLoop, 2, (LPSTR)rows[ulLoop].model);
      ListView_SetItemText(s_hList, (int)ulLoop, 3, (LPSTR)rows[ulLoop].firmware);
      ListView_SetItemText(s_hList, (int)ulLoop, 4, (LPSTR)rows[ulLoop].software);
      ListView_SetItemText(s_hList, (int)ulLoop, 5, (LPSTR)rows[ulLoop].serial);
   }

   SendMessageA(s_hList, WM_SETREDRAW, TRUE, 0);
   InvalidateRect(s_hList, NULL, TRUE);

   if (ulCount == 0)
   {
      s_bHasSelection = CK_FALSE;
      WndMain_SetStatus("No slots found.");
   }
   else
   {
      if (bHadSelection == CK_TRUE)
      {
         WndMain_SelectSlotId(previousSlot);
      }
      else
      {
         ListView_SetItemState(s_hList, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
      }
      WndMain_GetSelectedSlot(&s_selectedSlot, s_selectedLabel, sizeof(s_selectedLabel));
      if (P11_IsLoggedIn() == CK_TRUE)
      {
         WndMain_SetStatus("Logged in as %s on slot %lu (%s).",
            (s_bLoggedInAsCu == CK_TRUE) ? "Crypto User" : "Crypto Officer",
            (unsigned long)s_selectedSlot,
            s_selectedLabel);
      }
      else
      {
         WndMain_SetStatus("%lu slot(s). Selected slot %lu (%s).",
            (unsigned long)ulCount,
            (unsigned long)s_selectedSlot,
            s_selectedLabel);
      }
   }
}

static void WndMain_OnLibraryDone(GUI_LOAD_RESULT* pRes)
{
   if (pRes == NULL)
   {
      WndMain_UpdateButtons();
      return;
   }

   if ((s_hList == NULL) || (IsWindow(s_hList) == FALSE))
   {
      free(pRes);
      return;
   }

   if (pRes->bOk != CK_TRUE)
   {
      WndMain_ClearSlots();
      WndMain_SetStatus("%s", pRes->szStatus);
   }
   else
   {
      WndMain_FillSlots(pRes->rows, pRes->ulCount);
   }

   free(pRes);
   WndMain_UpdateButtons();
}

static void WndMain_RefreshSlots(void)
{
   char szPath[GUI_PATH_MAX];
   char szError[GUI_STATUS_TEXT_MAX];
   CK_BBOOL bReload = CK_FALSE;

   if (GUI_IsLoadInProgress() == CK_TRUE)
   {
      WndMain_SetStatus("PKCS#11 library is still loading...");
      return;
   }

   WndMain_RememberRefreshPath();

   if (WndMain_ApplyClientPath() != CK_TRUE)
   {
      WndMain_ClearSlots();
      WndMain_UpdateButtons();
      return;
   }

   memset(szPath, 0, sizeof(szPath));
   memset(szError, 0, sizeof(szError));
   WndMain_GetClientPath(szPath, sizeof(szPath));

   if (GUI_PreflightLibrary(szPath, szError, sizeof(szError)) != CK_TRUE)
   {
      WndMain_ClearSlots();
      WndMain_SetStatus("%s", szError);
      WndMain_UpdateButtons();
      return;
   }

   if ((GUI_IsLibraryLoaded() == CK_TRUE) && (GUI_IsSameLoadedPath(szPath) != CK_TRUE))
   {
      if (P11_IsLoggedIn() == CK_TRUE)
      {
         WndMain_SetStatus("Logout before changing ChrystokiConfigurationPath.");
         WndMain_UpdateButtons();
         return;
      }
      bReload = CK_TRUE;
   }

   /* All PKCS#11 calls run on the load thread so a slow HSM never freezes the UI. */
   if (GUI_BeginLibraryLoad(s_hWnd, szPath, bReload) != CK_TRUE)
   {
      GUI_GetLibraryStatus(szError, sizeof(szError));
      WndMain_SetStatus("%s", szError);
      WndMain_UpdateButtons();
      return;
   }

   if ((GUI_IsLibraryLoaded() == CK_TRUE) && (bReload == CK_FALSE))
   {
      WndMain_SetStatus("Refreshing slots...");
   }
   else
   {
      WndMain_SetStatus("Loading PKCS#11 library...");
   }
   WndMain_UpdateButtons();
}

static void WndMain_DoLogin(void)
{
   CK_SLOT_ID slotId = 0;
   char szLabel[P11_SLOT_LABEL_MAX + 1];
   char szPassword[GUI_PASSWORD_MAX];
   CK_CHAR_PTR pPin = NULL;
   CK_BBOOL bCryptoUser = CK_FALSE;
   CK_SLOT_ID selected;
   CK_RV rv;

   memset(szLabel, 0, sizeof(szLabel));
   memset(szPassword, 0, sizeof(szPassword));

   if (GUI_IsLoadInProgress() == CK_TRUE)
   {
      WndMain_SetStatus("PKCS#11 library is still loading...");
      return;
   }

   if (GUI_IsLibraryLoaded() == CK_FALSE)
   {
      WndMain_SetStatus("PKCS#11 library is not loaded.");
      return;
   }

   if (P11_IsLoggedIn() == CK_TRUE)
   {
      WndMain_SetStatus("Already logged in. Logout first.");
      WndMain_UpdateButtons();
      return;
   }

   if (WndMain_GetSelectedSlot(&slotId, szLabel, sizeof(szLabel)) != CK_TRUE)
   {
      WndMain_SetStatus("Select a slot.");
      return;
   }

   selected = P11_SelectStot(slotId);
   if (selected == CK_NULL_ELEMENT)
   {
      WndMain_SetStatus("Slot not found: %lu", (unsigned long)slotId);
      return;
   }

   bCryptoUser = (CK_BBOOL)((SendMessageA(s_hCryptoUser, BM_GETCHECK, 0, 0) == BST_CHECKED) ? CK_TRUE : CK_FALSE);

   /* 1.0.3.e: open first so salogin / already-authenticated sessions skip the PIN. */
   rv = P11_OpenSession(slotId);
   if ((rv != CKR_OK) && (P11_IsLoggedIn() != CK_TRUE))
   {
      WndMain_SetStatus("Open session failed: %s", P11Util_DisplayErrorName(rv));
      return;
   }

   if (P11_IsAlreadyConnected() == CK_TRUE)
   {
      s_bLoggedInAsCu = bCryptoUser;
      SetWindowTextA(s_hPassword, "");
      WndMain_SetStatus("Logged in as %s on slot %lu (%s) (existing session).",
         (bCryptoUser == CK_TRUE) ? "Crypto User" : "Crypto Officer",
         (unsigned long)slotId,
         szLabel);
      WndMain_UpdateButtons();
      return;
   }

   GetWindowTextA(s_hPassword, szPassword, sizeof(szPassword));
   if (szPassword[0] != 0)
   {
      /* Match CLI -password: a typed PIN is always sent, even on PED tokens. */
      pPin = (CK_CHAR_PTR)szPassword;
   }
   else if (P11_IsLoginPasswordRequired() == CK_FALSE)
   {
      /* PED token: NULL PIN hands authentication to the PED. */
      pPin = NULL;
   }
   else
   {
      /* Never send an empty PIN; failed attempts count toward partition lockout. */
      P11_Logout();
      WndMain_SetStatus("Enter the password for slot %lu (%s).",
         (unsigned long)slotId, szLabel);
      SetFocus(s_hPassword);
      return;
   }

   rv = P11_Login(slotId, pPin, bCryptoUser);
   GUI_SecureClear(szPassword, sizeof(szPassword));

   if (rv == CKR_OK)
   {
      s_bLoggedInAsCu = bCryptoUser;
      SetWindowTextA(s_hPassword, "");
      WndMain_SetStatus("Logged in as %s on slot %lu (%s).",
         (bCryptoUser == CK_TRUE) ? "Crypto User" : "Crypto Officer",
         (unsigned long)slotId,
         szLabel);
   }
   else
   {
      WndMain_SetStatus("Login failed: %s", P11Util_DisplayErrorName(rv));
   }

   WndMain_UpdateButtons();
}

static void WndMain_DoLogout(void)
{
   CK_RV rv;

   if (P11_IsLoggedIn() == CK_FALSE)
   {
      WndMain_SetStatus("Not logged in.");
      WndMain_UpdateButtons();
      return;
   }

   rv = P11_Logout();
   s_bLoggedInAsCu = CK_FALSE;
   GUI_SetLastObjectHandle(0);

   if (P11_IsLoggedIn() == CK_FALSE)
   {
      WndMain_SetStatus("Logged out.");
   }
   else
   {
      WndMain_SetStatus("Logout failed: %s", P11Util_DisplayErrorName(rv));
   }

   WndMain_UpdateButtons();
}

static void WndMain_Layout(int cx, int cy)
{
   int yAction;
   int listH;
   int statusY;
   int colLabelW;
   int pathY;
   int pathEditY;
   int listY;
   int editW;
   int browseX;
   int refreshX;
   int x;

   if (cx < 200)
   {
      cx = 200;
   }
   if (cy < 220)
   {
      cy = 220;
   }

   pathY = GUI_MARGIN;
   browseX = cx - GUI_MARGIN - GUI_BTN_W;
   refreshX = browseX - 8 - GUI_BTN_W;
   editW = refreshX - GUI_MARGIN - 8;
   if (editW < 80)
   {
      editW = 80;
   }
   pathEditY = pathY + GUI_PATH_LABEL_H + 4;
   MoveWindow(s_hLblPath, GUI_MARGIN, pathY, cx - (2 * GUI_MARGIN), GUI_PATH_LABEL_H, TRUE);
   MoveWindow(s_hPath, GUI_MARGIN, pathEditY, editW, GUI_EDIT_H, TRUE);
   MoveWindow(s_hRefresh, refreshX, pathEditY - 1, GUI_BTN_W, GUI_BTN_H, TRUE);
   MoveWindow(s_hBrowse, browseX, pathEditY - 1, GUI_BTN_W, GUI_BTN_H, TRUE);

   statusY = cy - GUI_MARGIN - GUI_STATUS_H;
   yAction = statusY - 8 - GUI_BTN_H;
   listY = pathEditY + GUI_EDIT_H + 10;
   listH = yAction - 8 - listY;
   if (listH < 80)
   {
      listH = 80;
   }

   MoveWindow(s_hList, GUI_MARGIN, listY, cx - (2 * GUI_MARGIN), listH, TRUE);

   colLabelW = cx - (2 * GUI_MARGIN) - GUI_COL_SLOT_W - GUI_COL_MODEL_W
      - GUI_COL_FW_W - GUI_COL_SW_W - GUI_COL_SERIAL_W - 24;
   if (colLabelW < 80)
   {
      colLabelW = 80;
   }
   ListView_SetColumnWidth(s_hList, 0, GUI_COL_SLOT_W);
   ListView_SetColumnWidth(s_hList, 1, colLabelW);
   ListView_SetColumnWidth(s_hList, 2, GUI_COL_MODEL_W);
   ListView_SetColumnWidth(s_hList, 3, GUI_COL_FW_W);
   ListView_SetColumnWidth(s_hList, 4, GUI_COL_SW_W);
   ListView_SetColumnWidth(s_hList, 5, GUI_COL_SERIAL_W);

   if (P11_IsLoggedIn() == CK_TRUE)
   {
      x = GUI_MARGIN;
      MoveWindow(s_hLogout, x, yAction, GUI_BTN_W, GUI_BTN_H, TRUE);
      x += GUI_BTN_W + 8;
      MoveWindow(s_hListKeys, x, yAction, GUI_ACTION_BTN_W, GUI_BTN_H, TRUE);
      x += GUI_ACTION_BTN_W + 8;
      MoveWindow(s_hGenerate, x, yAction, GUI_ACTION_BTN_W, GUI_BTN_H, TRUE);
      x += GUI_ACTION_BTN_W + 8;
      MoveWindow(s_hCreateDO, x, yAction, GUI_CREATEDO_BTN_W, GUI_BTN_H, TRUE);
      x += GUI_CREATEDO_BTN_W + 8;
      MoveWindow(s_hImport, x, yAction, GUI_IO_BTN_W, GUI_BTN_H, TRUE);
      x += GUI_IO_BTN_W + 8;
      MoveWindow(s_hExport, x, yAction, GUI_IO_BTN_W, GUI_BTN_H, TRUE);
      x += GUI_IO_BTN_W + 8;
      MoveWindow(s_hMore, x, yAction, GUI_MORE_BTN_W, GUI_BTN_H, TRUE);
   }
   else
   {
      MoveWindow(s_hLblPassword, GUI_MARGIN, yAction + 5, 64, 16, TRUE);
      MoveWindow(s_hPassword, GUI_MARGIN + 66, yAction + 1, 150, GUI_EDIT_H, TRUE);
      MoveWindow(s_hCryptoUser, GUI_MARGIN + 224, yAction + 4, 100, 18, TRUE);
      MoveWindow(s_hLogin, GUI_MARGIN + 332, yAction, GUI_BTN_W, GUI_BTN_H, TRUE);
   }
   MoveWindow(s_hStatus, GUI_MARGIN, statusY, cx - (2 * GUI_MARGIN), GUI_STATUS_H, TRUE);
}

static void WndMain_CreateChildren(HWND hWnd)
{
   LVCOLUMNA col;

   s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

   s_hLblPath = CreateWindowA("STATIC", "ChrystokiConfigurationPath:",
      WS_CHILD | WS_VISIBLE,
      0, 0, 280, GUI_PATH_LABEL_H, hWnd, (HMENU)(INT_PTR)IDC_LBL_CLIENT_PATH, NULL, NULL);

   s_hPath = CreateWindowA("EDIT", "",
      WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | ES_LEFT,
      0, 0, 300, GUI_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EDIT_CLIENT_PATH, NULL, NULL);

   s_hBrowse = CreateWindowA("BUTTON", "Browse...",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
      0, 0, GUI_BTN_W, GUI_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_BTN_BROWSE, NULL, NULL);

   s_hList = CreateWindowA(WC_LISTVIEWA, "",
      WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
      LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
      0, 0, 100, 100, hWnd, (HMENU)(INT_PTR)IDC_LIST_SLOTS, NULL, NULL);

   s_hRefresh = CreateWindowA("BUTTON", "Refresh",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
      0, 0, GUI_BTN_W, GUI_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_BTN_REFRESH, NULL, NULL);

   s_hLblPassword = CreateWindowA("STATIC", "Password:",
      WS_CHILD | WS_VISIBLE,
      0, 0, 70, 18, hWnd, (HMENU)(INT_PTR)IDC_LBL_PASSWORD, NULL, NULL);

   s_hPassword = CreateWindowA("EDIT", "",
      WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL | ES_LEFT,
      0, 0, 180, GUI_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_EDIT_PASSWORD, NULL, NULL);

   s_hCryptoUser = CreateWindowA("BUTTON", "Crypto User",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
      0, 0, 140, 20, hWnd, (HMENU)(INT_PTR)IDC_CHK_CRYPTO_USER, NULL, NULL);

   s_hLogin = CreateWindowA("BUTTON", "Login",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
      0, 0, GUI_BTN_W, GUI_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_BTN_LOGIN, NULL, NULL);

   s_hLogout = CreateWindowA("BUTTON", "Logout",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
      0, 0, GUI_BTN_W, GUI_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_BTN_LOGOUT, NULL, NULL);

   s_hListKeys = CreateWindowA("BUTTON", "List objects",
      WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
      0, 0, GUI_ACTION_BTN_W, GUI_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_BTN_LIST_KEYS, NULL, NULL);

   s_hGenerate = CreateWindowA("BUTTON", "Generate key",
      WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
      0, 0, GUI_ACTION_BTN_W, GUI_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_BTN_GENERATE, NULL, NULL);

   s_hCreateDO = CreateWindowA("BUTTON", "Create data object",
      WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
      0, 0, GUI_CREATEDO_BTN_W, GUI_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_BTN_CREATEDO, NULL, NULL);

   s_hImport = CreateWindowA("BUTTON", "Import",
      WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
      0, 0, GUI_IO_BTN_W, GUI_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_BTN_IMPORT, NULL, NULL);

   s_hExport = CreateWindowA("BUTTON", "Export",
      WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
      0, 0, GUI_IO_BTN_W, GUI_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_BTN_EXPORT, NULL, NULL);

   s_hMore = CreateWindowA("BUTTON", "More",
      WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
      0, 0, GUI_MORE_BTN_W, GUI_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_BTN_MORE, NULL, NULL);

   s_hStatus = CreateWindowA("STATIC", "",
      WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
      0, 0, 100, GUI_STATUS_H, hWnd, (HMENU)(INT_PTR)IDC_STATUS, NULL, NULL);

   WndMain_ApplyFont(s_hLblPath);
   WndMain_ApplyFont(s_hPath);
   WndMain_ApplyFont(s_hBrowse);
   WndMain_ApplyFont(s_hList);
   WndMain_ApplyFont(s_hRefresh);
   WndMain_ApplyFont(s_hLblPassword);
   WndMain_ApplyFont(s_hPassword);
   WndMain_ApplyFont(s_hCryptoUser);
   WndMain_ApplyFont(s_hLogin);
   WndMain_ApplyFont(s_hLogout);
   WndMain_ApplyFont(s_hListKeys);
   WndMain_ApplyFont(s_hGenerate);
   WndMain_ApplyFont(s_hCreateDO);
   WndMain_ApplyFont(s_hImport);
   WndMain_ApplyFont(s_hExport);
   WndMain_ApplyFont(s_hMore);
   WndMain_ApplyFont(s_hStatus);
   GUI_ThemeMarkStatus(s_hStatus);

   {
      HMENU hMenu;
      HMENU hFile;
      HMENU hHelp;

      hMenu = CreateMenu();
      hFile = CreatePopupMenu();
      hHelp = CreatePopupMenu();
      AppendMenuA(hFile, MF_STRING, IDM_FILE_CAPABILITIES, "&Get capabilities...");
      AppendMenuA(hFile, MF_STRING, IDM_FILE_CONVERT, "&Convert file...");
      AppendMenuA(hFile, MF_SEPARATOR, 0, NULL);
      AppendMenuA(hFile, MF_STRING, IDM_FILE_EXIT, "E&xit");
      AppendMenuA(hHelp, MF_STRING, IDM_HELP_ABOUT, "&About Luna KMU");
      AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hFile, "&File");
      AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hHelp, "&Help");
      SetMenu(hWnd, hMenu);
   }

   SendMessageA(s_hPath, EM_SETLIMITTEXT, GUI_PATH_MAX - 1, 0);
   SendMessageA(s_hPassword, EM_SETLIMITTEXT, GUI_PASSWORD_MAX - 1, 0);
   WndMain_PrefillClientPath();
   GUI_ThemeStyleList(s_hList);

   memset(&col, 0, sizeof(col));
   col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
   col.cx = GUI_COL_SLOT_W;
   col.iSubItem = 0;
   col.pszText = "Slot ID";
   SendMessageA(s_hList, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);

   col.cx = 180;
   col.iSubItem = 1;
   col.pszText = "Label";
   SendMessageA(s_hList, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);

   col.cx = GUI_COL_MODEL_W;
   col.iSubItem = 2;
   col.pszText = "Model";
   SendMessageA(s_hList, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);

   col.cx = GUI_COL_FW_W;
   col.iSubItem = 3;
   col.pszText = "Firmware";
   SendMessageA(s_hList, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);

   col.cx = GUI_COL_SW_W;
   col.iSubItem = 4;
   col.pszText = "Software";
   SendMessageA(s_hList, LVM_INSERTCOLUMNA, 4, (LPARAM)&col);

   col.cx = GUI_COL_SERIAL_W;
   col.iSubItem = 5;
   col.pszText = "Serial";
   SendMessageA(s_hList, LVM_INSERTCOLUMNA, 5, (LPARAM)&col);
}

static void WndMain_ShowMore(void)
{
   HMENU hPop;
   RECT rc;
   UINT cmd;

   if ((s_hMore == NULL) || (s_hWnd == NULL) || (P11_IsLoggedIn() != CK_TRUE))
   {
      return;
   }

   hPop = CreatePopupMenu();
   if (hPop == NULL)
   {
      return;
   }
   AppendMenuA(hPop, MF_STRING, IDM_MORE_ENCRYPT, "&Encrypt...");
   AppendMenuA(hPop, MF_STRING, IDM_MORE_DECRYPT, "&Decrypt...");
   AppendMenuA(hPop, MF_SEPARATOR, 0, NULL);
   AppendMenuA(hPop, MF_STRING, IDM_MORE_SIGN, "&Sign...");
   AppendMenuA(hPop, MF_STRING, IDM_MORE_VERIFY, "&Verify...");
   AppendMenuA(hPop, MF_SEPARATOR, 0, NULL);
   AppendMenuA(hPop, MF_STRING, IDM_MORE_DERIVE, "D&erive...");
   AppendMenuA(hPop, MF_STRING, IDM_MORE_MZMK, "Remote &MZMK...");
   GetWindowRect(s_hMore, &rc);
   cmd = (UINT)TrackPopupMenu(hPop,
      TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
      rc.left, rc.top, 0, s_hWnd, NULL);
   DestroyMenu(hPop);

   if (cmd == IDM_MORE_ENCRYPT)
   {
      DlgCrypt_Show(s_hWnd, CK_FALSE);
   }
   else if (cmd == IDM_MORE_DECRYPT)
   {
      DlgCrypt_Show(s_hWnd, CK_TRUE);
   }
   else if (cmd == IDM_MORE_SIGN)
   {
      DlgSign_Show(s_hWnd, CK_FALSE);
   }
   else if (cmd == IDM_MORE_VERIFY)
   {
      DlgSign_Show(s_hWnd, CK_TRUE);
   }
   else if (cmd == IDM_MORE_DERIVE)
   {
      DlgDerive_Show(s_hWnd);
   }
   else if (cmd == IDM_MORE_MZMK)
   {
      DlgMzmk_Show(s_hWnd);
   }
}

static void WndMain_ShowCapabilities(void)
{
   if (GUI_IsLibraryLoaded() != CK_TRUE)
   {
      WndMain_SetStatus("PKCS#11 is not loaded.");
      return;
   }
   if (s_bHasSelection != CK_TRUE)
   {
      WndMain_SetStatus("Select a slot to view capabilities.");
      return;
   }
   DlgCapabilities_Show(s_hWnd, s_selectedSlot, s_selectedLabel);
}

static void WndMain_ShowAbout(HWND hWnd)
{
   char szText[320];

   memset(szText, 0, sizeof(szText));
   _snprintf(szText, sizeof(szText) - 1,
      "Luna KMU\nVersion %s\n\nPKCS#11 Key Management Utility for Luna HSM.",
      GUI_VERSION);
   MessageBoxA(hWnd, szText, "About Luna KMU", MB_OK | MB_ICONINFORMATION);
}

static LRESULT CALLBACK WndMain_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      s_hWnd = hWnd;
      WndMain_CreateChildren(hWnd);
      WndMain_SetStatus("Ready.");
      WndMain_UpdateButtons();
      PostMessageA(hWnd, WM_GUI_START_LOAD, 0, 0);
      return 0;

   case WM_GUI_START_LOAD:
      WndMain_RefreshSlots();
      return 0;

   case WM_GUI_P11_DONE:
      WndMain_OnLibraryDone((GUI_LOAD_RESULT*)lParam);
      return 0;

   case WM_SIZE:
      WndMain_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 860;
         pMin->ptMinTrackSize.y = 360;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_EDIT_CLIENT_PATH:
         if (HIWORD(wParam) == EN_KILLFOCUS)
         {
            WndMain_OnPathFinished();
         }
         return 0;
      case IDC_BTN_BROWSE:
         if ((WndMain_BrowseClientPath() == CK_TRUE) && (P11_IsLoggedIn() != CK_TRUE))
         {
            WndMain_RefreshSlots();
         }
         return 0;
      case IDC_BTN_REFRESH:
         WndMain_RefreshSlots();
         return 0;
      case IDC_BTN_LOGIN:
         if (GetFocus() == s_hPath)
         {
            WndMain_RefreshSlots();
            return 0;
         }
         WndMain_DoLogin();
         return 0;
      case IDC_BTN_LOGOUT:
         WndMain_DoLogout();
         return 0;
      case IDC_BTN_LIST_KEYS:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgListKeys_Show(hWnd);
         }
         return 0;
      case IDC_BTN_GENERATE:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgGenerate_Show(hWnd);
         }
         return 0;
      case IDC_BTN_CREATEDO:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgCreateDO_Show(hWnd);
         }
         return 0;
      case IDC_BTN_IMPORT:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgImport_Show(hWnd);
         }
         return 0;
      case IDC_BTN_EXPORT:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgExport_Show(hWnd);
         }
         return 0;
      case IDC_BTN_MORE:
         WndMain_ShowMore();
         return 0;
      case IDM_MORE_ENCRYPT:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgCrypt_Show(hWnd, CK_FALSE);
         }
         return 0;
      case IDM_MORE_DECRYPT:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgCrypt_Show(hWnd, CK_TRUE);
         }
         return 0;
      case IDM_MORE_SIGN:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgSign_Show(hWnd, CK_FALSE);
         }
         return 0;
      case IDM_MORE_VERIFY:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgSign_Show(hWnd, CK_TRUE);
         }
         return 0;
      case IDM_MORE_DERIVE:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgDerive_Show(hWnd);
         }
         return 0;
      case IDM_MORE_MZMK:
         if (P11_IsLoggedIn() == CK_TRUE)
         {
            DlgMzmk_Show(hWnd);
         }
         return 0;
      case IDM_FILE_CAPABILITIES:
         WndMain_ShowCapabilities();
         return 0;
      case IDM_FILE_CONVERT:
         DlgConvert_Show(hWnd);
         return 0;
      case IDM_FILE_EXIT:
         PostMessageA(hWnd, WM_CLOSE, 0, 0);
         return 0;
      case IDM_HELP_ABOUT:
         WndMain_ShowAbout(hWnd);
         return 0;
      default:
         break;
      }
      break;

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

   case WM_NOTIFY:
      if (wParam == IDC_LIST_SLOTS)
      {
         NMHDR* pHdr = (NMHDR*)lParam;
         if (pHdr->code == LVN_ITEMCHANGED)
         {
            NMLISTVIEW* pNlv = (NMLISTVIEW*)lParam;
            if ((pNlv->uChanged & LVIF_STATE) && (pNlv->uNewState & LVIS_SELECTED))
            {
               WndMain_OnSlotSelected();
            }
         }
         else if (pHdr->code == NM_DBLCLK)
         {
            if ((P11_IsLoggedIn() != CK_TRUE) && (GUI_IsLoadInProgress() != CK_TRUE))
            {
               WndMain_DoLogin();
            }
         }
      }
      break;

   case WM_CLOSE:
      DestroyWindow(hWnd);
      return 0;

   case WM_DESTROY:
      s_hWnd = NULL;
      s_hList = NULL;
      s_hStatus = NULL;
      PostQuitMessage(0);
      return 0;

   default:
      break;
   }

   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

/*
    FUNCTION:        ATOM WndMain_Register(HINSTANCE hInstance)
*/
ATOM WndMain_Register(HINSTANCE hInstance)
{
   WNDCLASSEXA wc;

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.style = CS_HREDRAW | CS_VREDRAW;
   wc.lpfnWndProc = WndMain_WndProc;
   wc.hInstance = hInstance;
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = GUI_WND_CLASS;
   wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
   wc.hIconSm = wc.hIcon;

   return RegisterClassExA(&wc);
}

/*
    FUNCTION:        HWND WndMain_Create(HINSTANCE hInstance, int nCmdShow)
*/
HWND WndMain_Create(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hWnd = CreateWindowExA(WS_EX_CONTROLPARENT, GUI_WND_CLASS, GUI_APP_TITLE,
      WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
      CW_USEDEFAULT, CW_USEDEFAULT, 1100, 420,
      NULL, NULL, hInstance, NULL);

   if (hWnd == NULL)
   {
      return NULL;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);
   return hWnd;
}
