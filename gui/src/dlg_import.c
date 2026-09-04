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

#define _DLG_IMPORT_C

#ifdef OS_WIN32
#include <windows.h>
#include <commdlg.h>
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
#include "dlg_import.h"

#define DLG_IMP_CLASS             "LunaKmuImport"
#define DLG_IMP_COMP_CLASS        "LunaKmuImpComp"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               100
#define DLG_BROWSE_W              80
#define DLG_COMBO_DROP            240
#define DLG_PW_MAX                256
#define DLG_MAX_LABEL             100
#define DLG_CKA_ID_MAX            4096
#define DLG_HEX_MAX               8192

#define IDC_IMP_FILEMODE          3101
#define IDC_IMP_COMPMODE          3102
#define IDC_IMP_LABEL             3103
#define IDC_IMP_TYPE              3104
#define IDC_IMP_CLASS             3105
#define IDC_IMP_SIZE              3106
#define IDC_IMP_FILE              3107
#define IDC_IMP_BROWSE            3108
#define IDC_IMP_FORMAT            3109
#define IDC_IMP_UNWRAP            3110
#define IDC_IMP_ALGO              3111
#define IDC_IMP_IV                3112
#define IDC_IMP_AAD               3113
#define IDC_IMP_TAG               3114
#define IDC_IMP_HASH              3115
#define IDC_IMP_PASSWORD          3116
#define IDC_IMP_COMPN             3117
#define IDC_IMP_ID                3118
#define IDC_IMP_GO                3119
#define IDC_IMP_CLOSE             3120
#define IDC_IMP_STATUS            3121
#define IDC_IMP_TOKEN             3130
#define IDC_IMP_PRIVATE           3131
#define IDC_IMP_SENSITIVE         3132
#define IDC_IMP_EXTRACTABLE       3133
#define IDC_IMP_ENCRYPT           3134
#define IDC_IMP_DECRYPT           3135
#define IDC_IMP_SIGN              3136
#define IDC_IMP_VERIFY            3137
#define IDC_IMP_WRAP              3138
#define IDC_IMP_UNWRAPCKA         3139
#define IDC_IMP_DERIVE            3140
#define IDC_IMP_MODIFIABLE        3141
#define IDC_IMP_ENCAPSULATE       3142
#define IDC_IMP_DECAPSULATE       3143
#define IDC_IMP_LBL_LABEL         3150
#define IDC_IMP_LBL_TYPE          3151
#define IDC_IMP_LBL_CLASS         3152
#define IDC_IMP_LBL_SIZE          3153
#define IDC_IMP_LBL_FILE          3154
#define IDC_IMP_LBL_FORMAT        3155
#define IDC_IMP_LBL_UNWRAP        3156
#define IDC_IMP_LBL_ALGO          3157
#define IDC_IMP_LBL_IV            3158
#define IDC_IMP_LBL_AAD           3159
#define IDC_IMP_LBL_TAG           3160
#define IDC_IMP_LBL_HASH          3161
#define IDC_IMP_LBL_PASSWORD      3162
#define IDC_IMP_LBL_COMPN         3163
#define IDC_IMP_LBL_ID            3164
#define IDC_IMP_UNWRAP_LABEL      3165
#define IDC_IMP_UNWRAP_ID         3166
#define IDC_IMP_LBL_UNWRAP_LABEL  3167
#define IDC_IMP_LBL_UNWRAP_ID     3168
#define IDC_COMP_HEX              3201
#define IDC_COMP_NEXT             3202
#define IDC_COMP_CANCEL           3203

static HWND s_hDlg = NULL;
static HWND s_hFileMode = NULL;
static HWND s_hCompMode = NULL;
static HWND s_hLabel = NULL;
static HWND s_hType = NULL;
static HWND s_hClass = NULL;
static HWND s_hSize = NULL;
static HWND s_hFile = NULL;
static HWND s_hFormat = NULL;
static HWND s_hUnwrap = NULL;
static HWND s_hUnwrapLabel = NULL;
static HWND s_hUnwrapId = NULL;
static HWND s_hAlgo = NULL;
static HWND s_hIv = NULL;
static HWND s_hAad = NULL;
static HWND s_hTag = NULL;
static HWND s_hHash = NULL;
static HWND s_hPassword = NULL;
static HWND s_hCompN = NULL;
static HWND s_hId = NULL;
static HWND s_hStatus = NULL;
static HWND s_hToken = NULL;
static HWND s_hPrivate = NULL;
static HWND s_hSensitive = NULL;
static HWND s_hExtractable = NULL;
static HWND s_hEncrypt = NULL;
static HWND s_hDecrypt = NULL;
static HWND s_hSign = NULL;
static HWND s_hVerify = NULL;
static HWND s_hWrap = NULL;
static HWND s_hUnwrapCka = NULL;
static HWND s_hDerive = NULL;
static HWND s_hModifiable = NULL;
static HWND s_hEncapsulate = NULL;
static HWND s_hDecapsulate = NULL;
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static BOOL s_bCompDone = FALSE;
static BOOL s_bCompOk = FALSE;
static HWND s_hCompDlg = NULL;
static P11_ENCRYPTION_MECH s_mech;
static CK_BYTE s_ivBuf[32];
static CK_BYTE s_aadBuf[256];
static char s_szPassword[DLG_PW_MAX];
static char s_szLabel[DLG_MAX_LABEL];
static char s_szCkaId[(DLG_CKA_ID_MAX * 2) + 2];
static char s_szCompHex[2048];

static void DlgImp_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static CK_BBOOL DlgImp_IsChecked(HWND hChk)
{
   return (SendMessageA(hChk, BM_GETCHECK, 0, 0) == BST_CHECKED) ? CK_TRUE : CK_FALSE;
}

static void DlgImp_AddFmt(HWND hCombo, const char* sName, CK_BYTE fmt)
{
   int iItem = (int)SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)sName);
   if (iItem >= 0)
   {
      SendMessageA(hCombo, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)fmt);
   }
}

static CK_BYTE DlgImp_Format(void)
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

static const char* DlgImp_ComboName(HWND hCombo)
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

static void DlgImp_SelectNamed(HWND hCombo, const char* sName)
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

static BOOL DlgImp_IsComponents(void)
{
   return (SendMessageA(s_hCompMode, BM_GETCHECK, 0, 0) == BST_CHECKED) ? TRUE : FALSE;
}

static void DlgImp_StripHex(char* s)
{
   char* pSrc;
   char* pDst;

   if (s == NULL)
   {
      return;
   }
   pSrc = s;
   if ((pSrc[0] == '0') && ((pSrc[1] == 'x') || (pSrc[1] == 'X')))
   {
      pSrc += 2;
   }
   pDst = s;
   while (*pSrc != 0)
   {
      if (isspace((unsigned char)*pSrc) == 0)
      {
         *pDst++ = *pSrc;
      }
      pSrc++;
   }
   *pDst = 0;
}

static void DlgImp_FillTypes(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetKeyTypeNameCount(KEY_TYPE_IMPORT_EXPORTKEY);
   char szDisp[48];

   SendMessageA(s_hType, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetKeyTypeNameAt(KEY_TYPE_IMPORT_EXPORTKEY, uLoop);
      int iItem;
      if (pName == NULL)
      {
         continue;
      }
      memset(szDisp, 0, sizeof(szDisp));
      GUI_FormatKeyTypeCliName((const char*)pName, szDisp, sizeof(szDisp));
      iItem = (int)SendMessageA(s_hType, CB_ADDSTRING, 0, (LPARAM)szDisp);
      if (iItem >= 0)
      {
         SendMessageA(s_hType, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)pName);
      }
   }
   DlgImp_SelectNamed(s_hType, "aes");
}

static void DlgImp_FillClasses(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetKeyClassCount();

   SendMessageA(s_hClass, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetKeyClassNameAt(uLoop);
      int iItem;
      if (pName == NULL)
      {
         continue;
      }
      iItem = (int)SendMessageA(s_hClass, CB_ADDSTRING, 0, (LPARAM)pName);
      if (iItem >= 0)
      {
         SendMessageA(s_hClass, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)pName);
      }
   }
   DlgImp_SelectNamed(s_hClass, "secret");
}

static void DlgImp_FillSize(void)
{
   int iItem;

   SendMessageA(s_hSize, CB_RESETCONTENT, 0, 0);
   iItem = (int)SendMessageA(s_hSize, CB_ADDSTRING, 0, (LPARAM)"AES-128 (16)");
   SendMessageA(s_hSize, CB_SETITEMDATA, (WPARAM)iItem, AES_128_KEY_LENGTH);
   iItem = (int)SendMessageA(s_hSize, CB_ADDSTRING, 0, (LPARAM)"AES-192 (24)");
   SendMessageA(s_hSize, CB_SETITEMDATA, (WPARAM)iItem, AES_192_KEY_LENGTH);
   iItem = (int)SendMessageA(s_hSize, CB_ADDSTRING, 0, (LPARAM)"AES-256 (32)");
   SendMessageA(s_hSize, CB_SETITEMDATA, (WPARAM)iItem, AES_256_KEY_LENGTH);
   SendMessageA(s_hSize, CB_SETCURSEL, 0, 0);
}

static void DlgImp_FillAlgos(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetEncryptionCount(KEY_TYPE_IMPORT_EXPORTKEY);

   SendMessageA(s_hAlgo, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetEncryptionNameAt(KEY_TYPE_IMPORT_EXPORTKEY, uLoop);
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
   DlgImp_SelectNamed(s_hAlgo, "aes_cbc_pad");
}

static void DlgImp_FillHash(void)
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
   DlgImp_SelectNamed(s_hHash, "sha256");
}

static void DlgImp_FillFormat(void)
{
   SendMessageA(s_hFormat, CB_RESETCONTENT, 0, 0);
   DlgImp_AddFmt(s_hFormat, "text", P11_FILE_FORMAT_TEXT);
   DlgImp_AddFmt(s_hFormat, "bin", P11_FILE_FORMAT_BINARY);
   DlgImp_AddFmt(s_hFormat, "pkcs8", P11_FILE_FORMAT_PKCS8);
   DlgImp_AddFmt(s_hFormat, "tr31", P11_FILE_FORMAT_TR31);
   SendMessageA(s_hFormat, CB_SETCURSEL, 0, 0);
}

static CK_LONG DlgImp_SizeBytes(void)
{
   int iSel = (int)SendMessageA(s_hSize, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel < 0)
   {
      return AES_128_KEY_LENGTH;
   }
   data = SendMessageA(s_hSize, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if (data == CB_ERR)
   {
      return AES_128_KEY_LENGTH;
   }
   return (CK_LONG)data;
}

static CK_LONG DlgImp_CompCount(void)
{
   int iSel = (int)SendMessageA(s_hCompN, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel < 0)
   {
      return 2;
   }
   data = SendMessageA(s_hCompN, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if ((data == 0) || (data == CB_ERR))
   {
      return 2;
   }
   return (CK_LONG)data;
}

static void DlgImp_SyncClassFromType(void)
{
   const char* pType = DlgImp_ComboName(s_hType);
   CK_OBJECT_CLASS cls;

   if (pType == NULL)
   {
      return;
   }
   cls = P11Util_GetClassFromCKType((CK_CHAR_PTR)pType, KEY_TYPE_IMPORT_EXPORTKEY);
   if (cls == CKO_SECRET_KEY)
   {
      DlgImp_SelectNamed(s_hClass, "secret");
   }
   else if (cls == CKO_PRIVATE_KEY)
   {
      DlgImp_SelectNamed(s_hClass, "private");
   }
   else if (cls == CKO_PUBLIC_KEY)
   {
      DlgImp_SelectNamed(s_hClass, "public");
   }
}

static void DlgImp_UpdateFields(void)
{
   BOOL bComp = DlgImp_IsComponents();
   const char* pClass = DlgImp_ComboName(s_hClass);
   const char* pType = DlgImp_ComboName(s_hType);
   const char* pAlgo = DlgImp_ComboName(s_hAlgo);
   CK_BYTE fmt = DlgImp_Format();
   BOOL bPublic = FALSE;
   BOOL bPkcs8 = FALSE;
   BOOL bTr31 = FALSE;
   BOOL bWrap = FALSE;
   BOOL bIv = FALSE;
   BOOL bGcm = FALSE;
   BOOL bOaep = FALSE;
   BOOL bSize = FALSE;
   BOOL bAesKw = FALSE;

   if ((pClass != NULL) && (strcmp(pClass, "public") == 0))
   {
      bPublic = TRUE;
   }
   bPkcs8 = ((bComp == FALSE) && (bPublic == FALSE) && (fmt == P11_FILE_FORMAT_PKCS8));
   bTr31 = ((bComp == FALSE) && (bPublic == FALSE) && (fmt == P11_FILE_FORMAT_TR31));
   bWrap = ((bComp == FALSE) && (bPublic == FALSE) && (bPkcs8 == FALSE) && (bTr31 == FALSE));
   bAesKw = ((bWrap != FALSE) && (pAlgo != NULL) && (strcmp(pAlgo, "aes_kw") == 0));

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

   if ((pType != NULL) && (strcmp(pType, "aes") == 0) && ((bComp != FALSE) || (bAesKw != FALSE)))
   {
      bSize = TRUE;
   }

   EnableWindow(s_hClass, (bComp == FALSE));
   EnableWindow(s_hFile, (bComp == FALSE));
   EnableWindow(GetDlgItem(s_hDlg, IDC_IMP_BROWSE), (bComp == FALSE));
   EnableWindow(s_hFormat, (bComp == FALSE));
   EnableWindow(s_hUnwrap, ((bComp == FALSE) && (bPublic == FALSE) && (bPkcs8 == FALSE)));
   EnableWindow(s_hUnwrapLabel, ((bComp == FALSE) && (bPublic == FALSE) && (bPkcs8 == FALSE)));
   EnableWindow(s_hUnwrapId, ((bComp == FALSE) && (bPublic == FALSE) && (bPkcs8 == FALSE)));
   EnableWindow(s_hAlgo, bWrap);
   EnableWindow(s_hIv, bIv);
   EnableWindow(s_hAad, bGcm);
   EnableWindow(s_hTag, bGcm);
   EnableWindow(s_hHash, bOaep);
   EnableWindow(s_hPassword, bPkcs8);
   EnableWindow(s_hCompN, bComp);
   EnableWindow(s_hSize, bSize);
}

static BOOL DlgImp_PickFile(char* szPath, unsigned int pathSize)
{
   OPENFILENAMEA ofn;

   if ((szPath == NULL) || (pathSize < 8))
   {
      return FALSE;
   }
   memset(szPath, 0, pathSize);
   GetWindowTextA(s_hFile, szPath, (int)pathSize);

   memset(&ofn, 0, sizeof(ofn));
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = s_hDlg;
   ofn.lpstrFilter = "All files (*.*)\0*.*\0Text (*.txt)\0*.txt\0Binary (*.bin)\0*.bin\0PEM (*.pem)\0*.pem\0TR-31 (*.tr31)\0*.tr31\0";
   ofn.lpstrFile = szPath;
   ofn.nMaxFile = pathSize;
   ofn.Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_NOCHANGEDIR | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
   ofn.lpstrTitle = "Import from file";
   return (GetOpenFileNameA(&ofn) != FALSE) ? TRUE : FALSE;
}

static LRESULT CALLBACK DlgImp_CompProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_COMP_NEXT:
      case IDOK:
         memset(s_szCompHex, 0, sizeof(s_szCompHex));
         GetWindowTextA(GetDlgItem(hWnd, IDC_COMP_HEX), s_szCompHex, sizeof(s_szCompHex));
         s_bCompOk = TRUE;
         s_bCompDone = TRUE;
         DestroyWindow(hWnd);
         return 0;
      case IDC_COMP_CANCEL:
      case IDCANCEL:
         GUI_SecureClear(s_szCompHex, sizeof(s_szCompHex));
         s_bCompOk = FALSE;
         s_bCompDone = TRUE;
         DestroyWindow(hWnd);
         return 0;
      default:
         break;
      }
      break;
   case WM_CLOSE:
      GUI_SecureClear(s_szCompHex, sizeof(s_szCompHex));
      s_bCompOk = FALSE;
      s_bCompDone = TRUE;
      DestroyWindow(hWnd);
      return 0;
   case WM_DESTROY:
      s_hCompDlg = NULL;
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
   default:
      break;
   }
   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

static CK_BBOOL DlgImp_AskComponent(HWND hwndParent, CK_LONG iIndex, CK_LONG iTotal,
   CK_LONG nLen, CK_BYTE_PTR pOut)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   HWND hHex;
   MSG msg;
   RECT rc;
   char szTitle[80];
   CK_ULONG uBin;
   HFONT hFont;

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgImp_CompProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_IMP_COMP_CLASS;
   RegisterClassExA(&wc);

   if (hwndParent != NULL)
   {
      GetWindowRect(hwndParent, &rc);
   }
   else
   {
      rc.left = 240;
      rc.top = 200;
   }

   memset(szTitle, 0, sizeof(szTitle));
   _snprintf(szTitle, sizeof(szTitle) - 1, "Enter component %ld of %ld", (long)iIndex, (long)iTotal);
   memset(s_szCompHex, 0, sizeof(s_szCompHex));

   s_bCompDone = FALSE;
   s_bCompOk = FALSE;
   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_IMP_COMP_CLASS, szTitle,
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
      rc.left + 24, rc.top + 24, 560, 180,
      hwndParent, NULL, wc.hInstance, NULL);
   if (hDlg == NULL)
   {
      return CK_FALSE;
   }
   s_hCompDlg = hDlg;
   hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

   CreateWindowA("STATIC", "Paste the hex component, then click Next.",
      WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
      12, 12, 520, 18, hDlg, NULL, NULL, NULL);
   hHex = CreateWindowA("EDIT", "",
      WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
      12, 40, 520, 22, hDlg, (HMENU)(INT_PTR)IDC_COMP_HEX, NULL, NULL);
   CreateWindowA("BUTTON", "Next",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
      356, 110, DLG_BTN_W, DLG_BTN_H, hDlg, (HMENU)(INT_PTR)IDC_COMP_NEXT, NULL, NULL);
   CreateWindowA("BUTTON", "Cancel",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
      448, 110, DLG_BTN_W, DLG_BTN_H, hDlg, (HMENU)(INT_PTR)IDC_COMP_CANCEL, NULL, NULL);

   {
      HWND hCtrl;
      for (hCtrl = GetWindow(hDlg, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
      {
         SendMessageA(hCtrl, WM_SETFONT, (WPARAM)hFont, TRUE);
      }
   }
   SendMessageA(hHex, EM_SETLIMITTEXT, (WPARAM)(sizeof(s_szCompHex) - 1), 0);

   if (hwndParent != NULL)
   {
      EnableWindow(hwndParent, FALSE);
   }
   ShowWindow(hDlg, SW_SHOW);
   SetFocus(hHex);
   UpdateWindow(hDlg);

   while ((s_bCompDone == FALSE) && (GetMessageA(&msg, NULL, 0, 0) > 0))
   {
      if (msg.message == WM_QUIT)
      {
         s_bCompDone = TRUE;
         s_bCompOk = FALSE;
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

   if (s_bCompOk != TRUE)
   {
      GUI_SecureClear(s_szCompHex, sizeof(s_szCompHex));
      return CK_FALSE;
   }

   DlgImp_StripHex(s_szCompHex);
   uBin = str_StringtoByteArray((CK_CHAR_PTR)s_szCompHex, (CK_ULONG)strlen(s_szCompHex));
   if (uBin != (CK_ULONG)nLen)
   {
      char szMsg[128];
      memset(szMsg, 0, sizeof(szMsg));
      _snprintf(szMsg, sizeof(szMsg) - 1,
         "Component length must be %ld bytes (got %lu).", (long)nLen, (unsigned long)uBin);
      MessageBoxA(hwndParent, szMsg, "Import component", MB_OK | MB_ICONWARNING);
      GUI_SecureClear(s_szCompHex, sizeof(s_szCompHex));
      return CK_FALSE;
   }
   memcpy(pOut, s_szCompHex, (size_t)nLen);
   GUI_SecureClear(s_szCompHex, sizeof(s_szCompHex));
   return CK_TRUE;
}

static void DlgImp_FillTemplate(P11_UNWRAPTEMPLATE* pTpl)
{
   memset(pTpl, 0, sizeof(*pTpl));
   pTpl->pKeyLabel = (CK_CHAR_PTR)s_szLabel;
   pTpl->bCKA_Token = DlgImp_IsChecked(s_hToken);
   pTpl->bCKA_Private = DlgImp_IsChecked(s_hPrivate);
   pTpl->bCKA_Sensitive = DlgImp_IsChecked(s_hSensitive);
   pTpl->bCKA_Extractable = DlgImp_IsChecked(s_hExtractable);
   pTpl->bCKA_Encrypt = DlgImp_IsChecked(s_hEncrypt);
   pTpl->bCKA_Decrypt = DlgImp_IsChecked(s_hDecrypt);
   pTpl->bCKA_Sign = DlgImp_IsChecked(s_hSign);
   pTpl->bCKA_Verify = DlgImp_IsChecked(s_hVerify);
   pTpl->bCKA_Wrap = DlgImp_IsChecked(s_hWrap);
   pTpl->bCKA_Unwrap = DlgImp_IsChecked(s_hUnwrapCka);
   pTpl->bCKA_Derive = DlgImp_IsChecked(s_hDerive);
   pTpl->bCKA_Modifiable = DlgImp_IsChecked(s_hModifiable);
   pTpl->bCKA_Encapsulate = DlgImp_IsChecked(s_hEncapsulate);
   pTpl->bCKA_Decapsulate = DlgImp_IsChecked(s_hDecapsulate);
}

static CK_BBOOL DlgImp_DoComponents(P11_UNWRAPTEMPLATE* pTpl)
{
   CK_LONG nComp;
   CK_LONG sLoop;
   CK_LONG sKeyLength;
   CK_BYTE_PTR pbComp = NULL;
   CK_BYTE_PTR pbKey = NULL;
   CK_BYTE_PTR pbCopy = NULL;
   CK_OBJECT_HANDLE hWrapKey = 0;
   CK_OBJECT_HANDLE hKey = 0;
   CK_BYTE_PTR pKcv = NULL;
   CK_BBOOL bError = CK_FALSE;
   char szMsg[192];

   nComp = DlgImp_CompCount();
   sKeyLength = pTpl->skeySize;
   if ((nComp < 2) || (sKeyLength <= 0))
   {
      DlgImp_SetStatus("Component import needs a component count and key size.");
      return CK_FALSE;
   }

   hWrapKey = P11_GenerateAESWrapKey(CK_FALSE, AES_256_KEY_LENGTH, "AES_KEY_WRAP_KEY_COMP");
   pbComp = (CK_BYTE_PTR)malloc((size_t)sKeyLength);
   pbKey = (CK_BYTE_PTR)malloc((size_t)sKeyLength);
   pbCopy = (CK_BYTE_PTR)malloc((size_t)sKeyLength);
   if ((hWrapKey == 0) || (pbComp == NULL) || (pbKey == NULL) || (pbCopy == NULL))
   {
      DlgImp_SetStatus("Failed to start component import.");
      bError = CK_TRUE;
   }
   else
   {
      memset(pbKey, 0, (size_t)sKeyLength);
      for (sLoop = 1; sLoop <= nComp; )
      {
         P11_UNWRAPTEMPLATE sCompTpl;
         CK_BBOOL bAsk;

         bAsk = DlgImp_AskComponent(s_hDlg, sLoop, nComp, sKeyLength, pbComp);
         if (bAsk != CK_TRUE)
         {
            if (s_bCompOk != TRUE)
            {
               DlgImp_SetStatus("Component import cancelled.");
               bError = CK_TRUE;
               break;
            }
            continue;
         }
         if (pTpl->skeyType != CKK_AES)
         {
            str_ByteArrayComputeParityBit((CK_CHAR_PTR)pbComp, sKeyLength);
         }
         str_ByteArrayXOR((CK_CHAR_PTR)pbKey, (CK_CHAR_PTR)pbComp, (CK_ULONG)sKeyLength);
         memcpy(pbCopy, pbComp, (size_t)sKeyLength);

         memset(&sCompTpl, 0, sizeof(sCompTpl));
         sCompTpl.sClass = pTpl->sClass;
         sCompTpl.skeyType = pTpl->skeyType;
         sCompTpl.skeySize = pTpl->skeySize;
         sCompTpl.pKeyLabel = "";
         sCompTpl.bCKA_Sign = CK_TRUE;
         sCompTpl.bCKA_Verify = CK_TRUE;
         sCompTpl.bCKA_Token = CK_FALSE;
         sCompTpl.bCKA_Sensitive = CK_TRUE;
         sCompTpl.bCKA_Private = CK_TRUE;
         sCompTpl.hWrappingKey = hWrapKey;
         hKey = P11_ImportClearSymetricKey(&sCompTpl, (CK_CHAR_PTR)pbCopy, (CK_ULONG)sKeyLength);
         GUI_SecureClear(pbCopy, (unsigned int)sKeyLength);
         GUI_SecureClear(pbComp, (unsigned int)sKeyLength);
         if (hKey == 0)
         {
            DlgImp_SetStatus("Failed to load a component for KCV.");
            bError = CK_TRUE;
            break;
         }
         pKcv = NULL;
         if (P11_ComputeKCV(KCV_PCI, hKey, &pKcv) != CK_TRUE)
         {
            P11_DeleteObject(hKey);
            DlgImp_SetStatus("Failed to compute component KCV.");
            bError = CK_TRUE;
            break;
         }
         P11_DeleteObject(hKey);
         hKey = 0;

         memset(szMsg, 0, sizeof(szMsg));
         _snprintf(szMsg, sizeof(szMsg) - 1,
            "Component %ld KCV (PCI): %02X%02X%02X\nContinue?",
            (long)sLoop,
            (unsigned char)pKcv[0], (unsigned char)pKcv[1], (unsigned char)pKcv[2]);
         free(pKcv);
         pKcv = NULL;
         if (MessageBoxA(s_hDlg, szMsg, "Import component", MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
         {
            DlgImp_SetStatus("Component import cancelled.");
            bError = CK_TRUE;
            break;
         }
         sLoop++;
      }
   }

   if (bError != CK_TRUE)
   {
      if (pTpl->skeyType != CKK_AES)
      {
         str_ByteArrayComputeParityBit((CK_CHAR_PTR)pbKey, sKeyLength);
      }
      pTpl->hWrappingKey = hWrapKey;
      hKey = P11_ImportClearSymetricKey(pTpl, (CK_CHAR_PTR)pbKey, (CK_ULONG)sKeyLength);
      if (hKey == 0)
      {
         DlgImp_SetStatus("Failed to import the combined key.");
         bError = CK_TRUE;
      }
      else
      {
         pKcv = NULL;
         memset(szMsg, 0, sizeof(szMsg));
         if (P11_ComputeKCV(KCV_PCI, hKey, &pKcv) == CK_TRUE)
         {
            _snprintf(szMsg, sizeof(szMsg) - 1,
               "Imported handle %lu. KCV (PCI): %02X%02X%02X",
               (unsigned long)hKey,
               (unsigned char)pKcv[0], (unsigned char)pKcv[1], (unsigned char)pKcv[2]);
            free(pKcv);
         }
         else
         {
            _snprintf(szMsg, sizeof(szMsg) - 1, "Imported handle %lu.", (unsigned long)hKey);
         }
         DlgImp_SetStatus(szMsg);
         GUI_SetLastObjectHandle(hKey);
      }
   }

   if (pbComp != NULL)
   {
      GUI_SecureClear(pbComp, (unsigned int)sKeyLength);
      free(pbComp);
   }
   if (pbKey != NULL)
   {
      GUI_SecureClear(pbKey, (unsigned int)sKeyLength);
      free(pbKey);
   }
   if (pbCopy != NULL)
   {
      GUI_SecureClear(pbCopy, (unsigned int)sKeyLength);
      free(pbCopy);
   }
   if (hWrapKey != 0)
   {
      P11_DeleteObject(hWrapKey);
   }
   return (bError == CK_TRUE) ? CK_FALSE : CK_TRUE;
}

static void DlgImp_DoImport(void)
{
   P11_UNWRAPTEMPLATE tpl;
   const char* pType;
   const char* pClass;
   const char* pAlgo;
   const char* pHash;
   char szPath[GUI_PATH_MAX];
   char szIv[80];
   char szAad[520];
   char szTag[32];
   char szErr[P11_QUERY_ERR_MAX];
   char szStatus[GUI_STATUS_TEXT_MAX];
   CK_BYTE fmt;
   CK_ULONG tagBits = 0;
   CK_OBJECT_HANDLE hKey = 0;
   CK_LONG nIdLen;

   memset(s_szLabel, 0, sizeof(s_szLabel));
   GetWindowTextA(s_hLabel, s_szLabel, sizeof(s_szLabel));
   if (s_szLabel[0] == 0)
   {
      DlgImp_SetStatus("Label is required.");
      return;
   }

   pType = DlgImp_ComboName(s_hType);
   if (pType == NULL)
   {
      DlgImp_SetStatus("Select a key type.");
      return;
   }

   DlgImp_FillTemplate(&tpl);
   tpl.skeyType = P11Util_GetCKType((CK_CHAR_PTR)pType, KEY_TYPE_IMPORT_EXPORTKEY);
   if ((CK_ULONG)tpl.skeyType == (CK_ULONG)-1)
   {
      DlgImp_SetStatus("Unknown key type.");
      return;
   }

   memset(s_szCkaId, 0, sizeof(s_szCkaId));
   GetWindowTextA(s_hId, s_szCkaId, sizeof(s_szCkaId));
   DlgImp_StripHex(s_szCkaId);
   if (s_szCkaId[0] != 0)
   {
      nIdLen = (CK_LONG)str_StringtoByteArray((CK_CHAR_PTR)s_szCkaId, (CK_ULONG)strlen(s_szCkaId));
      if (nIdLen <= 0)
      {
         DlgImp_SetStatus("CKA_ID must be hexadecimal.");
         return;
      }
      tpl.pCKA_ID = (CK_CHAR_PTR)s_szCkaId;
      tpl.uCKA_ID_Length = (CK_ULONG)nIdLen;
   }

   if (DlgImp_IsComponents() != FALSE)
   {
      tpl.sClass = CKO_SECRET_KEY;
      switch (tpl.skeyType)
      {
      case CKK_AES:
         tpl.skeySize = DlgImp_SizeBytes();
         if ((tpl.skeySize != AES_128_KEY_LENGTH) && (tpl.skeySize != AES_192_KEY_LENGTH) &&
            (tpl.skeySize != AES_256_KEY_LENGTH))
         {
            DlgImp_SetStatus("AES component import needs size 16, 24, or 32.");
            return;
         }
         break;
      case CKK_DES:
         tpl.skeySize = DES_KEY_LENGTH;
         break;
      case CKK_DES2:
         tpl.skeySize = DES2_KEY_LENGTH;
         break;
      case CKK_DES3:
         tpl.skeySize = DES3_KEY_LENGTH;
         break;
      default:
         DlgImp_SetStatus("Component import supports AES and DES keys only.");
         return;
      }
      DlgImp_DoComponents(&tpl);
      return;
   }

   pClass = DlgImp_ComboName(s_hClass);
   tpl.sClass = P11Util_GetClass((CK_CHAR_PTR)pClass);
   if ((pClass == NULL) || ((CK_ULONG)tpl.sClass == (CK_ULONG)-1))
   {
      DlgImp_SetStatus("Select a key class.");
      return;
   }

   memset(szPath, 0, sizeof(szPath));
   GetWindowTextA(s_hFile, szPath, sizeof(szPath));
   if (szPath[0] == 0)
   {
      DlgImp_SetStatus("Choose an input file.");
      return;
   }

   fmt = DlgImp_Format();
   memset(szIv, 0, sizeof(szIv));
   memset(szAad, 0, sizeof(szAad));
   memset(szTag, 0, sizeof(szTag));
   memset(s_szPassword, 0, sizeof(s_szPassword));
   GetWindowTextA(s_hIv, szIv, sizeof(szIv));
   GetWindowTextA(s_hAad, szAad, sizeof(szAad));
   GetWindowTextA(s_hTag, szTag, sizeof(szTag));
   GetWindowTextA(s_hPassword, s_szPassword, sizeof(s_szPassword));
   if (szTag[0] != 0)
   {
      tagBits = (CK_ULONG)strtoul(szTag, NULL, 10);
   }
   pAlgo = DlgImp_ComboName(s_hAlgo);
   pHash = DlgImp_ComboName(s_hHash);
   memset(&s_mech, 0, sizeof(s_mech));

   if (tpl.sClass != CKO_PUBLIC_KEY)
   {
      if (fmt == P11_FILE_FORMAT_PKCS8)
      {
         tpl.bPbe = CK_TRUE;
      }
      else if (fmt != P11_FILE_FORMAT_TR31)
      {
         tpl.hWrappingKey = GUI_ResolveKeyFromEdits(s_hUnwrap, s_hUnwrapLabel, s_hUnwrapId,
            szErr, sizeof(szErr));
         if (tpl.hWrappingKey == 0)
         {
            DlgImp_SetStatus(szErr[0] != 0 ? szErr : "Enter an unwrap key handle, label, or CKA_ID.");
            GUI_SecureClear(s_szPassword, sizeof(s_szPassword));
            return;
         }
         if (P11_QueryBuildWrapMech(pAlgo, KEY_TYPE_IMPORT_EXPORTKEY, szIv, szAad, tagBits, pHash,
            &s_mech, s_ivBuf, sizeof(s_ivBuf), s_aadBuf, sizeof(s_aadBuf),
            szErr, sizeof(szErr)) != CK_TRUE)
         {
            DlgImp_SetStatus(szErr[0] != 0 ? szErr : "Invalid unwrap algorithm.");
            GUI_SecureClear(s_szPassword, sizeof(s_szPassword));
            return;
         }
         tpl.wrapmech = &s_mech;
         if (s_mech.ckMechType == CKM_AES_KW)
         {
            tpl.skeySize = DlgImp_SizeBytes();
         }
      }
      else
      {
         tpl.hWrappingKey = GUI_ResolveKeyFromEdits(s_hUnwrap, s_hUnwrapLabel, s_hUnwrapId,
            szErr, sizeof(szErr));
         if (tpl.hWrappingKey == 0)
         {
            DlgImp_SetStatus(szErr[0] != 0 ? szErr : "Enter an unwrap key handle, label, or CKA_ID.");
            GUI_SecureClear(s_szPassword, sizeof(s_szPassword));
            return;
         }
      }
   }

   DlgImp_SetStatus("Importing...");
   UpdateWindow(s_hStatus);
   if (P11_QueryImportKey(&tpl, szPath, fmt, s_szPassword, &hKey, szErr, sizeof(szErr)) != CK_TRUE)
   {
      DlgImp_SetStatus(szErr[0] != 0 ? szErr : "Import failed.");
      GUI_SecureClear(s_szPassword, sizeof(s_szPassword));
      return;
   }
   memset(szStatus, 0, sizeof(szStatus));
   if (hKey != 0)
   {
      _snprintf(szStatus, sizeof(szStatus) - 1, "Imported. Handle %lu, label %s.",
         (unsigned long)hKey, s_szLabel);
      GUI_SetLastObjectHandle(hKey);
   }
   else
   {
      _snprintf(szStatus, sizeof(szStatus) - 1, "Imported. Label %s.", s_szLabel);
   }
   DlgImp_SetStatus(szStatus);
   GUI_SecureClear(s_szPassword, sizeof(s_szPassword));
}

static HWND DlgImp_Label(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("STATIC", sText, WS_CHILD | WS_VISIBLE,
      0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static HWND DlgImp_Check(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("BUTTON", sText,
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
      0, 0, 90, 18, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static void DlgImp_Layout(int cx, int cy)
{
   int y;
   int fieldX;
   int fieldW;
   int browseX;
   int rowH = DLG_EDIT_H + 7;
   int flagY;
   int i;
   HWND hFlags[14];
   int nFlag;

   if (cx < 480)
   {
      cx = 480;
   }
   fieldX = DLG_MARGIN + DLG_LABEL_W + 8;
   browseX = cx - DLG_MARGIN - DLG_BROWSE_W;
   fieldW = browseX - 8 - fieldX;
   if (fieldW < 80)
   {
      fieldW = 80;
   }

   y = DLG_MARGIN;
   MoveWindow(s_hFileMode, DLG_MARGIN, y, 70, 18, TRUE);
   MoveWindow(s_hCompMode, DLG_MARGIN + 80, y, 110, 18, TRUE);

   y += 26;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_LABEL), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hLabel, fieldX, y, fieldW + DLG_BROWSE_W + 8, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_TYPE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hType, fieldX, y, 160, DLG_COMBO_DROP, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_CLASS), fieldX + 172, y + 3, 40, 16, TRUE);
   MoveWindow(s_hClass, fieldX + 216, y, 100, DLG_COMBO_DROP, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_SIZE), fieldX + 328, y + 3, 36, 16, TRUE);
   MoveWindow(s_hSize, fieldX + 366, y, 130, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_FILE), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hFile, fieldX, y, fieldW, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_BROWSE), browseX, y, DLG_BROWSE_W, DLG_BTN_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_FORMAT), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hFormat, fieldX, y, 140, DLG_COMBO_DROP, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_COMPN), fieldX + 160, y + 3, 80, 16, TRUE);
   MoveWindow(s_hCompN, fieldX + 244, y, 60, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_UNWRAP), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hUnwrap, fieldX, y, 72, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_UNWRAP_LABEL), fieldX + 80, y + 3, 40, 16, TRUE);
   MoveWindow(s_hUnwrapLabel, fieldX + 120, y, 160, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_UNWRAP_ID), fieldX + 288, y + 3, 22, 16, TRUE);
   MoveWindow(s_hUnwrapId, fieldX + 312, y, 140, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_ALGO), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hAlgo, fieldX, y, 220, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_IV), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hIv, fieldX, y, fieldW + DLG_BROWSE_W + 8, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_AAD), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hAad, fieldX, y, fieldW + DLG_BROWSE_W + 8, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_TAG), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hTag, fieldX, y, 80, DLG_EDIT_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_HASH), fieldX + 100, y + 3, 80, 16, TRUE);
   MoveWindow(s_hHash, fieldX + 184, y, 140, DLG_COMBO_DROP, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_PASSWORD), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hPassword, fieldX, y, 220, DLG_EDIT_H, TRUE);

   y += rowH;
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_LBL_ID), DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
   MoveWindow(s_hId, fieldX, y, fieldW + DLG_BROWSE_W + 8, DLG_EDIT_H, TRUE);

   y += rowH + 4;
   hFlags[0] = s_hToken;
   hFlags[1] = s_hPrivate;
   hFlags[2] = s_hSensitive;
   hFlags[3] = s_hExtractable;
   hFlags[4] = s_hEncrypt;
   hFlags[5] = s_hDecrypt;
   hFlags[6] = s_hSign;
   hFlags[7] = s_hVerify;
   hFlags[8] = s_hWrap;
   hFlags[9] = s_hUnwrapCka;
   hFlags[10] = s_hDerive;
   hFlags[11] = s_hModifiable;
   hFlags[12] = s_hEncapsulate;
   hFlags[13] = s_hDecapsulate;
   nFlag = 14;
   flagY = y;
   for (i = 0; i < nFlag; i++)
   {
      int col = i % 7;
      int row = i / 7;
      MoveWindow(hFlags[i], DLG_MARGIN + (col * 86), flagY + (row * 22), 82, 18, TRUE);
   }

   y = cy - DLG_MARGIN - DLG_BTN_H;
   MoveWindow(s_hStatus, DLG_MARGIN, y - 26, cx - (2 * DLG_MARGIN), 18, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_GO), cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, y, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_IMP_CLOSE), cx - DLG_MARGIN - DLG_BTN_W, y, DLG_BTN_W, DLG_BTN_H, TRUE);
}

static LRESULT CALLBACK DlgImp_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      {
         HWND hCtrl;
         CK_OBJECT_HANDLE hLast;
         char szHandle[32];
         int iN;
         int iItem;

         s_hDlg = hWnd;
         s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

         s_hFileMode = CreateWindowA("BUTTON", "File",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTORADIOBUTTON | WS_GROUP,
            0, 0, 70, 18, hWnd, (HMENU)(INT_PTR)IDC_IMP_FILEMODE, NULL, NULL);
         s_hCompMode = CreateWindowA("BUTTON", "Components",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTORADIOBUTTON,
            0, 0, 110, 18, hWnd, (HMENU)(INT_PTR)IDC_IMP_COMPMODE, NULL, NULL);
         SendMessageA(s_hFileMode, BM_SETCHECK, BST_CHECKED, 0);

         DlgImp_Label(hWnd, "Label:", IDC_IMP_LBL_LABEL);
         s_hLabel = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_LABEL, NULL, NULL);
         DlgImp_Label(hWnd, "Key type:", IDC_IMP_LBL_TYPE);
         s_hType = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 160, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_IMP_TYPE, NULL, NULL);
         DlgImp_Label(hWnd, "Class:", IDC_IMP_LBL_CLASS);
         s_hClass = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 100, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_IMP_CLASS, NULL, NULL);
         DlgImp_Label(hWnd, "Size:", IDC_IMP_LBL_SIZE);
         s_hSize = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 130, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_IMP_SIZE, NULL, NULL);
         DlgImp_Label(hWnd, "Input file:", IDC_IMP_LBL_FILE);
         s_hFile = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_FILE, NULL, NULL);
         CreateWindowA("BUTTON", "Browse...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BROWSE_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_BROWSE, NULL, NULL);
         DlgImp_Label(hWnd, "Format:", IDC_IMP_LBL_FORMAT);
         s_hFormat = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 140, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_IMP_FORMAT, NULL, NULL);
         DlgImp_Label(hWnd, "Components:", IDC_IMP_LBL_COMPN);
         s_hCompN = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 60, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_IMP_COMPN, NULL, NULL);
         DlgImp_Label(hWnd, "Unwrap key:", IDC_IMP_LBL_UNWRAP);
         s_hUnwrap = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 72, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_UNWRAP, NULL, NULL);
         DlgImp_Label(hWnd, "Label:", IDC_IMP_LBL_UNWRAP_LABEL);
         s_hUnwrapLabel = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 160, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_UNWRAP_LABEL, NULL, NULL);
         DlgImp_Label(hWnd, "ID:", IDC_IMP_LBL_UNWRAP_ID);
         s_hUnwrapId = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 140, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_UNWRAP_ID, NULL, NULL);
         DlgImp_Label(hWnd, "Algorithm:", IDC_IMP_LBL_ALGO);
         s_hAlgo = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 220, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_IMP_ALGO, NULL, NULL);
         DlgImp_Label(hWnd, "IV (hex):", IDC_IMP_LBL_IV);
         s_hIv = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_IV, NULL, NULL);
         DlgImp_Label(hWnd, "GCM AAD:", IDC_IMP_LBL_AAD);
         s_hAad = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_AAD, NULL, NULL);
         DlgImp_Label(hWnd, "Tag bits:", IDC_IMP_LBL_TAG);
         s_hTag = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 80, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_TAG, NULL, NULL);
         DlgImp_Label(hWnd, "OAEP hash:", IDC_IMP_LBL_HASH);
         s_hHash = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
            0, 0, 140, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)IDC_IMP_HASH, NULL, NULL);
         DlgImp_Label(hWnd, "Password:", IDC_IMP_LBL_PASSWORD);
         s_hPassword = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            0, 0, 220, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_PASSWORD, NULL, NULL);
         DlgImp_Label(hWnd, "CKA_ID:", IDC_IMP_LBL_ID);
         s_hId = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_ID, NULL, NULL);

         s_hToken = DlgImp_Check(hWnd, "Token", IDC_IMP_TOKEN);
         s_hPrivate = DlgImp_Check(hWnd, "Private", IDC_IMP_PRIVATE);
         s_hSensitive = DlgImp_Check(hWnd, "Sensitive", IDC_IMP_SENSITIVE);
         s_hExtractable = DlgImp_Check(hWnd, "Extractable", IDC_IMP_EXTRACTABLE);
         s_hEncrypt = DlgImp_Check(hWnd, "Encrypt", IDC_IMP_ENCRYPT);
         s_hDecrypt = DlgImp_Check(hWnd, "Decrypt", IDC_IMP_DECRYPT);
         s_hSign = DlgImp_Check(hWnd, "Sign", IDC_IMP_SIGN);
         s_hVerify = DlgImp_Check(hWnd, "Verify", IDC_IMP_VERIFY);
         s_hWrap = DlgImp_Check(hWnd, "Wrap", IDC_IMP_WRAP);
         s_hUnwrapCka = DlgImp_Check(hWnd, "Unwrap", IDC_IMP_UNWRAPCKA);
         s_hDerive = DlgImp_Check(hWnd, "Derive", IDC_IMP_DERIVE);
         s_hModifiable = DlgImp_Check(hWnd, "Modifiable", IDC_IMP_MODIFIABLE);
         s_hEncapsulate = DlgImp_Check(hWnd, "Encapsulate", IDC_IMP_ENCAPSULATE);
         s_hDecapsulate = DlgImp_Check(hWnd, "Decapsulate", IDC_IMP_DECAPSULATE);

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 200, 18, hWnd, (HMENU)(INT_PTR)IDC_IMP_STATUS, NULL, NULL);
         CreateWindowA("BUTTON", "Import",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_GO, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_IMP_CLOSE, NULL, NULL);

         SendMessageA(s_hLabel, EM_SETLIMITTEXT, DLG_MAX_LABEL - 1, 0);
         SendMessageA(s_hFile, EM_SETLIMITTEXT, GUI_PATH_MAX - 1, 0);
         SendMessageA(s_hPassword, EM_SETLIMITTEXT, DLG_PW_MAX - 1, 0);
         SendMessageA(s_hId, EM_SETLIMITTEXT, (DLG_CKA_ID_MAX * 2) - 1, 0);

         SendMessageA(s_hToken, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hPrivate, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hSensitive, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hExtractable, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hModifiable, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hEncrypt, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hDecrypt, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hSign, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hVerify, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hWrap, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hUnwrapCka, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hDerive, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hEncapsulate, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hDecapsulate, BM_SETCHECK, BST_CHECKED, 0);

         for (iN = 2; iN <= 16; iN++)
         {
            char szN[8];
            memset(szN, 0, sizeof(szN));
            _snprintf(szN, sizeof(szN) - 1, "%d", iN);
            iItem = (int)SendMessageA(s_hCompN, CB_ADDSTRING, 0, (LPARAM)szN);
            SendMessageA(s_hCompN, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)iN);
         }
         SendMessageA(s_hCompN, CB_SETCURSEL, 0, 0);

         DlgImp_FillTypes();
         DlgImp_FillClasses();
         DlgImp_FillSize();
         DlgImp_FillFormat();
         DlgImp_FillAlgos();
         DlgImp_FillHash();
         DlgImp_SyncClassFromType();

         hLast = GUI_GetLastObjectHandle();
         if (hLast != 0)
         {
            memset(szHandle, 0, sizeof(szHandle));
            _snprintf(szHandle, sizeof(szHandle) - 1, "%lu", (unsigned long)hLast);
            SetWindowTextA(s_hUnwrap, szHandle);
         }

         for (hCtrl = GetWindow(hWnd, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
         {
            SendMessageA(hCtrl, WM_SETFONT, (WPARAM)s_hFont, TRUE);
         }
         GUI_ThemeMarkStatus(s_hStatus);
         DlgImp_UpdateFields();
         DlgImp_SetStatus("File unwrap needs an unwrap key with CKA_UNWRAP. PKCS#8 private keys need a password.");
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
      DlgImp_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 640;
         pMin->ptMinTrackSize.y = 620;
      }
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_IMP_FILEMODE:
      case IDC_IMP_COMPMODE:
         DlgImp_UpdateFields();
         return 0;
      case IDC_IMP_TYPE:
         if (HIWORD(wParam) == CBN_SELCHANGE)
         {
            DlgImp_SyncClassFromType();
            DlgImp_UpdateFields();
         }
         return 0;
      case IDC_IMP_CLASS:
      case IDC_IMP_FORMAT:
      case IDC_IMP_ALGO:
         if (HIWORD(wParam) == CBN_SELCHANGE)
         {
            DlgImp_UpdateFields();
         }
         return 0;
      case IDC_IMP_BROWSE:
         {
            char szPath[GUI_PATH_MAX];
            if (DlgImp_PickFile(szPath, sizeof(szPath)) != FALSE)
            {
               SetWindowTextA(s_hFile, szPath);
            }
         }
         return 0;
      case IDC_IMP_GO:
      case IDOK:
         DlgImp_DoImport();
         return 0;
      case IDC_IMP_CLOSE:
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
      GUI_SecureClear(s_szCkaId, sizeof(s_szCkaId));
      s_hDlg = NULL;
      s_hFileMode = NULL;
      s_hCompMode = NULL;
      s_hLabel = NULL;
      s_hType = NULL;
      s_hClass = NULL;
      s_hSize = NULL;
      s_hFile = NULL;
      s_hFormat = NULL;
      s_hUnwrap = NULL;
      s_hUnwrapLabel = NULL;
      s_hUnwrapId = NULL;
      s_hAlgo = NULL;
      s_hIv = NULL;
      s_hAad = NULL;
      s_hTag = NULL;
      s_hHash = NULL;
      s_hPassword = NULL;
      s_hCompN = NULL;
      s_hId = NULL;
      s_hStatus = NULL;
      s_hToken = NULL;
      s_hPrivate = NULL;
      s_hSensitive = NULL;
      s_hExtractable = NULL;
      s_hEncrypt = NULL;
      s_hDecrypt = NULL;
      s_hSign = NULL;
      s_hVerify = NULL;
      s_hWrap = NULL;
      s_hUnwrapCka = NULL;
      s_hDerive = NULL;
      s_hModifiable = NULL;
      s_hEncapsulate = NULL;
      s_hDecapsulate = NULL;
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }
   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

void DlgImport_Show(HWND hwndParent)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgImp_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_IMP_CLASS;
   RegisterClassExA(&wc);

   s_bDone = FALSE;
   if (hwndParent != NULL)
   {
      GetWindowRect(hwndParent, &rc);
   }
   else
   {
      rc.left = 140;
      rc.top = 40;
   }

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_IMP_CLASS,
      "Import key",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 24, rc.top + 24, 700, 680,
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
