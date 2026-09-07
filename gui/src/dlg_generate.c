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

#define _DLG_GENERATE_C

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
#include "str.h"
#include "gui.h"
#include "gui_theme.h"
#include "dlg_generate.h"

#define DLG_GEN_CLASS             "LunaKmuGenerate"
#define DLG_COMP_CLASS            "LunaKmuGenComp"
#define DLG_MARGIN                12
#define DLG_BTN_W                 88
#define DLG_BTN_H                 24
#define DLG_EDIT_H                22
#define DLG_LABEL_W               78
#define DLG_MAX_LABEL             100
#define DLG_HEX_MAX               8192
#define DLG_CKA_ID_MAX            4096
#define DLG_COMBO_DROP            240
#define WM_GEN_READY              (WM_APP + 20)

#define IDC_GEN_TYPE              2101
#define IDC_GEN_LABEL             2102
#define IDC_GEN_PARAM             2103
#define IDC_GEN_LBL_PARAM         2104
#define IDC_GEN_TOKEN             2105
#define IDC_GEN_PRIVATE           2106
#define IDC_GEN_SENSITIVE         2107
#define IDC_GEN_EXTRACTABLE       2108
#define IDC_GEN_GENERATE          2109
#define IDC_GEN_CLOSE             2110
#define IDC_GEN_STATUS            2111
#define IDC_GEN_LBL_TYPE          2112
#define IDC_GEN_LBL_LABEL         2113
#define IDC_GEN_LBL_PUB           2114
#define IDC_GEN_LABEL_PUB         2115
#define IDC_GEN_LBL_PRIV          2116
#define IDC_GEN_LABEL_PRIV        2117
#define IDC_GEN_LBL_ID            2118
#define IDC_GEN_ID                2119
#define IDC_GEN_LBL_MECH          2120
#define IDC_GEN_MECH              2121
#define IDC_GEN_LBL_EXP           2122
#define IDC_GEN_EXP               2123
#define IDC_GEN_LBL_PRIME         2124
#define IDC_GEN_PRIME             2125
#define IDC_GEN_LBL_BASE          2126
#define IDC_GEN_BASE              2127
#define IDC_GEN_LBL_SUB           2128
#define IDC_GEN_SUBPRIME          2129
#define IDC_GEN_LBL_LEVEL         2130
#define IDC_GEN_LEVEL             2131
#define IDC_GEN_LBL_COMP          2132
#define IDC_GEN_COMP              2133
#define IDC_GEN_ENCRYPT           2134
#define IDC_GEN_DECRYPT           2135
#define IDC_GEN_SIGN              2136
#define IDC_GEN_VERIFY            2137
#define IDC_GEN_WRAP              2138
#define IDC_GEN_UNWRAP            2139
#define IDC_GEN_DERIVE            2140
#define IDC_GEN_MODIFIABLE        2141
#define IDC_GEN_ENCAPSULATE       2142
#define IDC_GEN_DECAPSULATE       2143
#define IDC_GEN_LMS               2200
#define IDC_GEN_LMOTS             2210
#define IDC_GEN_LBL_LMS           2220
#define IDC_GEN_LBL_LMOTS         2230
#define IDC_COMP_HEX              2301
#define IDC_COMP_KCV              2302
#define IDC_COMP_NEXT             2303
#define IDC_COMP_CANCEL           2304
#define IDC_COMP_COPY             2305
#define IDC_COMP_STATUS           2306

typedef enum
{
   GEN_KIND_NONE = 0,
   GEN_KIND_AES,
   GEN_KIND_DES,
   GEN_KIND_SM4,
   GEN_KIND_HMAC,
   GEN_KIND_RSA,
   GEN_KIND_CURVE,
   GEN_KIND_DH,
   GEN_KIND_DSA,
   GEN_KIND_MLDSA,
   GEN_KIND_MLKEM,
   GEN_KIND_LMS,
   GEN_KIND_HSS
} GEN_KIND;

static HWND s_hDlg = NULL;
static HWND s_hType = NULL;
static HWND s_hLabel = NULL;
static HWND s_hLabelPub = NULL;
static HWND s_hLabelPriv = NULL;
static HWND s_hId = NULL;
static HWND s_hParam = NULL;
static HWND s_hLblParam = NULL;
static HWND s_hMech = NULL;
static HWND s_hLblMech = NULL;
static HWND s_hExp = NULL;
static HWND s_hLblExp = NULL;
static HWND s_hPrime = NULL;
static HWND s_hBase = NULL;
static HWND s_hSubprime = NULL;
static HWND s_hLevel = NULL;
static HWND s_hComp = NULL;
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
static HWND s_hUnwrap = NULL;
static HWND s_hDerive = NULL;
static HWND s_hModifiable = NULL;
static HWND s_hEncapsulate = NULL;
static HWND s_hDecapsulate = NULL;
static HWND s_hLms[MAX_HSS_LEVEL];
static HWND s_hLmots[MAX_HSS_LEVEL];
static HWND s_hLblLms[MAX_HSS_LEVEL];
static HWND s_hLblLmots[MAX_HSS_LEVEL];
static HFONT s_hFont = NULL;
static BOOL s_bDone = FALSE;
static char s_szParamTyped[80];
static char s_szMechTyped[32];
static char s_szExpTyped[32];
/* Holds the typed hex string (2 chars per byte), converted in place to binary. */
static char s_szCkaId[(DLG_CKA_ID_MAX * 2) + 2];
static P11_EXP_DOMAIN s_domain;

static BOOL s_bCompDone = FALSE;
static BOOL s_bCompOk = FALSE;
static HWND s_hCompDlg = NULL;

static void DlgGenerate_SetStatus(const char* sText)
{
   if (s_hStatus != NULL)
   {
      SetWindowTextA(s_hStatus, (sText != NULL) ? sText : "");
   }
}

static CK_BBOOL DlgGenerate_IsChecked(HWND hChk)
{
   return (SendMessageA(hChk, BM_GETCHECK, 0, 0) == BST_CHECKED) ? CK_TRUE : CK_FALSE;
}

static const char* DlgGenerate_CurrentCliName(void)
{
   int iSel = (int)SendMessageA(s_hType, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel < 0)
   {
      return NULL;
   }
   data = SendMessageA(s_hType, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if ((data == 0) || (data == CB_ERR))
   {
      return NULL;
   }
   return (const char*)data;
}

static GEN_KIND DlgGenerate_KindFromName(const char* pName)
{
   if (pName == NULL)
   {
      return GEN_KIND_NONE;
   }
   if (strcmp(pName, "aes") == 0)
   {
      return GEN_KIND_AES;
   }
   if (strcmp(pName, "des") == 0)
   {
      return GEN_KIND_DES;
   }
   if (strcmp(pName, "sm4") == 0)
   {
      return GEN_KIND_SM4;
   }
   if ((strcmp(pName, "hmac") == 0) || (strcmp(pName, "genericsecret") == 0))
   {
      return GEN_KIND_HMAC;
   }
   if (strcmp(pName, "rsa") == 0)
   {
      return GEN_KIND_RSA;
   }
   if ((strcmp(pName, "ecdsa") == 0) || (strcmp(pName, "eddsa") == 0) ||
      (strcmp(pName, "montgomery") == 0) || (strcmp(pName, "sm2") == 0))
   {
      return GEN_KIND_CURVE;
   }
   if (strcmp(pName, "dh") == 0)
   {
      return GEN_KIND_DH;
   }
   if (strcmp(pName, "dsa") == 0)
   {
      return GEN_KIND_DSA;
   }
   if (strcmp(pName, "ml-dsa") == 0)
   {
      return GEN_KIND_MLDSA;
   }
   if (strcmp(pName, "ml-kem") == 0)
   {
      return GEN_KIND_MLKEM;
   }
   if (strcmp(pName, "lms") == 0)
   {
      return GEN_KIND_LMS;
   }
   if (strcmp(pName, "hss") == 0)
   {
      return GEN_KIND_HSS;
   }
   return GEN_KIND_NONE;
}

static void DlgGenerate_AddNamed(HWND hCombo, const char* sText, LPARAM data)
{
   int iItem;

   iItem = (int)SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)sText);
   if (iItem >= 0)
   {
      SendMessageA(hCombo, CB_SETITEMDATA, (WPARAM)iItem, data);
   }
}

static void DlgGenerate_AddParam(const char* sText, LPARAM data)
{
   DlgGenerate_AddNamed(s_hParam, sText, data);
}

static const char* DlgGenerate_ComboName(HWND hCombo, char* typed, unsigned int typedSize)
{
   int iSel = (int)SendMessageA(hCombo, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel >= 0)
   {
      data = SendMessageA(hCombo, CB_GETITEMDATA, (WPARAM)iSel, 0);
      if ((data != 0) && (data != CB_ERR))
      {
         return (const char*)data;
      }
   }
   memset(typed, 0, typedSize);
   GetWindowTextA(hCombo, typed, (int)typedSize);
   if (typed[0] == 0)
   {
      return NULL;
   }
   return typed;
}

static CK_BBOOL DlgGenerate_GetParamLong(CK_LONG* pVal)
{
   char sz[40];
   char* pEnd = NULL;
   int iSel;
   LPARAM data;

   if (pVal == NULL)
   {
      return CK_FALSE;
   }
   iSel = (int)SendMessageA(s_hParam, CB_GETCURSEL, 0, 0);
   if (iSel >= 0)
   {
      data = SendMessageA(s_hParam, CB_GETITEMDATA, (WPARAM)iSel, 0);
      if ((data != CB_ERR) && ((CK_LONG)data > 0))
      {
         *pVal = (CK_LONG)data;
         return CK_TRUE;
      }
   }
   memset(sz, 0, sizeof(sz));
   GetWindowTextA(s_hParam, sz, sizeof(sz));
   *pVal = (CK_LONG)strtol(sz, &pEnd, 10);
   if ((pEnd == sz) || (*pVal <= 0))
   {
      return CK_FALSE;
   }
   return CK_TRUE;
}

static CK_LONG DlgGenerate_GetHssLevel(void)
{
   int iSel = (int)SendMessageA(s_hLevel, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel < 0)
   {
      return DEFAULT_LMS_LEVEL;
   }
   data = SendMessageA(s_hLevel, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if ((data < 1) || (data > MAX_HSS_LEVEL))
   {
      return DEFAULT_LMS_LEVEL;
   }
   return (CK_LONG)data;
}

static CK_LONG DlgGenerate_GetComponentCount(void)
{
   int iSel = (int)SendMessageA(s_hComp, CB_GETCURSEL, 0, 0);
   LPARAM data;

   if (iSel < 0)
   {
      return 0;
   }
   data = SendMessageA(s_hComp, CB_GETITEMDATA, (WPARAM)iSel, 0);
   if (data == CB_ERR)
   {
      return 0;
   }
   return (CK_LONG)data;
}

static void DlgGenerate_SelectNamed(HWND hCombo, const char* sName)
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

static HWND DlgGenerate_CreateCombo(HWND hWnd, int id, BOOL bEdit);

static void DlgGenerate_ClearComboHighlight(HWND hCombo)
{
   COMBOBOXINFO info;

   if (hCombo == NULL)
   {
      return;
   }
   memset(&info, 0, sizeof(info));
   info.cbSize = sizeof(info);
   if ((GetComboBoxInfo(hCombo, &info) != FALSE) && (info.hwndItem != NULL))
   {
      SendMessageA(info.hwndItem, EM_SETSEL, (WPARAM)-1, (LPARAM)0);
   }
   SendMessageA(hCombo, CB_SETEDITSEL, 0, MAKELPARAM(0, 0));
}

static void DlgGenerate_EnsureParamEditable(BOOL bEdit)
{
   DWORD dwStyle;
   BOOL bIsEdit;

   if (s_hParam == NULL)
   {
      return;
   }
   dwStyle = (DWORD)GetWindowLongA(s_hParam, GWL_STYLE);
   bIsEdit = ((dwStyle & 0x0003L) == CBS_DROPDOWN) ? TRUE : FALSE;
   if (bIsEdit == bEdit)
   {
      return;
   }
   DestroyWindow(s_hParam);
   s_hParam = DlgGenerate_CreateCombo(s_hDlg, IDC_GEN_PARAM, bEdit);
   if ((s_hParam != NULL) && (s_hFont != NULL))
   {
      SendMessageA(s_hParam, WM_SETFONT, (WPARAM)s_hFont, TRUE);
   }
}

static void DlgGenerate_FillParam(void)
{
   const char* pType = DlgGenerate_CurrentCliName();
   GEN_KIND kind = DlgGenerate_KindFromName(pType);
   CK_ULONG uLoop;
   CK_ULONG uCount;
   const char* pLbl = "Size:";
   BOOL bShow = TRUE;
   CK_KEY_TYPE ckType;
   int iDefault = 0;

   /* Size is a pick-list except HMAC/RSA, which still allow a typed value. */
   DlgGenerate_EnsureParamEditable((kind == GEN_KIND_HMAC) || (kind == GEN_KIND_RSA));
   SendMessageA(s_hParam, CB_RESETCONTENT, 0, 0);

   switch (kind)
   {
   case GEN_KIND_AES:
      DlgGenerate_AddParam("AES-128 (16)", AES_128_KEY_LENGTH);
      DlgGenerate_AddParam("AES-192 (24)", AES_192_KEY_LENGTH);
      DlgGenerate_AddParam("AES-256 (32)", AES_256_KEY_LENGTH);
      SendMessageA(s_hParam, CB_SETCURSEL, 2, 0);
      break;
   case GEN_KIND_DES:
      DlgGenerate_AddParam("DES (8)", DES_KEY_LENGTH);
      DlgGenerate_AddParam("2DES (16)", DES2_KEY_LENGTH);
      DlgGenerate_AddParam("3DES (24)", DES3_KEY_LENGTH);
      SendMessageA(s_hParam, CB_SETCURSEL, 0, 0);
      break;
   case GEN_KIND_HMAC:
      DlgGenerate_AddParam("8", 8);
      DlgGenerate_AddParam("16", 16);
      DlgGenerate_AddParam("32", 32);
      DlgGenerate_AddParam("64", 64);
      DlgGenerate_AddParam("128", 128);
      DlgGenerate_AddParam("256", 256);
      DlgGenerate_AddParam("512", 512);
      SendMessageA(s_hParam, CB_SETCURSEL, 2, 0);
      break;
   case GEN_KIND_RSA:
      DlgGenerate_AddParam("1024", 1024);
      DlgGenerate_AddParam("2048", 2048);
      DlgGenerate_AddParam("3072", 3072);
      DlgGenerate_AddParam("4096", 4096);
      DlgGenerate_AddParam("8192", 8192);
      SendMessageA(s_hParam, CB_SETCURSEL, 1, 0);
      break;
   case GEN_KIND_CURVE:
      pLbl = "Curve:";
      ckType = P11Util_GetCKType((CK_CHAR_PTR)pType, KEY_TYPE_GENKEY);
      uCount = P11Util_GetEcCurveCount(ckType);
      for (uLoop = 0; uLoop < uCount; uLoop++)
      {
         CK_CHAR_PTR pName = P11Util_GetEcCurveNameAt(ckType, uLoop);
         int iItem;
         if (pName == NULL)
         {
            continue;
         }
         iItem = (int)SendMessageA(s_hParam, CB_ADDSTRING, 0, (LPARAM)pName);
         if (iItem >= 0)
         {
            SendMessageA(s_hParam, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)pName);
            if ((strcmp(pType, "ecdsa") == 0) && (strcmp((const char*)pName, "secp256r1") == 0))
            {
               iDefault = iItem;
            }
            else if ((strcmp(pType, "eddsa") == 0) && (strcmp((const char*)pName, "ed25519") == 0))
            {
               iDefault = iItem;
            }
            else if ((strcmp(pType, "montgomery") == 0) && (strcmp((const char*)pName, "x25519") == 0))
            {
               iDefault = iItem;
            }
         }
      }
      SendMessageA(s_hParam, CB_SETCURSEL, iDefault, 0);
      break;
   case GEN_KIND_MLDSA:
      pLbl = "Set:";
      uCount = P11Util_GetML_DSA_Count();
      for (uLoop = 0; uLoop < uCount; uLoop++)
      {
         P11_ML_DSA_KEY* pSet = P11Util_GetML_DSA_At(uLoop);
         if (pSet != NULL)
         {
            DlgGenerate_AddParam((const char*)pSet->sName, (LPARAM)pSet->sPublicKeySize);
         }
      }
      SendMessageA(s_hParam, CB_SETCURSEL, (uCount > 1) ? 1 : 0, 0);
      break;
   case GEN_KIND_MLKEM:
      pLbl = "Set:";
      uCount = P11Util_GetML_KEM_Count();
      for (uLoop = 0; uLoop < uCount; uLoop++)
      {
         P11_ML_KEM_KEY* pSet = P11Util_GetML_KEM_At(uLoop);
         if (pSet != NULL)
         {
            DlgGenerate_AddParam((const char*)pSet->sName, (LPARAM)pSet->sPublicKeySize);
         }
      }
      SendMessageA(s_hParam, CB_SETCURSEL, (uCount > 1) ? 1 : 0, 0);
      break;
   default:
      bShow = FALSE;
      break;
   }

   SetWindowTextA(s_hLblParam, pLbl);
   ShowWindow(s_hLblParam, bShow ? SW_SHOW : SW_HIDE);
   ShowWindow(s_hParam, bShow ? SW_SHOW : SW_HIDE);
   DlgGenerate_ClearComboHighlight(s_hParam);
}

static void DlgGenerate_FillMechExp(void)
{
   const char* pType = DlgGenerate_CurrentCliName();
   GEN_KIND kind = DlgGenerate_KindFromName(pType);
   CK_ULONG uLoop;
   CK_ULONG uCount;

   SendMessageA(s_hMech, CB_RESETCONTENT, 0, 0);
   SendMessageA(s_hExp, CB_RESETCONTENT, 0, 0);

   if (kind == GEN_KIND_RSA)
   {
      uCount = P11Util_GetRSAGenMechCount();
      for (uLoop = 0; uLoop < uCount; uLoop++)
      {
         CK_CHAR_PTR pName = P11Util_GetRSAGenMechNameAt(uLoop);
         DlgGenerate_AddNamed(s_hMech, (const char*)pName, (LPARAM)pName);
      }
      DlgGenerate_SelectNamed(s_hMech, "pkcs");
      uCount = P11Util_GetPublicExpCount();
      for (uLoop = 0; uLoop < uCount; uLoop++)
      {
         CK_CHAR_PTR pName = P11Util_GetPublicExpNameAt(uLoop);
         DlgGenerate_AddNamed(s_hExp, (const char*)pName, (LPARAM)pName);
      }
      DlgGenerate_SelectNamed(s_hExp, "65537");
      DlgGenerate_ClearComboHighlight(s_hExp);
   }
   else if (kind == GEN_KIND_DH)
   {
      uCount = P11Util_GetDHGenMechCount();
      for (uLoop = 0; uLoop < uCount; uLoop++)
      {
         CK_CHAR_PTR pName = P11Util_GetDHGenMechNameAt(uLoop);
         DlgGenerate_AddNamed(s_hMech, (const char*)pName, (LPARAM)pName);
      }
      DlgGenerate_SelectNamed(s_hMech, "pkcs");
   }
}

static void DlgGenerate_FillTypes(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount = P11Util_GetKeyTypeNameCount(KEY_TYPE_GENKEY);
   char szDisp[48];

   SendMessageA(s_hType, CB_RESETCONTENT, 0, 0);
   for (uLoop = 0; uLoop < uCount; uLoop++)
   {
      CK_CHAR_PTR pName = P11Util_GetKeyTypeNameAt(KEY_TYPE_GENKEY, uLoop);
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
   SendMessageA(s_hType, CB_SETCURSEL, 0, 0);
}

static void DlgGenerate_FillLmsCombos(void)
{
   CK_ULONG uLoop;
   CK_ULONG uCount;
   int iLevel;

   uCount = P11Util_GetLMSTypeCount();
   for (iLevel = 0; iLevel < MAX_HSS_LEVEL; iLevel++)
   {
      SendMessageA(s_hLms[iLevel], CB_RESETCONTENT, 0, 0);
      for (uLoop = 0; uLoop < uCount; uLoop++)
      {
         CK_CHAR_PTR pName = P11Util_GetLMSTypeNameAt(uLoop);
         DlgGenerate_AddNamed(s_hLms[iLevel], (const char*)pName, (LPARAM)pName);
      }
      DlgGenerate_SelectNamed(s_hLms[iLevel], "sha256_m32_h10");
   }

   uCount = P11Util_GetLMSOTSTypeCount();
   for (iLevel = 0; iLevel < MAX_HSS_LEVEL; iLevel++)
   {
      SendMessageA(s_hLmots[iLevel], CB_RESETCONTENT, 0, 0);
      for (uLoop = 0; uLoop < uCount; uLoop++)
      {
         CK_CHAR_PTR pName = P11Util_GetLMSOTSTypeNameAt(uLoop);
         DlgGenerate_AddNamed(s_hLmots[iLevel], (const char*)pName, (LPARAM)pName);
      }
      DlgGenerate_SelectNamed(s_hLmots[iLevel], "sha256_n32_w8");
   }
}

static int DlgGenerate_PlaceRow(HWND hLbl, HWND hCtl, BOOL bShow, int y, int editX, int editW, BOOL bCombo)
{
   int nCmd = bShow ? SW_SHOW : SW_HIDE;
   int ctlH = bCombo ? DLG_COMBO_DROP : DLG_EDIT_H;

   if (hLbl != NULL)
   {
      ShowWindow(hLbl, nCmd);
      if (bShow)
      {
         MoveWindow(hLbl, DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
      }
   }
   if (hCtl != NULL)
   {
      ShowWindow(hCtl, nCmd);
      if (bShow)
      {
         MoveWindow(hCtl, editX, y, editW, ctlH, TRUE);
      }
   }
   if (bShow)
   {
      return y + DLG_EDIT_H + 8;
   }
   return y;
}

static int DlgGenerate_PlaceFlags(int y, int cx)
{
   HWND hFlags[15];
   int widths[15];
   int nCount = 14;
   int x = DLG_MARGIN;
   int iLoop;

   hFlags[0] = s_hToken;        widths[0] = 64;
   hFlags[1] = s_hPrivate;      widths[1] = 70;
   hFlags[2] = s_hSensitive;    widths[2] = 84;
   hFlags[3] = s_hExtractable;  widths[3] = 90;
   hFlags[4] = s_hModifiable;   widths[4] = 90;
   hFlags[5] = s_hEncrypt;      widths[5] = 70;
   hFlags[6] = s_hDecrypt;      widths[6] = 70;
   hFlags[7] = s_hSign;         widths[7] = 50;
   hFlags[8] = s_hVerify;       widths[8] = 60;
   hFlags[9] = s_hWrap;         widths[9] = 54;
   hFlags[10] = s_hUnwrap;      widths[10] = 70;
   hFlags[11] = s_hDerive;      widths[11] = 60;
   hFlags[12] = s_hEncapsulate; widths[12] = 96;
   hFlags[13] = s_hDecapsulate; widths[13] = 96;
   hFlags[14] = NULL;           widths[14] = 0;

   for (iLoop = 0; iLoop < nCount; iLoop++)
   {
      if (hFlags[iLoop] == NULL)
      {
         continue;
      }
      ShowWindow(hFlags[iLoop], SW_SHOW);
      if ((x + widths[iLoop]) > (cx - DLG_MARGIN))
      {
         x = DLG_MARGIN;
         y += 20;
      }
      MoveWindow(hFlags[iLoop], x, y, widths[iLoop], 18, TRUE);
      x += widths[iLoop] + 8;
   }
   return y + 22;
}

static BOOL DlgGenerate_DhNeedsSubprime(void)
{
   const char* pMech = DlgGenerate_ComboName(s_hMech, s_szMechTyped, sizeof(s_szMechTyped));
   if (pMech == NULL)
   {
      return FALSE;
   }
   return (strcmp(pMech, "x942") == 0) ? TRUE : FALSE;
}

static void DlgGenerate_Layout(int cx, int cy)
{
   const char* pType = DlgGenerate_CurrentCliName();
   GEN_KIND kind = DlgGenerate_KindFromName(pType);
   BOOL bPair;
   BOOL bDhSub;
   BOOL bComp;
   int y;
   int editX;
   int editW;
   int yBtn;
   int iLevel;
   int nLevels = 0;
   RECT rcWin;
   RECT rcAdj;
   DWORD dwStyle;
   DWORD dwEx;

   (void)cy;
   editX = DLG_MARGIN + DLG_LABEL_W + 8;
   editW = cx - editX - DLG_MARGIN;
   if (editW < 140)
   {
      editW = 140;
   }

   bPair = (kind == GEN_KIND_RSA) || (kind == GEN_KIND_CURVE) || (kind == GEN_KIND_DH) ||
      (kind == GEN_KIND_DSA) || (kind == GEN_KIND_MLDSA) || (kind == GEN_KIND_MLKEM) ||
      (kind == GEN_KIND_LMS) || (kind == GEN_KIND_HSS);
   bDhSub = (kind == GEN_KIND_DSA) || ((kind == GEN_KIND_DH) && DlgGenerate_DhNeedsSubprime());
   bComp = (kind == GEN_KIND_AES) || (kind == GEN_KIND_DES);

   if (kind == GEN_KIND_HSS)
   {
      nLevels = (int)DlgGenerate_GetHssLevel();
   }
   else if (kind == GEN_KIND_LMS)
   {
      nLevels = 1;
   }

   y = DLG_MARGIN;
   y = DlgGenerate_PlaceRow(GetDlgItem(s_hDlg, IDC_GEN_LBL_TYPE), s_hType, TRUE, y, editX, editW, TRUE);
   y = DlgGenerate_PlaceRow(GetDlgItem(s_hDlg, IDC_GEN_LBL_LABEL), s_hLabel, TRUE, y, editX, editW, FALSE);
   y = DlgGenerate_PlaceRow(GetDlgItem(s_hDlg, IDC_GEN_LBL_PUB), s_hLabelPub, bPair, y, editX, editW, FALSE);
   y = DlgGenerate_PlaceRow(GetDlgItem(s_hDlg, IDC_GEN_LBL_PRIV), s_hLabelPriv, bPair, y, editX, editW, FALSE);
   y = DlgGenerate_PlaceRow(GetDlgItem(s_hDlg, IDC_GEN_LBL_ID), s_hId, TRUE, y, editX, editW, FALSE);
   y = DlgGenerate_PlaceRow(s_hLblParam, s_hParam,
      (kind != GEN_KIND_SM4) && (kind != GEN_KIND_DH) && (kind != GEN_KIND_DSA) &&
      (kind != GEN_KIND_LMS) && (kind != GEN_KIND_HSS) && (kind != GEN_KIND_NONE),
      y, editX, editW, TRUE);
   y = DlgGenerate_PlaceRow(s_hLblMech, s_hMech, (kind == GEN_KIND_RSA) || (kind == GEN_KIND_DH), y, editX, editW, TRUE);
   y = DlgGenerate_PlaceRow(s_hLblExp, s_hExp, kind == GEN_KIND_RSA, y, editX, editW, TRUE);
   y = DlgGenerate_PlaceRow(GetDlgItem(s_hDlg, IDC_GEN_LBL_PRIME), s_hPrime,
      (kind == GEN_KIND_DH) || (kind == GEN_KIND_DSA), y, editX, editW, FALSE);
   y = DlgGenerate_PlaceRow(GetDlgItem(s_hDlg, IDC_GEN_LBL_BASE), s_hBase,
      (kind == GEN_KIND_DH) || (kind == GEN_KIND_DSA), y, editX, editW, FALSE);
   y = DlgGenerate_PlaceRow(GetDlgItem(s_hDlg, IDC_GEN_LBL_SUB), s_hSubprime, bDhSub, y, editX, editW, FALSE);
   y = DlgGenerate_PlaceRow(GetDlgItem(s_hDlg, IDC_GEN_LBL_LEVEL), s_hLevel, kind == GEN_KIND_HSS, y, editX, editW, TRUE);

   for (iLevel = 0; iLevel < MAX_HSS_LEVEL; iLevel++)
   {
      BOOL bShow = (iLevel < nLevels);
      int half;
      int nCmd = bShow ? SW_SHOW : SW_HIDE;

      ShowWindow(s_hLblLms[iLevel], nCmd);
      ShowWindow(s_hLms[iLevel], nCmd);
      ShowWindow(s_hLblLmots[iLevel], nCmd);
      ShowWindow(s_hLmots[iLevel], nCmd);
      if (bShow == FALSE)
      {
         continue;
      }
      half = (editW / 2) - 8;
      if (half < 80)
      {
         half = 80;
      }
      MoveWindow(s_hLblLms[iLevel], DLG_MARGIN, y + 3, DLG_LABEL_W, 16, TRUE);
      MoveWindow(s_hLms[iLevel], editX, y, half - 40, DLG_COMBO_DROP, TRUE);
      MoveWindow(s_hLblLmots[iLevel], editX + half - 36, y + 3, 36, 16, TRUE);
      MoveWindow(s_hLmots[iLevel], editX + half, y, editW - half, DLG_COMBO_DROP, TRUE);
      y += DLG_EDIT_H + 8;
   }

   y = DlgGenerate_PlaceRow(GetDlgItem(s_hDlg, IDC_GEN_LBL_COMP), s_hComp, bComp, y, editX, editW, TRUE);
   y += 4;
   y = DlgGenerate_PlaceFlags(y, cx);
   y += 6;

   yBtn = y;
   MoveWindow(s_hStatus, DLG_MARGIN, yBtn, cx - (2 * DLG_MARGIN), 32, TRUE);
   yBtn += 36;
   MoveWindow(GetDlgItem(s_hDlg, IDC_GEN_GENERATE), cx - DLG_MARGIN - (2 * DLG_BTN_W) - 8, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   MoveWindow(GetDlgItem(s_hDlg, IDC_GEN_CLOSE), cx - DLG_MARGIN - DLG_BTN_W, yBtn, DLG_BTN_W, DLG_BTN_H, TRUE);
   yBtn += DLG_BTN_H + DLG_MARGIN;

   GetWindowRect(s_hDlg, &rcWin);
   rcAdj.left = 0;
   rcAdj.top = 0;
   rcAdj.right = cx;
   rcAdj.bottom = yBtn;
   dwStyle = (DWORD)GetWindowLongA(s_hDlg, GWL_STYLE);
   dwEx = (DWORD)GetWindowLongA(s_hDlg, GWL_EXSTYLE);
   AdjustWindowRectEx(&rcAdj, dwStyle, FALSE, dwEx);
   if ((rcWin.bottom - rcWin.top) != (rcAdj.bottom - rcAdj.top))
   {
      static BOOL s_bSizing = FALSE;
      if (s_bSizing == FALSE)
      {
         s_bSizing = TRUE;
         SetWindowPos(s_hDlg, NULL, 0, 0, rcWin.right - rcWin.left, rcAdj.bottom - rcAdj.top,
            SWP_NOMOVE | SWP_NOZORDER);
         s_bSizing = FALSE;
      }
   }
}

static void DlgGenerate_OnTypeChanged(void)
{
   DlgGenerate_FillParam();
   DlgGenerate_FillMechExp();
   if (s_hDlg != NULL)
   {
      RECT rc;
      GetClientRect(s_hDlg, &rc);
      DlgGenerate_Layout(rc.right - rc.left, rc.bottom - rc.top);
   }
   DlgGenerate_SetStatus("");
}

static void DlgGenerate_InitTemplateFlags(P11_KEYGENTEMPLATE* pTpl)
{
   pTpl->bCKA_Token = DlgGenerate_IsChecked(s_hToken);
   pTpl->bCKA_Private = DlgGenerate_IsChecked(s_hPrivate);
   pTpl->bCKA_Sensitive = DlgGenerate_IsChecked(s_hSensitive);
   pTpl->bCKA_Extractable = DlgGenerate_IsChecked(s_hExtractable);
   pTpl->bCKA_Encrypt = DlgGenerate_IsChecked(s_hEncrypt);
   pTpl->bCKA_Decrypt = DlgGenerate_IsChecked(s_hDecrypt);
   pTpl->bCKA_Sign = DlgGenerate_IsChecked(s_hSign);
   pTpl->bCKA_Verify = DlgGenerate_IsChecked(s_hVerify);
   pTpl->bCKA_Wrap = DlgGenerate_IsChecked(s_hWrap);
   pTpl->bCKA_Unwrap = DlgGenerate_IsChecked(s_hUnwrap);
   pTpl->bCKA_Derive = DlgGenerate_IsChecked(s_hDerive);
   pTpl->bCKA_Modifiable = DlgGenerate_IsChecked(s_hModifiable);
   pTpl->bCKA_Encapsulate = DlgGenerate_IsChecked(s_hEncapsulate);
   pTpl->bCKA_Decapsulate = DlgGenerate_IsChecked(s_hDecapsulate);
}

static void DlgGenerate_StripHex(char* s)
{
   char* pDst = s;
   if (s == NULL)
   {
      return;
   }
   if ((s[0] == '0') && ((s[1] == 'x') || (s[1] == 'X')))
   {
      s += 2;
   }
   while (*s != 0)
   {
      if (isspace((unsigned char)*s) == 0)
      {
         *pDst++ = *s;
      }
      s++;
   }
   *pDst = 0;
}

static void DlgGenerate_FreeDomain(void)
{
   if (s_domain.sPrime != NULL)
   {
      GUI_SecureClear(s_domain.sPrime, (unsigned int)s_domain.uPrimeLength);
      free(s_domain.sPrime);
   }
   if (s_domain.sBase != NULL)
   {
      GUI_SecureClear(s_domain.sBase, (unsigned int)s_domain.uBaseLength);
      free(s_domain.sBase);
   }
   if (s_domain.sSubPrime != NULL)
   {
      GUI_SecureClear(s_domain.sSubPrime, (unsigned int)s_domain.uSubPrimeLength);
      free(s_domain.sSubPrime);
   }
   memset(&s_domain, 0, sizeof(s_domain));
}

static CK_BBOOL DlgGenerate_ParseHexEdit(HWND hEdit, CK_CHAR_PTR* ppOut, CK_LONG* pLen)
{
   char* pBuf;
   CK_ULONG uText;
   CK_ULONG uBin;

   *ppOut = NULL;
   *pLen = 0;
   uText = (CK_ULONG)GetWindowTextLengthA(hEdit);
   if (uText == 0)
   {
      return CK_FALSE;
   }
   pBuf = (char*)malloc((size_t)uText + 1);
   if (pBuf == NULL)
   {
      return CK_FALSE;
   }
   memset(pBuf, 0, (size_t)uText + 1);
   GetWindowTextA(hEdit, pBuf, (int)uText + 1);
   DlgGenerate_StripHex(pBuf);
   uText = (CK_ULONG)strlen(pBuf);
   if (uText == 0)
   {
      free(pBuf);
      return CK_FALSE;
   }
   uBin = str_StringtoByteArray((CK_CHAR_PTR)pBuf, uText);
   if (uBin == 0)
   {
      free(pBuf);
      return CK_FALSE;
   }
   *ppOut = (CK_CHAR_PTR)pBuf;
   *pLen = (CK_LONG)uBin;
   return CK_TRUE;
}

static void DlgGenerate_CompSetStatus(HWND hWnd, const char* sText)
{
   HWND hStatus = GetDlgItem(hWnd, IDC_COMP_STATUS);
   if (hStatus != NULL)
   {
      SetWindowTextA(hStatus, (sText != NULL) ? sText : "");
   }
}

static void DlgGenerate_CopyComponent(HWND hWnd)
{
   HWND hHex;
   int nLen;
   HGLOBAL hMem;
   char* pMem;

   hHex = GetDlgItem(hWnd, IDC_COMP_HEX);
   if (hHex == NULL)
   {
      DlgGenerate_CompSetStatus(hWnd, "Copy failed.");
      return;
   }
   nLen = GetWindowTextLengthA(hHex);
   if (nLen <= 0)
   {
      DlgGenerate_CompSetStatus(hWnd, "Nothing to copy.");
      return;
   }
   hMem = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)nLen + 1);
   if (hMem == NULL)
   {
      DlgGenerate_CompSetStatus(hWnd, "Copy failed.");
      return;
   }
   pMem = (char*)GlobalLock(hMem);
   if (pMem == NULL)
   {
      GlobalFree(hMem);
      DlgGenerate_CompSetStatus(hWnd, "Copy failed.");
      return;
   }
   GetWindowTextA(hHex, pMem, nLen + 1);
   GlobalUnlock(hMem);
   if (OpenClipboard(hWnd) == FALSE)
   {
      GlobalFree(hMem);
      DlgGenerate_CompSetStatus(hWnd, "Copy failed.");
      return;
   }
   EmptyClipboard();
   SetClipboardData(CF_TEXT, hMem);
   CloseClipboard();
   DlgGenerate_CompSetStatus(hWnd, "Copied.");
}

static LRESULT CALLBACK DlgGenerate_CompProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_COMP_COPY:
         DlgGenerate_CopyComponent(hWnd);
         return 0;
      case IDC_COMP_NEXT:
      case IDOK:
         s_bCompOk = TRUE;
         DestroyWindow(hWnd);
         return 0;
      case IDC_COMP_CANCEL:
      case IDCANCEL:
         s_bCompOk = FALSE;
         DestroyWindow(hWnd);
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
   case WM_CLOSE:
      s_bCompOk = FALSE;
      DestroyWindow(hWnd);
      return 0;
   case WM_DESTROY:
      s_hCompDlg = NULL;
      s_bCompDone = TRUE;
      return 0;
   default:
      break;
   }
   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

static CK_BBOOL DlgGenerate_ShowComponent(HWND hwndParent, CK_LONG iIndex, CK_LONG iTotal,
   CK_BYTE_PTR pComp, CK_LONG nLen, CK_CHAR_PTR pKcv)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   HWND hHex;
   MSG msg;
   RECT rc;
   char szTitle[80];
   char szHex[2048];
   char szKcv[80];
   CK_LONG iLoop;
   unsigned int uUsed = 0;
   HFONT hFont;

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgGenerate_CompProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_COMP_CLASS;
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
   _snprintf(szTitle, sizeof(szTitle) - 1, "Clear component %ld of %ld", (long)iIndex, (long)iTotal);

   s_bCompDone = FALSE;
   s_bCompOk = FALSE;
   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_COMP_CLASS, szTitle,
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
      rc.left + 24, rc.top + 24, 560, 240,
      hwndParent, NULL, wc.hInstance, NULL);
   if (hDlg == NULL)
   {
      return CK_FALSE;
   }
   s_hCompDlg = hDlg;
   hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

   CreateWindowA("STATIC", "Write this component down or copy it, then click Next. It is not saved.",
      WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
      12, 12, 520, 18, hDlg, NULL, NULL, NULL);

   memset(szHex, 0, sizeof(szHex));
   for (iLoop = 0; (iLoop < nLen) && (uUsed + 4 < sizeof(szHex)); iLoop++)
   {
      uUsed += (unsigned int)_snprintf(szHex + uUsed, sizeof(szHex) - uUsed - 1, "%02X%s",
         pComp[iLoop], (iLoop + 1 < nLen) ? " " : "");
   }

   hHex = CreateWindowA("EDIT", szHex,
      WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY,
      12, 36, 520, 22, hDlg, (HMENU)(INT_PTR)IDC_COMP_HEX, NULL, NULL);

   memset(szKcv, 0, sizeof(szKcv));
   if (pKcv != NULL)
   {
      _snprintf(szKcv, sizeof(szKcv) - 1, "KCV (PCI): %02X%02X%02X",
         (unsigned char)pKcv[0], (unsigned char)pKcv[1], (unsigned char)pKcv[2]);
   }
   CreateWindowA("STATIC", szKcv,
      WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
      12, 66, 520, 18, hDlg, (HMENU)(INT_PTR)IDC_COMP_KCV, NULL, NULL);
   CreateWindowA("STATIC", "",
      WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
      12, 90, 520, 18, hDlg, (HMENU)(INT_PTR)IDC_COMP_STATUS, NULL, NULL);

   CreateWindowA("BUTTON", "Copy",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
      264, 160, DLG_BTN_W, DLG_BTN_H, hDlg, (HMENU)(INT_PTR)IDC_COMP_COPY, NULL, NULL);
   CreateWindowA("BUTTON", "Next",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
      356, 160, DLG_BTN_W, DLG_BTN_H, hDlg, (HMENU)(INT_PTR)IDC_COMP_NEXT, NULL, NULL);
   CreateWindowA("BUTTON", "Cancel",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
      448, 160, DLG_BTN_W, DLG_BTN_H, hDlg, (HMENU)(INT_PTR)IDC_COMP_CANCEL, NULL, NULL);

   {
      HWND hCtrl;
      HWND hStatus;
      for (hCtrl = GetWindow(hDlg, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
      {
         SendMessageA(hCtrl, WM_SETFONT, (WPARAM)hFont, TRUE);
      }
      hStatus = GetDlgItem(hDlg, IDC_COMP_STATUS);
      if (hStatus != NULL)
      {
         GUI_ThemeMarkStatus(hStatus);
      }
   }

   if (hwndParent != NULL)
   {
      EnableWindow(hwndParent, FALSE);
   }
   ShowWindow(hDlg, SW_SHOW);
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

   /* The dialog (and its edit control) is already destroyed here; just scrub the local copy. */
   GUI_SecureClear(szHex, sizeof(szHex));
   (void)hHex;

   if (hwndParent != NULL)
   {
      EnableWindow(hwndParent, TRUE);
      SetForegroundWindow(hwndParent);
   }
   return s_bCompOk ? CK_TRUE : CK_FALSE;
}

static CK_BBOOL DlgGenerate_GenerateWithComponents(P11_KEYGENTEMPLATE* pTpl, CK_LONG nComp, CK_OBJECT_HANDLE_PTR phKey)
{
   CK_LONG sLoop;
   CK_LONG sKeyLength;
   CK_BYTE_PTR pbComponent = NULL;
   CK_BYTE_PTR pbDisplay = NULL;
   CK_BYTE_PTR pbKey = NULL;
   P11_UNWRAPTEMPLATE sKeyTemplate;
   CK_OBJECT_HANDLE hWrapKey = 0;
   CK_OBJECT_HANDLE hKey = 0;
   CK_CHAR_PTR pKcvBuffer = NULL;
   CK_BBOOL bError = CK_FALSE;
   CK_BBOOL bOk = CK_FALSE;

   if (MessageBoxA(s_hDlg,
      "This generates a key from clear components. Each holder should see only their own component.\n\nContinue?",
      "Generate from components", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
   {
      DlgGenerate_SetStatus("Component generate cancelled.");
      return CK_FALSE;
   }

   do
   {
      hWrapKey = P11_GenerateAESWrapKey(CK_FALSE, AES_256_KEY_LENGTH, "AES_KEY_WRAP_KEY_COMP");
      sKeyLength = pTpl->skeySize;
      pbComponent = (CK_BYTE_PTR)malloc((size_t)sKeyLength);
      pbDisplay = (CK_BYTE_PTR)malloc((size_t)sKeyLength);
      pbKey = (CK_BYTE_PTR)malloc((size_t)sKeyLength);
      if ((pbComponent == NULL) || (pbDisplay == NULL) || (pbKey == NULL) || (hWrapKey == 0))
      {
         bError = CK_TRUE;
         break;
      }
      memset(pbKey, 0, (size_t)sKeyLength);

      for (sLoop = 1; sLoop <= nComp; sLoop++)
      {
         if (P11_GenerateRandom(pbComponent, (CK_ULONG)sKeyLength) != CK_TRUE)
         {
            bError = CK_TRUE;
            break;
         }
         if (pTpl->skeyType != CKK_AES)
         {
            str_ByteArrayComputeParityBit(pbComponent, sKeyLength);
         }
         str_ByteArrayXOR(pbKey, pbComponent, (CK_ULONG)sKeyLength);
         /* ImportClear zeros the source buffer after wrapping; keep a copy to show. */
         memcpy(pbDisplay, pbComponent, (size_t)sKeyLength);

         memset(&sKeyTemplate, 0, sizeof(sKeyTemplate));
         sKeyTemplate.sClass = pTpl->sClass;
         sKeyTemplate.skeyType = pTpl->skeyType;
         sKeyTemplate.pKeyLabel = "";
         sKeyTemplate.bCKA_Sign = CK_TRUE;
         sKeyTemplate.bCKA_Verify = CK_TRUE;
         sKeyTemplate.bCKA_Encrypt = CK_TRUE;
         sKeyTemplate.bCKA_Decrypt = CK_TRUE;
         sKeyTemplate.bCKA_Token = CK_FALSE;
         sKeyTemplate.bCKA_Sensitive = CK_TRUE;
         sKeyTemplate.bCKA_Private = CK_TRUE;
         sKeyTemplate.hWrappingKey = hWrapKey;
         hKey = P11_ImportClearSymetricKey(&sKeyTemplate, (CK_CHAR_PTR)pbComponent, (CK_ULONG)sKeyLength);
         if (hKey == 0)
         {
            bError = CK_TRUE;
            break;
         }
         pKcvBuffer = NULL;
         if (P11_ComputeKCV(KCV_PCI, hKey, &pKcvBuffer) != CK_TRUE)
         {
            bError = CK_TRUE;
            P11_DeleteObject(hKey);
            break;
         }
         P11_DeleteObject(hKey);
         hKey = 0;

         if (DlgGenerate_ShowComponent(s_hDlg, sLoop, nComp, pbDisplay, sKeyLength, pKcvBuffer) != CK_TRUE)
         {
            bError = CK_TRUE;
            free(pKcvBuffer);
            pKcvBuffer = NULL;
            GUI_SecureClear(pbDisplay, (unsigned int)sKeyLength);
            GUI_SecureClear(pbComponent, (unsigned int)sKeyLength);
            break;
         }
         free(pKcvBuffer);
         pKcvBuffer = NULL;
         GUI_SecureClear(pbDisplay, (unsigned int)sKeyLength);
         GUI_SecureClear(pbComponent, (unsigned int)sKeyLength);
      }

      if (bError == CK_TRUE)
      {
         break;
      }

      memset(&sKeyTemplate, 0, sizeof(sKeyTemplate));
      sKeyTemplate.sClass = pTpl->sClass;
      sKeyTemplate.skeyType = pTpl->skeyType;
      sKeyTemplate.bCKA_Private = pTpl->bCKA_Private;
      sKeyTemplate.bCKA_Modifiable = pTpl->bCKA_Modifiable;
      sKeyTemplate.bCKA_Sign = pTpl->bCKA_Sign;
      sKeyTemplate.bCKA_Verify = pTpl->bCKA_Verify;
      sKeyTemplate.bCKA_Unwrap = pTpl->bCKA_Unwrap;
      sKeyTemplate.bCKA_Wrap = pTpl->bCKA_Wrap;
      sKeyTemplate.bCKA_Encrypt = pTpl->bCKA_Encrypt;
      sKeyTemplate.bCKA_Decrypt = pTpl->bCKA_Decrypt;
      sKeyTemplate.bCKA_Token = pTpl->bCKA_Token;
      sKeyTemplate.bCKA_Sensitive = pTpl->bCKA_Sensitive;
      sKeyTemplate.bCKA_Derive = pTpl->bCKA_Derive;
      sKeyTemplate.bCKA_Extractable = pTpl->bCKA_Extractable;
      sKeyTemplate.pKeyLabel = pTpl->pKeyLabel;
      sKeyTemplate.pCKA_ID = pTpl->pCKA_ID;
      sKeyTemplate.uCKA_ID_Length = (CK_ULONG)pTpl->uCKA_ID_Length;
      sKeyTemplate.hWrappingKey = hWrapKey;
      if (pTpl->skeyType != CKK_AES)
      {
         str_ByteArrayComputeParityBit(pbKey, sKeyLength);
      }
      hKey = P11_ImportClearSymetricKey(&sKeyTemplate, (CK_CHAR_PTR)pbKey, (CK_ULONG)sKeyLength);
      if (hKey != 0)
      {
         *phKey = hKey;
         bOk = CK_TRUE;
         GUI_SetLastObjectHandle(hKey);
         if (P11_ComputeKCV(KCV_PCI, hKey, &pKcvBuffer) == CK_TRUE)
         {
            char sz[160];
            memset(sz, 0, sizeof(sz));
            _snprintf(sz, sizeof(sz) - 1, "Generated. Handle %lu. KCV %02X%02X%02X.",
               (unsigned long)hKey,
               (unsigned char)pKcvBuffer[0],
               (unsigned char)pKcvBuffer[1],
               (unsigned char)pKcvBuffer[2]);
            DlgGenerate_SetStatus(sz);
            free(pKcvBuffer);
            pKcvBuffer = NULL;
         }
      }
   } while (FALSE);

   if (pbComponent != NULL)
   {
      GUI_SecureClear(pbComponent, (unsigned int)sKeyLength);
      free(pbComponent);
   }
   if (pbDisplay != NULL)
   {
      GUI_SecureClear(pbDisplay, (unsigned int)sKeyLength);
      free(pbDisplay);
   }
   if (pbKey != NULL)
   {
      GUI_SecureClear(pbKey, (unsigned int)sKeyLength);
      free(pbKey);
   }
   if (hWrapKey != 0)
   {
      P11_DeleteObject(hWrapKey);
   }
   if ((bOk != CK_TRUE) && (bError == CK_TRUE))
   {
      DlgGenerate_SetStatus("Component generate failed or cancelled.");
   }
   return bOk;
}

static void DlgGenerate_DoGenerate(void)
{
   const char* pType;
   GEN_KIND kind;
   P11_KEYGENTEMPLATE tpl;
   char szLabel[DLG_MAX_LABEL];
   char szPub[DLG_MAX_LABEL];
   char szPriv[DLG_MAX_LABEL];
   CK_OBJECT_HANDLE hKey = 0;
   CK_OBJECT_HANDLE hPub = 0;
   CK_OBJECT_HANDLE hPriv = 0;
   CK_BBOOL bPair = CK_FALSE;
   CK_BBOOL bOk = CK_FALSE;
   CK_LONG nComp = 0;
   HCURSOR hWait;
   HCURSOR hOld;
   const char* pMech;
   const char* pExp;
   const char* pCurve;
   CK_LONG nIdLen;

   memset(&tpl, 0, sizeof(tpl));
   memset(szLabel, 0, sizeof(szLabel));
   memset(szPub, 0, sizeof(szPub));
   memset(szPriv, 0, sizeof(szPriv));
   DlgGenerate_FreeDomain();

   if (P11_IsLoggedIn() != CK_TRUE)
   {
      DlgGenerate_SetStatus("Not logged in.");
      return;
   }

   pType = DlgGenerate_CurrentCliName();
   kind = DlgGenerate_KindFromName(pType);
   if ((pType == NULL) || (kind == GEN_KIND_NONE))
   {
      DlgGenerate_SetStatus("Select a key type.");
      return;
   }

   GetWindowTextA(s_hLabel, szLabel, sizeof(szLabel));
   GetWindowTextA(s_hLabelPub, szPub, sizeof(szPub));
   GetWindowTextA(s_hLabelPriv, szPriv, sizeof(szPriv));

   tpl.sClass = P11Util_GetClassFromCKType((CK_CHAR_PTR)pType, KEY_TYPE_GENKEY);
   tpl.skeyType = P11Util_GetCKType((CK_CHAR_PTR)pType, KEY_TYPE_GENKEY);
   if ((tpl.sClass == CK_NULL_ELEMENT) || (tpl.skeyType == CK_NULL_ELEMENT))
   {
      DlgGenerate_SetStatus("Unsupported key type.");
      return;
   }

   DlgGenerate_InitTemplateFlags(&tpl);

   if (tpl.sClass == CKO_PRIVATE_KEY)
   {
      bPair = CK_TRUE;
      tpl.sClassPublic = CKO_PUBLIC_KEY;
      if (szPub[0] != 0)
      {
         tpl.pKeyLabelPublic = (CK_CHAR_PTR)szPub;
      }
      else if (szLabel[0] != 0)
      {
         tpl.pKeyLabelPublic = (CK_CHAR_PTR)szLabel;
      }
      if (szPriv[0] != 0)
      {
         tpl.pKeyLabelPrivate = (CK_CHAR_PTR)szPriv;
      }
      else if (szLabel[0] != 0)
      {
         tpl.pKeyLabelPrivate = (CK_CHAR_PTR)szLabel;
      }
      if ((tpl.pKeyLabelPublic == NULL) || (tpl.pKeyLabelPrivate == NULL))
      {
         DlgGenerate_SetStatus("Enter a label, or both public and private labels.");
         return;
      }
      tpl.pKeyLabel = (szLabel[0] != 0) ? (CK_CHAR_PTR)szLabel : tpl.pKeyLabelPrivate;
   }
   else
   {
      if (szLabel[0] == 0)
      {
         DlgGenerate_SetStatus("Enter a label.");
         SetFocus(s_hLabel);
         return;
      }
      tpl.pKeyLabel = (CK_CHAR_PTR)szLabel;
   }

   nIdLen = 0;
   memset(s_szCkaId, 0, sizeof(s_szCkaId));
   GetWindowTextA(s_hId, s_szCkaId, sizeof(s_szCkaId));
   DlgGenerate_StripHex(s_szCkaId);
   if (s_szCkaId[0] != 0)
   {
      nIdLen = (CK_LONG)str_StringtoByteArray((CK_CHAR_PTR)s_szCkaId, (CK_ULONG)strlen(s_szCkaId));
      if (nIdLen == 0)
      {
         DlgGenerate_SetStatus("CKA_ID must be hexadecimal.");
         return;
      }
      if (nIdLen > DLG_CKA_ID_MAX)
      {
         DlgGenerate_SetStatus("CKA_ID too long (max 4096 bytes).");
         return;
      }
      tpl.pCKA_ID = (CK_CHAR_PTR)s_szCkaId;
      tpl.uCKA_ID_Length = nIdLen;
   }

   switch (kind)
   {
   case GEN_KIND_AES:
   case GEN_KIND_DES:
   case GEN_KIND_HMAC:
      if (DlgGenerate_GetParamLong(&tpl.skeySize) != CK_TRUE)
      {
         DlgGenerate_SetStatus("Select or enter a size.");
         return;
      }
      if ((kind == GEN_KIND_HMAC) &&
         ((tpl.skeySize < GENERIC_KEY_MINIMUM_LENGTH) || (tpl.skeySize > GENERIC_KEY__MAXIMUM_LENGTH)))
      {
         DlgGenerate_SetStatus("HMAC / generic size must be 1 to 512 bytes.");
         return;
      }
      break;
   case GEN_KIND_SM4:
      tpl.skeySize = SM4_KEY_LENGTH;
      break;
   case GEN_KIND_RSA:
      if (DlgGenerate_GetParamLong(&tpl.skeySize) != CK_TRUE)
      {
         DlgGenerate_SetStatus("Select or enter an RSA size in bits.");
         return;
      }
      pMech = DlgGenerate_ComboName(s_hMech, s_szMechTyped, sizeof(s_szMechTyped));
      pExp = DlgGenerate_ComboName(s_hExp, s_szExpTyped, sizeof(s_szExpTyped));
      if ((pMech == NULL) || (pExp == NULL))
      {
         DlgGenerate_SetStatus("Select RSA mechanism and public exponent.");
         return;
      }
      if ((strcmp(pMech, "prime") == 0) && ((tpl.skeySize < 2048) || (tpl.skeySize > 8192)))
      {
         DlgGenerate_SetStatus("prime mechanism: RSA size 2048 to 8192 bits.");
         return;
      }
      if ((strcmp(pMech, "aux") == 0) && ((tpl.skeySize < 1024) || (tpl.skeySize > 8192)))
      {
         DlgGenerate_SetStatus("aux mechanism: RSA size 1024 to 8192 bits.");
         return;
      }
      if ((strcmp(pMech, "pkcs") == 0) && ((tpl.skeySize < 256) || (tpl.skeySize > 8192)))
      {
         DlgGenerate_SetStatus("pkcs mechanism: RSA size 256 to 8192 bits.");
         return;
      }
      tpl.pKeyPublicExp = P11Util_GetPublicExpParam((CK_CHAR_PTR)pExp);
      tpl.sKeyGenMech = (CK_LONG)P11Util_GetRSAGenMechParam((CK_CHAR_PTR)pMech);
      if ((tpl.pKeyPublicExp == NULL) || (tpl.sKeyGenMech == (CK_LONG)0xFFFFFFFF))
      {
         DlgGenerate_SetStatus("Invalid RSA mechanism or exponent.");
         return;
      }
      break;
   case GEN_KIND_CURVE:
      pCurve = DlgGenerate_ComboName(s_hParam, s_szParamTyped, sizeof(s_szParamTyped));
      if (pCurve == NULL)
      {
         DlgGenerate_SetStatus("Select a curve.");
         return;
      }
      tpl.pECCurveOID = P11Util_GetEcCurveOIDParam((CK_CHAR_PTR)pCurve);
      if (tpl.pECCurveOID == NULL)
      {
         DlgGenerate_SetStatus("Unknown curve.");
         return;
      }
      break;
   case GEN_KIND_DH:
      pMech = DlgGenerate_ComboName(s_hMech, s_szMechTyped, sizeof(s_szMechTyped));
      if (pMech == NULL)
      {
         DlgGenerate_SetStatus("Select a DH mechanism.");
         return;
      }
      tpl.sKeyGenMech = (CK_LONG)P11Util_GetDHGenMechParam((CK_CHAR_PTR)pMech);
      if (tpl.sKeyGenMech == (CK_LONG)0xFFFFFFFF)
      {
         DlgGenerate_SetStatus("Invalid DH mechanism.");
         return;
      }
      if (DlgGenerate_ParseHexEdit(s_hPrime, &s_domain.sPrime, &s_domain.uPrimeLength) != CK_TRUE)
      {
         DlgGenerate_SetStatus("Enter prime as hexadecimal.");
         return;
      }
      if (DlgGenerate_ParseHexEdit(s_hBase, &s_domain.sBase, &s_domain.uBaseLength) != CK_TRUE)
      {
         DlgGenerate_SetStatus("Enter base as hexadecimal.");
         DlgGenerate_FreeDomain();
         return;
      }
      if (DlgGenerate_DhNeedsSubprime() == TRUE)
      {
         if (DlgGenerate_ParseHexEdit(s_hSubprime, &s_domain.sSubPrime, &s_domain.uSubPrimeLength) != CK_TRUE)
         {
            DlgGenerate_SetStatus("x942 requires subprime as hexadecimal.");
            DlgGenerate_FreeDomain();
            return;
         }
         s_domain.bIsSubPrime = CK_TRUE;
      }
      tpl.pDHDomain = &s_domain;
      break;
   case GEN_KIND_DSA:
      if (DlgGenerate_ParseHexEdit(s_hPrime, &s_domain.sPrime, &s_domain.uPrimeLength) != CK_TRUE)
      {
         DlgGenerate_SetStatus("Enter prime as hexadecimal.");
         return;
      }
      if (DlgGenerate_ParseHexEdit(s_hBase, &s_domain.sBase, &s_domain.uBaseLength) != CK_TRUE)
      {
         DlgGenerate_SetStatus("Enter base as hexadecimal.");
         DlgGenerate_FreeDomain();
         return;
      }
      if (DlgGenerate_ParseHexEdit(s_hSubprime, &s_domain.sSubPrime, &s_domain.uSubPrimeLength) != CK_TRUE)
      {
         DlgGenerate_SetStatus("Enter subprime as hexadecimal.");
         DlgGenerate_FreeDomain();
         return;
      }
      s_domain.bIsSubPrime = CK_TRUE;
      tpl.pDSADomain = &s_domain;
      break;
   case GEN_KIND_MLDSA:
      if (DlgGenerate_GetParamLong(&tpl.skeySize) != CK_TRUE)
      {
         DlgGenerate_SetStatus("Select a parameter set.");
         return;
      }
      tpl.pML_DSA = P11Util_GetML_DSA_ParameterFromKeySize((CK_ULONG)tpl.skeySize);
      if (tpl.pML_DSA == NULL)
      {
         DlgGenerate_SetStatus("Invalid ML-DSA set.");
         return;
      }
      break;
   case GEN_KIND_MLKEM:
      if (DlgGenerate_GetParamLong(&tpl.skeySize) != CK_TRUE)
      {
         DlgGenerate_SetStatus("Select a parameter set.");
         return;
      }
      tpl.pML_KEM = P11Util_GetML_KEM_ParameterFromKeySize((CK_ULONG)tpl.skeySize);
      if (tpl.pML_KEM == NULL)
      {
         DlgGenerate_SetStatus("Invalid ML-KEM set.");
         return;
      }
      break;
   case GEN_KIND_LMS:
   case GEN_KIND_HSS:
      {
         CK_LONG nLevels;
         CK_LONG iLoop;
         if (kind == GEN_KIND_LMS)
         {
            nLevels = DEFAULT_LMS_LEVEL;
            tpl.skeyType = CKK_HSS;
         }
         else
         {
            nLevels = DlgGenerate_GetHssLevel();
         }
         if ((nLevels < 1) || (nLevels > MAX_HSS_LEVEL))
         {
            DlgGenerate_SetStatus("HSS level must be 1 to 8.");
            return;
         }
         tpl.pHSS.uHSS_Levels = (CK_HSS_LEVELS)nLevels;
         for (iLoop = 0; iLoop < nLevels; iLoop++)
         {
            const char* pLms = DlgGenerate_ComboName(s_hLms[iLoop], s_szParamTyped, sizeof(s_szParamTyped));
            const char* pOts = DlgGenerate_ComboName(s_hLmots[iLoop], s_szMechTyped, sizeof(s_szMechTyped));
            CK_LMS_TYPE uLms;
            CK_LMOTS_TYPE uOts;
            if ((pLms == NULL) || (pOts == NULL))
            {
               DlgGenerate_SetStatus("Select LMS and LMOTS types for each level.");
               return;
            }
            uLms = P11Util_GetLMSType((CK_CHAR_PTR)pLms);
            uOts = P11Util_GetLMSOTSType((CK_CHAR_PTR)pOts);
            if ((uLms == (CK_LMS_TYPE)-1) || (uOts == (CK_LMOTS_TYPE)-1))
            {
               DlgGenerate_SetStatus("Invalid LMS or LMOTS type.");
               return;
            }
            tpl.pHSS.uLmsType[iLoop] = uLms;
            tpl.pHSS.uLmotsType[iLoop] = uOts;
         }
      }
      break;
   default:
      DlgGenerate_SetStatus("Unsupported options.");
      return;
   }

   nComp = 0;
   if ((kind == GEN_KIND_AES) || (kind == GEN_KIND_DES))
   {
      nComp = DlgGenerate_GetComponentCount();
      if (nComp > 0)
      {
         if (kind == GEN_KIND_DES)
         {
            if (tpl.skeySize == DES2_KEY_LENGTH)
            {
               tpl.skeyType = CKK_DES2;
            }
            else if (tpl.skeySize == DES3_KEY_LENGTH)
            {
               tpl.skeyType = CKK_DES3;
            }
         }
         DlgGenerate_GenerateWithComponents(&tpl, nComp, &hKey);
         DlgGenerate_FreeDomain();
         return;
      }
   }

   DlgGenerate_SetStatus("Generating...");
   UpdateWindow(s_hDlg);
   hWait = LoadCursor(NULL, IDC_WAIT);
   hOld = SetCursor(hWait);

   if (bPair == CK_TRUE)
   {
      bOk = P11_GenerateKeyPair(&tpl, &hPriv, &hPub, CK_FALSE);
   }
   else
   {
      bOk = P11_GenerateKey(&tpl, &hKey, CK_FALSE);
   }

   SetCursor(hOld);
   DlgGenerate_FreeDomain();

   if (bOk == CK_TRUE)
   {
      char sz[160];
      memset(sz, 0, sizeof(sz));
      if (bPair == CK_TRUE)
      {
         GUI_SetLastObjectHandle(hPriv);
         _snprintf(sz, sizeof(sz) - 1,
            "Private handle %lu\nPublic handle %lu",
            (unsigned long)hPriv, (unsigned long)hPub);
      }
      else
      {
         GUI_SetLastObjectHandle(hKey);
         _snprintf(sz, sizeof(sz) - 1, "Generated. Handle %lu.", (unsigned long)hKey);
      }
      DlgGenerate_SetStatus(sz);
   }
   else
   {
      DlgGenerate_SetStatus("Generate failed. Check type, size, domain, and partition policy.");
   }
}

static HWND DlgGenerate_CreateLabel(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("STATIC", sText, WS_CHILD | WS_VISIBLE,
      0, 0, DLG_LABEL_W, 16, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static HWND DlgGenerate_CreateEdit(HWND hWnd, int id)
{
   return CreateWindowA("EDIT", "",
      WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
      0, 0, 200, DLG_EDIT_H, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static HWND DlgGenerate_CreateCombo(HWND hWnd, int id, BOOL bEdit)
{
   HWND hCombo;
   DWORD dwStyle = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL;
   dwStyle |= bEdit ? (CBS_DROPDOWN | CBS_AUTOHSCROLL) : CBS_DROPDOWNLIST;
   hCombo = CreateWindowA("COMBOBOX", "",
      dwStyle, 0, 0, 200, DLG_COMBO_DROP, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
   if ((hCombo != NULL) && bEdit)
   {
      COMBOBOXINFO info;
      LONG_PTR lStyle;

      memset(&info, 0, sizeof(info));
      info.cbSize = sizeof(info);
      if ((GetComboBoxInfo(hCombo, &info) != FALSE) && (info.hwndItem != NULL))
      {
         lStyle = GetWindowLongPtrA(info.hwndItem, GWL_STYLE);
         SetWindowLongPtrA(info.hwndItem, GWL_STYLE, lStyle & ~(LONG_PTR)ES_NOHIDESEL);
      }
   }
   return hCombo;
}

static HWND DlgGenerate_CreateCheck(HWND hWnd, const char* sText, int id)
{
   return CreateWindowA("BUTTON", sText,
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
      0, 0, 90, 18, hWnd, (HMENU)(INT_PTR)id, NULL, NULL);
}

static LRESULT CALLBACK DlgGenerate_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   switch (uMsg)
   {
   case WM_CREATE:
      {
         HWND hCtrl;
         int iLevel;
         char szLvl[16];

         s_hDlg = hWnd;
         s_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

         DlgGenerate_CreateLabel(hWnd, "Type:", IDC_GEN_LBL_TYPE);
         s_hType = DlgGenerate_CreateCombo(hWnd, IDC_GEN_TYPE, FALSE);
         DlgGenerate_CreateLabel(hWnd, "Label:", IDC_GEN_LBL_LABEL);
         s_hLabel = DlgGenerate_CreateEdit(hWnd, IDC_GEN_LABEL);
         DlgGenerate_CreateLabel(hWnd, "Public:", IDC_GEN_LBL_PUB);
         s_hLabelPub = DlgGenerate_CreateEdit(hWnd, IDC_GEN_LABEL_PUB);
         DlgGenerate_CreateLabel(hWnd, "Private:", IDC_GEN_LBL_PRIV);
         s_hLabelPriv = DlgGenerate_CreateEdit(hWnd, IDC_GEN_LABEL_PRIV);
         DlgGenerate_CreateLabel(hWnd, "CKA_ID:", IDC_GEN_LBL_ID);
         s_hId = DlgGenerate_CreateEdit(hWnd, IDC_GEN_ID);

         s_hLblParam = DlgGenerate_CreateLabel(hWnd, "Size:", IDC_GEN_LBL_PARAM);
         s_hParam = DlgGenerate_CreateCombo(hWnd, IDC_GEN_PARAM, FALSE);
         s_hLblMech = DlgGenerate_CreateLabel(hWnd, "Mech:", IDC_GEN_LBL_MECH);
         s_hMech = DlgGenerate_CreateCombo(hWnd, IDC_GEN_MECH, FALSE);
         s_hLblExp = DlgGenerate_CreateLabel(hWnd, "Exp:", IDC_GEN_LBL_EXP);
         s_hExp = DlgGenerate_CreateCombo(hWnd, IDC_GEN_EXP, TRUE);

         DlgGenerate_CreateLabel(hWnd, "Prime:", IDC_GEN_LBL_PRIME);
         s_hPrime = DlgGenerate_CreateEdit(hWnd, IDC_GEN_PRIME);
         DlgGenerate_CreateLabel(hWnd, "Base:", IDC_GEN_LBL_BASE);
         s_hBase = DlgGenerate_CreateEdit(hWnd, IDC_GEN_BASE);
         DlgGenerate_CreateLabel(hWnd, "Subprime:", IDC_GEN_LBL_SUB);
         s_hSubprime = DlgGenerate_CreateEdit(hWnd, IDC_GEN_SUBPRIME);
         DlgGenerate_CreateLabel(hWnd, "HSS level:", IDC_GEN_LBL_LEVEL);
         s_hLevel = DlgGenerate_CreateCombo(hWnd, IDC_GEN_LEVEL, FALSE);

         for (iLevel = 0; iLevel < MAX_HSS_LEVEL; iLevel++)
         {
            memset(szLvl, 0, sizeof(szLvl));
            _snprintf(szLvl, sizeof(szLvl) - 1, "LMS %d:", iLevel + 1);
            s_hLblLms[iLevel] = DlgGenerate_CreateLabel(hWnd, szLvl, IDC_GEN_LBL_LMS + iLevel);
            s_hLms[iLevel] = DlgGenerate_CreateCombo(hWnd, IDC_GEN_LMS + iLevel, FALSE);
            s_hLblLmots[iLevel] = DlgGenerate_CreateLabel(hWnd, "OTS:", IDC_GEN_LBL_LMOTS + iLevel);
            s_hLmots[iLevel] = DlgGenerate_CreateCombo(hWnd, IDC_GEN_LMOTS + iLevel, FALSE);
         }

         DlgGenerate_CreateLabel(hWnd, "Components:", IDC_GEN_LBL_COMP);
         s_hComp = DlgGenerate_CreateCombo(hWnd, IDC_GEN_COMP, FALSE);

         s_hToken = DlgGenerate_CreateCheck(hWnd, "Token", IDC_GEN_TOKEN);
         s_hPrivate = DlgGenerate_CreateCheck(hWnd, "Private", IDC_GEN_PRIVATE);
         s_hSensitive = DlgGenerate_CreateCheck(hWnd, "Sensitive", IDC_GEN_SENSITIVE);
         s_hExtractable = DlgGenerate_CreateCheck(hWnd, "Extractable", IDC_GEN_EXTRACTABLE);
         s_hModifiable = DlgGenerate_CreateCheck(hWnd, "Modifiable", IDC_GEN_MODIFIABLE);
         s_hEncrypt = DlgGenerate_CreateCheck(hWnd, "Encrypt", IDC_GEN_ENCRYPT);
         s_hDecrypt = DlgGenerate_CreateCheck(hWnd, "Decrypt", IDC_GEN_DECRYPT);
         s_hSign = DlgGenerate_CreateCheck(hWnd, "Sign", IDC_GEN_SIGN);
         s_hVerify = DlgGenerate_CreateCheck(hWnd, "Verify", IDC_GEN_VERIFY);
         s_hWrap = DlgGenerate_CreateCheck(hWnd, "Wrap", IDC_GEN_WRAP);
         s_hUnwrap = DlgGenerate_CreateCheck(hWnd, "Unwrap", IDC_GEN_UNWRAP);
         s_hDerive = DlgGenerate_CreateCheck(hWnd, "Derive", IDC_GEN_DERIVE);
         s_hEncapsulate = DlgGenerate_CreateCheck(hWnd, "Encapsulate", IDC_GEN_ENCAPSULATE);
         s_hDecapsulate = DlgGenerate_CreateCheck(hWnd, "Decapsulate", IDC_GEN_DECAPSULATE);

         s_hStatus = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX | SS_EDITCONTROL,
            0, 0, 200, 32, hWnd, (HMENU)(INT_PTR)IDC_GEN_STATUS, NULL, NULL);

         CreateWindowA("BUTTON", "Generate",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_GEN_GENERATE, NULL, NULL);
         CreateWindowA("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, DLG_BTN_W, DLG_BTN_H, hWnd, (HMENU)(INT_PTR)IDC_GEN_CLOSE, NULL, NULL);

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
         SendMessageA(s_hUnwrap, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hDerive, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hEncapsulate, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hDecapsulate, BM_SETCHECK, BST_CHECKED, 0);
         SendMessageA(s_hLabel, EM_SETLIMITTEXT, DLG_MAX_LABEL - 1, 0);
         SendMessageA(s_hLabelPub, EM_SETLIMITTEXT, DLG_MAX_LABEL - 1, 0);
         SendMessageA(s_hLabelPriv, EM_SETLIMITTEXT, DLG_MAX_LABEL - 1, 0);
         SendMessageA(s_hId, EM_SETLIMITTEXT, (DLG_CKA_ID_MAX * 2) - 1, 0);
         SendMessageA(s_hPrime, EM_SETLIMITTEXT, DLG_HEX_MAX - 1, 0);
         SendMessageA(s_hBase, EM_SETLIMITTEXT, DLG_HEX_MAX - 1, 0);
         SendMessageA(s_hSubprime, EM_SETLIMITTEXT, DLG_HEX_MAX - 1, 0);

         SendMessageA(s_hComp, CB_ADDSTRING, 0, (LPARAM)"None");
         SendMessageA(s_hComp, CB_SETITEMDATA, 0, 0);
         for (iLevel = 2; iLevel <= 16; iLevel++)
         {
            char szN[8];
            int iItem;
            memset(szN, 0, sizeof(szN));
            _snprintf(szN, sizeof(szN) - 1, "%d", iLevel);
            iItem = (int)SendMessageA(s_hComp, CB_ADDSTRING, 0, (LPARAM)szN);
            SendMessageA(s_hComp, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)iLevel);
         }
         SendMessageA(s_hComp, CB_SETCURSEL, 0, 0);

         for (iLevel = 1; iLevel <= MAX_HSS_LEVEL; iLevel++)
         {
            int iItem;
            memset(szLvl, 0, sizeof(szLvl));
            _snprintf(szLvl, sizeof(szLvl) - 1, "%d", iLevel);
            iItem = (int)SendMessageA(s_hLevel, CB_ADDSTRING, 0, (LPARAM)szLvl);
            SendMessageA(s_hLevel, CB_SETITEMDATA, (WPARAM)iItem, (LPARAM)iLevel);
         }
         SendMessageA(s_hLevel, CB_SETCURSEL, 1, 0);

         DlgGenerate_FillTypes();
         DlgGenerate_FillLmsCombos();
         DlgGenerate_FillParam();
         DlgGenerate_FillMechExp();

         for (hCtrl = GetWindow(hWnd, GW_CHILD); hCtrl != NULL; hCtrl = GetWindow(hCtrl, GW_HWNDNEXT))
         {
            SendMessageA(hCtrl, WM_SETFONT, (WPARAM)s_hFont, TRUE);
         }
      }
      return 0;

   case WM_SIZE:
      DlgGenerate_Layout(LOWORD(lParam), HIWORD(lParam));
      return 0;

   case WM_GETMINMAXINFO:
      {
         MINMAXINFO* pMin = (MINMAXINFO*)lParam;
         pMin->ptMinTrackSize.x = 540;
         pMin->ptMinTrackSize.y = 280;
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

   case WM_GEN_READY:
      if (wParam == 0)
      {
         SetFocus(s_hType);
      }
      DlgGenerate_ClearComboHighlight(s_hParam);
      DlgGenerate_ClearComboHighlight(s_hExp);
      return 0;

   case WM_COMMAND:
      switch (LOWORD(wParam))
      {
      case IDC_GEN_TYPE:
         if (HIWORD(wParam) == CBN_SELCHANGE)
         {
            DlgGenerate_OnTypeChanged();
            PostMessageA(hWnd, WM_GEN_READY, 0, 0);
         }
         return 0;
      case IDC_GEN_PARAM:
      case IDC_GEN_EXP:
         if (HIWORD(wParam) == CBN_SETFOCUS)
         {
            PostMessageA(hWnd, WM_GEN_READY, 1, 0);
         }
         return 0;
      case IDC_GEN_MECH:
      case IDC_GEN_LEVEL:
         if (HIWORD(wParam) == CBN_SELCHANGE)
         {
            RECT rc;
            GetClientRect(hWnd, &rc);
            DlgGenerate_Layout(rc.right - rc.left, rc.bottom - rc.top);
         }
         return 0;
      case IDC_GEN_GENERATE:
      case IDOK:
         DlgGenerate_DoGenerate();
         return 0;
      case IDC_GEN_CLOSE:
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
      DlgGenerate_FreeDomain();
      s_hDlg = NULL;
      s_hType = NULL;
      s_hLabel = NULL;
      s_hLabelPub = NULL;
      s_hLabelPriv = NULL;
      s_hId = NULL;
      s_hParam = NULL;
      s_hLblParam = NULL;
      s_hMech = NULL;
      s_hLblMech = NULL;
      s_hExp = NULL;
      s_hLblExp = NULL;
      s_hPrime = NULL;
      s_hBase = NULL;
      s_hSubprime = NULL;
      s_hLevel = NULL;
      s_hComp = NULL;
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
      s_hUnwrap = NULL;
      s_hDerive = NULL;
      s_hModifiable = NULL;
      s_hEncapsulate = NULL;
      s_hDecapsulate = NULL;
      memset(s_hLms, 0, sizeof(s_hLms));
      memset(s_hLmots, 0, sizeof(s_hLmots));
      s_bDone = TRUE;
      return 0;

   default:
      break;
   }

   return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

/*
    FUNCTION:        void DlgGenerate_Show(HWND hwndParent)
*/
void DlgGenerate_Show(HWND hwndParent)
{
   WNDCLASSEXA wc;
   HWND hDlg;
   MSG msg;
   RECT rc;

   memset(&wc, 0, sizeof(wc));
   wc.cbSize = sizeof(wc);
   wc.lpfnWndProc = DlgGenerate_WndProc;
   wc.hInstance = GetModuleHandleA(NULL);
   wc.hCursor = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = GUI_ThemeBgBrush();
   wc.lpszClassName = DLG_GEN_CLASS;
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

   hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, DLG_GEN_CLASS, "Generate key",
      WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX | WS_CLIPCHILDREN,
      rc.left + 40, rc.top + 40, 580, 420,
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
   PostMessageA(hDlg, WM_GEN_READY, 0, 0);

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
