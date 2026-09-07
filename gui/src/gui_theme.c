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

#define _GUI_THEME_C

#ifdef OS_WIN32
#include <windows.h>
#include <commctrl.h>
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "p11.h"
#include "p11util.h"
#include "p11query.h"
#include "gui_theme.h"

/* Quiet Luna-like palette — window tint only, no row/header highlights. */
#define GUI_RGB_BG         RGB(226, 234, 240)
#define GUI_RGB_NAVY       RGB(11, 61, 92)
#define GUI_RGB_TEXT       RGB(26, 35, 50)
#define GUI_RGB_EDIT       RGB(255, 255, 255)
#define GUI_RGB_LIST       RGB(255, 255, 255)

static HBRUSH s_hbrBg = NULL;
static HBRUSH s_hbrEdit = NULL;

static void GUI_ThemeUpperCopy(char* dest, unsigned int destSize, const char* src)
{
   unsigned int uLoop;

   memset(dest, 0, destSize);
   if ((src == NULL) || (destSize == 0))
   {
      return;
   }
   for (uLoop = 0; (uLoop + 1) < destSize && src[uLoop] != 0; uLoop++)
   {
      dest[uLoop] = (char)toupper((unsigned char)src[uLoop]);
   }
}

/*
    FUNCTION:        void GUI_ThemeInit(void)
*/
void GUI_ThemeInit(void)
{
   if (s_hbrBg == NULL)
   {
      s_hbrBg = CreateSolidBrush(GUI_RGB_BG);
   }
   if (s_hbrEdit == NULL)
   {
      s_hbrEdit = CreateSolidBrush(GUI_RGB_EDIT);
   }
}

/*
    FUNCTION:        void GUI_ThemeTerm(void)
*/
void GUI_ThemeTerm(void)
{
   if (s_hbrBg != NULL)
   {
      DeleteObject(s_hbrBg);
      s_hbrBg = NULL;
   }
   if (s_hbrEdit != NULL)
   {
      DeleteObject(s_hbrEdit);
      s_hbrEdit = NULL;
   }
}

/*
    FUNCTION:        HBRUSH GUI_ThemeBgBrush(void)
*/
HBRUSH GUI_ThemeBgBrush(void)
{
   return (s_hbrBg != NULL) ? s_hbrBg : (HBRUSH)(COLOR_3DFACE + 1);
}

/*
    FUNCTION:        void GUI_ThemeMarkStatus(HWND hCtrl)
*/
void GUI_ThemeMarkStatus(HWND hCtrl)
{
   (void)hCtrl;
}

/*
    FUNCTION:        void GUI_ThemeStyleList(HWND hList)
*/
void GUI_ThemeStyleList(HWND hList)
{
   if (hList == NULL)
   {
      return;
   }

   ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);
   ListView_SetBkColor(hList, GUI_RGB_LIST);
   ListView_SetTextBkColor(hList, GUI_RGB_LIST);
   ListView_SetTextColor(hList, GUI_RGB_TEXT);
}

/*
    FUNCTION:        LRESULT GUI_ThemeCtlColor(...)
*/
LRESULT GUI_ThemeCtlColor(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
   HDC hdc = (HDC)wParam;
   HWND hCtrl = (HWND)lParam;

   if (uMsg == WM_CTLCOLOREDIT)
   {
      SetTextColor(hdc, GUI_RGB_TEXT);
      SetBkColor(hdc, GUI_RGB_EDIT);
      SetBkMode(hdc, OPAQUE);
      return (LRESULT)s_hbrEdit;
   }

   if ((uMsg == WM_CTLCOLORSTATIC) || (uMsg == WM_CTLCOLORBTN))
   {
      (void)hCtrl;
      SetTextColor(hdc, GUI_RGB_NAVY);
      SetBkColor(hdc, GUI_RGB_BG);
      SetBkMode(hdc, TRANSPARENT);
      return (LRESULT)s_hbrBg;
   }

   return 0;
}

/*
    FUNCTION:        void GUI_FormatKeyTypeName(...)
*/
void GUI_FormatKeyTypeName(CK_KEY_TYPE keyType, char* buffer, unsigned int bufferSize)
{
   const char* pName;
   unsigned int uLoop;
   static const struct
   {
      const char* src;
      const char* dst;
   } map[] = {
      { "aes", "AES" },
      { "sm4", "SM4" },
      { "des", "DES" },
      { "des2", "DES2" },
      { "des3", "DES3" },
      { "rsa", "RSA" },
      { "rsa-pkcs", "RSA-PKCS" },
      { "rsa-prime", "RSA-PRIME" },
      { "rsa-aux", "RSA-AUX" },
      { "ecdsa", "ECDSA" },
      { "eddsa", "EdDSA" },
      { "montgomery", "ECDH" },
      { "sm2", "SM2" },
      { "hmac", "HMAC" },
      { "dh", "DH" },
      { "dsa", "DSA" },
      { "dh-x9.42", "DH-X9.42" },
      { "genericsecret", "GENERIC" },
      { "ml-dsa", "ML-DSA" },
      { "ml-kem", "ML-KEM" },
      { "lms", "LMS" },
      { "hss", "HSS" },
      { "kea", "KEA" },
      { "rc2", "RC2" },
      { "rc4", "RC4" },
      { "rc5", "RC5" },
      { "cast", "CAST" },
      { "cast3", "CAST3" },
      { "cast5", "CAST5" },
      { "cast128", "CAST128" },
      { "kcdsa", "KCDSA" },
      { "korean seed", "SEED" },
      { "bip32", "BIP32" },
      { "idea", "IDEA" },
   };

   if ((buffer == NULL) || (bufferSize == 0))
   {
      return;
   }
   memset(buffer, 0, bufferSize);

   if (keyType == P11_KEY_TYPE_NONE)
   {
      return;
   }

   pName = (const char*)P11Util_DisplayKeyTypeName(keyType);
   if ((pName == NULL) || (pName[0] == 0))
   {
      return;
   }

   for (uLoop = 0; uLoop < (unsigned int)(sizeof(map) / sizeof(map[0])); uLoop++)
   {
      if (_stricmp(pName, map[uLoop].src) == 0)
      {
         strncpy(buffer, map[uLoop].dst, bufferSize - 1);
         return;
      }
   }

   if (_stricmp(pName, "Unknown") == 0)
   {
      return;
   }

   GUI_ThemeUpperCopy(buffer, bufferSize, pName);
}

/*
    FUNCTION:        void GUI_FormatKeyTypeCliName(...)
*/
void GUI_FormatKeyTypeCliName(const char* cliName, char* buffer, unsigned int bufferSize)
{
   unsigned int uLoop;
   static const struct
   {
      const char* src;
      const char* dst;
   } map[] = {
      { "aes", "AES" },
      { "sm4", "SM4" },
      { "des", "DES" },
      { "hmac", "HMAC" },
      { "genericsecret", "Generic secret" },
      { "rsa", "RSA" },
      { "rsa-pkcs", "RSA-PKCS" },
      { "rsa-prime", "RSA-PRIME" },
      { "rsa-aux", "RSA-AUX" },
      { "des2", "DES2" },
      { "des3", "DES3" },
      { "ecdsa", "ECDSA" },
      { "eddsa", "EdDSA" },
      { "montgomery", "ECDH" },
      { "sm2", "SM2" },
      { "dh", "DH" },
      { "dh-x9.42", "DH-X9.42" },
      { "dsa", "DSA" },
      { "ml-dsa", "ML-DSA" },
      { "ml-kem", "ML-KEM" },
      { "lms", "LMS" },
      { "hss", "HSS" },
   };

   if ((buffer == NULL) || (bufferSize == 0))
   {
      return;
   }
   memset(buffer, 0, bufferSize);
   if ((cliName == NULL) || (cliName[0] == 0))
   {
      return;
   }
   for (uLoop = 0; uLoop < (unsigned int)(sizeof(map) / sizeof(map[0])); uLoop++)
   {
      if (_stricmp(cliName, map[uLoop].src) == 0)
      {
         strncpy(buffer, map[uLoop].dst, bufferSize - 1);
         return;
      }
   }
   GUI_ThemeUpperCopy(buffer, bufferSize, cliName);
}
