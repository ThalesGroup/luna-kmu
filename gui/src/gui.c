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

#define _GUI_C

#ifdef OS_WIN32
#include <windows.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <objbase.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "p11query.h"
#include "gui.h"
#include "gui_theme.h"
#include "wnd_main.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

static CK_BBOOL s_bLibraryLoaded = CK_FALSE;
static char     s_szLibraryStatus[GUI_STATUS_TEXT_MAX];
static char     s_szLoadedPath[GUI_PATH_MAX];
static HANDLE   s_hLoadThread = NULL;
static volatile LONG s_lLoadBusy = 0;
static volatile LONG s_lShutdown = 0;
static HWND     s_hLoadNotify = NULL;
static CK_OBJECT_HANDLE s_hLastObject = 0;

static void GUI_CopyPath(char* dest, unsigned int destSize, const char* src)
{
   memset(dest, 0, destSize);
   if ((src != NULL) && (destSize > 0))
   {
      strncpy(dest, src, destSize - 1);
   }
}

static void GUI_TrimPath(char* path)
{
   char* pStart;
   size_t uLen;

   if (path == NULL)
   {
      return;
   }

   pStart = path;
   while ((*pStart == ' ') || (*pStart == '\t') || (*pStart == '"'))
   {
      pStart++;
   }
   if (pStart != path)
   {
      memmove(path, pStart, strlen(pStart) + 1);
   }

   uLen = strlen(path);
   while (uLen > 0)
   {
      char c = path[uLen - 1];
      if ((c == ' ') || (c == '\t') || (c == '"') || (c == '\r') || (c == '\n'))
      {
         path[uLen - 1] = 0;
         uLen--;
      }
      else
      {
         break;
      }
   }
}

static void GUI_SetLibraryStatus(const char* sText)
{
   memset(s_szLibraryStatus, 0, sizeof(s_szLibraryStatus));
   if (sText != NULL)
   {
      strncpy(s_szLibraryStatus, sText, sizeof(s_szLibraryStatus) - 1);
   }
}

static void GUI_ResolveCryptokiPath(const char* path, char* dllPath, unsigned int dllPathSize);

/*
    FUNCTION:        CK_BBOOL GUI_InitPkcs11(void)
*/
CK_BBOOL GUI_InitPkcs11(void)
{
   P11_Init();
   return CK_TRUE;
}

static CK_BBOOL GUI_LoadLibrarySafe(void)
{
   CK_BBOOL bOk = CK_FALSE;

   __try
   {
      bOk = P11_LoadLibrary();
   }
   __except(EXCEPTION_EXECUTE_HANDLER)
   {
      GUI_SetLibraryStatus("PKCS#11 library failed while loading. Check ChrystokiConfigurationPath.");
      __try
      {
         P11_Terminate();
      }
      __except(EXCEPTION_EXECUTE_HANDLER)
      {
      }
      P11_Init();
      s_bLibraryLoaded = CK_FALSE;
      memset(s_szLoadedPath, 0, sizeof(s_szLoadedPath));
      return CK_FALSE;
   }

   if (bOk == CK_TRUE)
   {
      s_bLibraryLoaded = CK_TRUE;
      GUI_GetChrystokiPath(s_szLoadedPath, sizeof(s_szLoadedPath));
      GUI_SetLibraryStatus("PKCS#11 library loaded.");
      return CK_TRUE;
   }

   s_bLibraryLoaded = CK_FALSE;
   memset(s_szLoadedPath, 0, sizeof(s_szLoadedPath));
   GUI_SetLibraryStatus("Failed to load PKCS#11 library. Check ChrystokiConfigurationPath.");
   return CK_FALSE;
}

/*
    FUNCTION:        void GUI_TermPkcs11(void)
*/
void GUI_TermPkcs11(void)
{
   InterlockedExchange(&s_lShutdown, 1);
   if (s_hLoadThread != NULL)
   {
      WaitForSingleObject(s_hLoadThread, 8000);
      CloseHandle(s_hLoadThread);
      s_hLoadThread = NULL;
   }
   InterlockedExchange(&s_lLoadBusy, 0);

   if (P11_IsLoggedIn() == CK_TRUE)
   {
      P11_Logout();
   }
   __try
   {
      P11_Terminate();
   }
   __except(EXCEPTION_EXECUTE_HANDLER)
   {
   }
   s_bLibraryLoaded = CK_FALSE;
   memset(s_szLoadedPath, 0, sizeof(s_szLoadedPath));
   s_hLastObject = 0;
}

void GUI_SetLastObjectHandle(CK_OBJECT_HANDLE hObj)
{
   s_hLastObject = hObj;
}

CK_OBJECT_HANDLE GUI_GetLastObjectHandle(void)
{
   return s_hLastObject;
}

/*
    FUNCTION:        CK_OBJECT_HANDLE GUI_ResolveKeyFromEdits(...)
*/
CK_OBJECT_HANDLE GUI_ResolveKeyFromEdits(HWND hHandle, HWND hLabel, HWND hId,
   char* err, unsigned int errMax)
{
   char szHandle[64];
   char szLabel[256];
   char szId[256];

   szHandle[0] = 0;
   szLabel[0] = 0;
   szId[0] = 0;
   if (hHandle != NULL)
   {
      GetWindowTextA(hHandle, szHandle, sizeof(szHandle));
   }
   if (hLabel != NULL)
   {
      GetWindowTextA(hLabel, szLabel, sizeof(szLabel));
   }
   if (hId != NULL)
   {
      GetWindowTextA(hId, szId, sizeof(szId));
   }
   return P11_QueryResolveKey(szHandle, szLabel, szId, err, (CK_ULONG)errMax);
}

/*
    FUNCTION:        CK_BBOOL GUI_IsLibraryLoaded(void)
*/
CK_BBOOL GUI_IsLibraryLoaded(void)
{
   return s_bLibraryLoaded;
}

/*
    FUNCTION:        void GUI_GetLibraryStatus(char* buffer, unsigned int bufferSize)
*/
void GUI_GetLibraryStatus(char* buffer, unsigned int bufferSize)
{
   if ((buffer == NULL) || (bufferSize == 0))
   {
      return;
   }
   memset(buffer, 0, bufferSize);
   strncpy(buffer, s_szLibraryStatus, bufferSize - 1);
}

/*
    FUNCTION:        void GUI_GetChrystokiPath(char* buffer, unsigned int bufferSize)
*/
void GUI_GetChrystokiPath(char* buffer, unsigned int bufferSize)
{
   DWORD nCopied;
   const char* pPath;

   if ((buffer == NULL) || (bufferSize == 0))
   {
      return;
   }

   memset(buffer, 0, bufferSize);

   /* Report the value P11_GetLibrary will see (it reads the process env via getenv). */
   nCopied = GetEnvironmentVariableA(GUI_CHRYSTOKI_ENV, buffer, bufferSize);
   if ((nCopied > 0) && (nCopied < bufferSize))
   {
      GUI_TrimPath(buffer);
      if (buffer[0] != 0)
      {
         return;
      }
   }

   memset(buffer, 0, bufferSize);
   pPath = getenv(GUI_CHRYSTOKI_ENV);
   if (pPath != NULL)
   {
      strncpy(buffer, pPath, bufferSize - 1);
      GUI_TrimPath(buffer);
   }
}

/*
    FUNCTION:        CK_BBOOL GUI_SetChrystokiPath(const char* path)
*/
CK_BBOOL GUI_SetChrystokiPath(const char* path)
{
   char szPath[GUI_PATH_MAX];
   char szEnv[GUI_PATH_MAX + 40];

   memset(szPath, 0, sizeof(szPath));
   if (path != NULL)
   {
      strncpy(szPath, path, sizeof(szPath) - 1);
   }
   GUI_TrimPath(szPath);

   if (szPath[0] == 0)
   {
      _putenv(GUI_CHRYSTOKI_ENV "=");
      SetEnvironmentVariableA(GUI_CHRYSTOKI_ENV, NULL);
      return CK_FALSE;
   }

   memset(szEnv, 0, sizeof(szEnv));
   sprintf(szEnv, "%s=%s", GUI_CHRYSTOKI_ENV, szPath);
   _putenv(szEnv);
   SetEnvironmentVariableA(GUI_CHRYSTOKI_ENV, szPath);
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL GUI_IsSameLoadedPath(const char* path)
*/
CK_BBOOL GUI_IsSameLoadedPath(const char* path)
{
   char szPath[GUI_PATH_MAX];

   if (s_bLibraryLoaded != CK_TRUE)
   {
      return CK_FALSE;
   }

   memset(szPath, 0, sizeof(szPath));
   if (path != NULL)
   {
      strncpy(szPath, path, sizeof(szPath) - 1);
   }
   GUI_TrimPath(szPath);

   if (lstrcmpiA(s_szLoadedPath, szPath) == 0)
   {
      return CK_TRUE;
   }
   return CK_FALSE;
}

/*
    FUNCTION:        void GUI_SuggestDefaultChrystokiPath(char* buffer, unsigned int bufferSize)
*/
void GUI_SuggestDefaultChrystokiPath(char* buffer, unsigned int bufferSize)
{
   if ((buffer == NULL) || (bufferSize == 0))
   {
      return;
   }

   /* Default Luna Client install. Users with that layout should not need to edit. */
   GUI_CopyPath(buffer, bufferSize, GUI_DEFAULT_LUNA_CLIENT);
}

static void GUI_ResolveCryptokiPath(const char* path, char* dllPath, unsigned int dllPathSize)
{
   size_t uLen;
   const char* pExt = ".dll";

   GUI_CopyPath(dllPath, dllPathSize, path);
   GUI_TrimPath(dllPath);
   uLen = strlen(dllPath);
   if (uLen == 0)
   {
      return;
   }

   if ((uLen >= 4) && (lstrcmpiA(&dllPath[uLen - 4], pExt) == 0))
   {
      return;
   }

   if (dllPath[uLen - 1] != '\\')
   {
      if ((uLen + 1) < dllPathSize)
      {
         dllPath[uLen] = '\\';
         dllPath[uLen + 1] = 0;
         uLen++;
      }
   }
   if ((uLen + strlen("cryptoki.dll")) < dllPathSize)
   {
      strcat(dllPath, "cryptoki.dll");
   }
}

/*
    FUNCTION:        CK_BBOOL GUI_PreflightLibrary(const char* path, char* error, unsigned int errorSize)
*/
CK_BBOOL GUI_PreflightLibrary(const char* path, char* error, unsigned int errorSize)
{
   char szDll[GUI_PATH_MAX];

   memset(szDll, 0, sizeof(szDll));
   GUI_ResolveCryptokiPath(path, szDll, sizeof(szDll));

   if (szDll[0] == 0)
   {
      if ((error != NULL) && (errorSize > 0))
      {
         strncpy(error, "ChrystokiConfigurationPath is not set. Paste or browse to the folder, then leave the field or click Refresh.", errorSize - 1);
      }
      return CK_FALSE;
   }

   if (PathFileExistsA(szDll) == FALSE)
   {
      if ((error != NULL) && (errorSize > 0))
      {
         _snprintf(error, errorSize - 1, "PKCS#11 library not found: %s", szDll);
         error[errorSize - 1] = 0;
      }
      return CK_FALSE;
   }
   return CK_TRUE;
}

CK_BBOOL GUI_IsLoadInProgress(void)
{
   return (s_lLoadBusy != 0) ? CK_TRUE : CK_FALSE;
}

static DWORD WINAPI GUI_LoadThreadProc(LPVOID pParam)
{
   GUI_LOAD_RESULT* pRes = (GUI_LOAD_RESULT*)pParam;
   HWND hwndNotify;
   char szError[GUI_STATUS_TEXT_MAX];

   if ((pRes == NULL) || (s_lShutdown != 0))
   {
      if (pRes != NULL)
      {
         free(pRes);
      }
      InterlockedExchange(&s_lLoadBusy, 0);
      return 0;
   }

   memset(szError, 0, sizeof(szError));
   pRes->bOk = CK_FALSE;
   pRes->ulCount = 0;

   if (GUI_SetChrystokiPath(pRes->szPath) != CK_TRUE)
   {
      strncpy(pRes->szStatus, "ChrystokiConfigurationPath is not set.", sizeof(pRes->szStatus) - 1);
      goto done;
   }

   if (GUI_PreflightLibrary(pRes->szPath, szError, sizeof(szError)) != CK_TRUE)
   {
      strncpy(pRes->szStatus, szError, sizeof(pRes->szStatus) - 1);
      goto done;
   }

   if (pRes->bReload == CK_TRUE)
   {
      if (P11_IsLoggedIn() == CK_TRUE)
      {
         strncpy(pRes->szStatus, "Logout before changing ChrystokiConfigurationPath.", sizeof(pRes->szStatus) - 1);
         goto done;
      }
      __try
      {
         P11_Terminate();
      }
      __except(EXCEPTION_EXECUTE_HANDLER)
      {
      }
      s_bLibraryLoaded = CK_FALSE;
      memset(s_szLoadedPath, 0, sizeof(s_szLoadedPath));
      P11_Init();
   }

   if (s_bLibraryLoaded != CK_TRUE)
   {
      if (GUI_LoadLibrarySafe() != CK_TRUE)
      {
         GUI_GetLibraryStatus(pRes->szStatus, sizeof(pRes->szStatus));
         goto done;
      }
   }

   __try
   {
      if (P11_QuerySlots(pRes->rows, GUI_MAX_SLOT_ROWS, &pRes->ulCount) == CK_TRUE)
      {
         pRes->bOk = CK_TRUE;
         if (pRes->ulCount == 0)
         {
            strncpy(pRes->szStatus, "No slots found.", sizeof(pRes->szStatus) - 1);
         }
         else
         {
            _snprintf(pRes->szStatus, sizeof(pRes->szStatus) - 1,
               "%lu slot(s).", (unsigned long)pRes->ulCount);
            pRes->szStatus[sizeof(pRes->szStatus) - 1] = 0;
         }
      }
      else
      {
         strncpy(pRes->szStatus, "Failed to query slots.", sizeof(pRes->szStatus) - 1);
      }
   }
   __except(EXCEPTION_EXECUTE_HANDLER)
   {
      strncpy(pRes->szStatus, "PKCS#11 library failed while querying slots. Check ChrystokiConfigurationPath.", sizeof(pRes->szStatus) - 1);
      pRes->bOk = CK_FALSE;
      pRes->ulCount = 0;
   }

done:
   hwndNotify = s_hLoadNotify;
   InterlockedExchange(&s_lLoadBusy, 0);
   if ((s_lShutdown == 0) && (hwndNotify != NULL) && (IsWindow(hwndNotify) != FALSE))
   {
      if (PostMessageA(hwndNotify, WM_GUI_P11_DONE, 0, (LPARAM)pRes) == FALSE)
      {
         free(pRes);
      }
   }
   else
   {
      free(pRes);
   }
   return 0;
}

/*
    FUNCTION:        CK_BBOOL GUI_BeginLibraryLoad(HWND hwndNotify, const char* path, CK_BBOOL bReload)
*/
CK_BBOOL GUI_BeginLibraryLoad(HWND hwndNotify, const char* path, CK_BBOOL bReload)
{
   GUI_LOAD_RESULT* pRes;

   if (InterlockedCompareExchange(&s_lLoadBusy, 1, 0) != 0)
   {
      GUI_SetLibraryStatus("PKCS#11 library is already loading.");
      return CK_FALSE;
   }

   pRes = (GUI_LOAD_RESULT*)calloc(1, sizeof(GUI_LOAD_RESULT));
   if (pRes == NULL)
   {
      InterlockedExchange(&s_lLoadBusy, 0);
      GUI_SetLibraryStatus("Out of memory.");
      return CK_FALSE;
   }

   pRes->bReload = bReload;
   if (path != NULL)
   {
      strncpy(pRes->szPath, path, sizeof(pRes->szPath) - 1);
   }

   s_hLoadNotify = hwndNotify;
   if (s_hLoadThread != NULL)
   {
      CloseHandle(s_hLoadThread);
      s_hLoadThread = NULL;
   }

   s_hLoadThread = CreateThread(NULL, 0, GUI_LoadThreadProc, pRes, 0, NULL);
   if (s_hLoadThread == NULL)
   {
      free(pRes);
      InterlockedExchange(&s_lLoadBusy, 0);
      GUI_SetLibraryStatus("Failed to start PKCS#11 load.");
      return CK_FALSE;
   }

   GUI_SetLibraryStatus("Loading PKCS#11 library...");
   return CK_TRUE;
}

/*
    FUNCTION:        void GUI_SecureClear(void* buffer, unsigned int size)
*/
void GUI_SecureClear(void* buffer, unsigned int size)
{
   if ((buffer == NULL) || (size == 0))
   {
      return;
   }
#ifdef OS_WIN32
   SecureZeroMemory(buffer, size);
#else
   memset(buffer, 0, size);
#endif
}

/*
    FUNCTION:        int WINAPI WinMain(...)
*/
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
   MSG msg;
   HWND hwndMain;
   INITCOMMONCONTROLSEX icc;

   (void)hPrevInstance;
   (void)lpCmdLine;

   CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

   memset(&icc, 0, sizeof(icc));
   icc.dwSize = sizeof(icc);
   icc.dwICC = ICC_LISTVIEW_CLASSES;
   InitCommonControlsEx(&icc);
   GUI_ThemeInit();

   /* Init PKCS#11 globals only (no library load). The first load runs on a
      worker thread, posted from WM_CREATE after the window is visible. */
   GUI_InitPkcs11();

   if (WndMain_Register(hInstance) == 0)
   {
      GUI_ThemeTerm();
      CoUninitialize();
      return 1;
   }

   hwndMain = WndMain_Create(hInstance, nCmdShow);
   if (hwndMain == NULL)
   {
      GUI_ThemeTerm();
      CoUninitialize();
      return 1;
   }

   while (GetMessageA(&msg, NULL, 0, 0) > 0)
   {
      if (!IsDialogMessageA(hwndMain, &msg))
      {
         TranslateMessage(&msg);
         DispatchMessageA(&msg);
      }
   }

   GUI_TermPkcs11();
   GUI_ThemeTerm();
   CoUninitialize();
   return (int)msg.wParam;
}
