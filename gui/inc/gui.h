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

#ifndef _GUI_H_
#define _GUI_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OS_WIN32
#include <windows.h>
#endif
#include "p11.h"
#include "p11query.h"

#define GUI_APP_TITLE             "Luna KMU"
#define GUI_WND_CLASS             "LunaKmuMainWnd"
#define GUI_STATUS_TEXT_MAX       512
#define GUI_PASSWORD_MAX          256
#define GUI_PATH_MAX              4096
#define GUI_CHRYSTOKI_ENV         "ChrystokiConfigurationPath"
#define GUI_DEFAULT_LUNA_CLIENT   "C:\\Program Files\\SafeNet\\LunaClient"
#define GUI_MAX_SLOT_ROWS         128
#define WM_GUI_START_LOAD         (WM_APP + 1)
#define WM_GUI_P11_DONE           (WM_APP + 2)

   typedef struct
   {
      CK_BBOOL      bOk;
      CK_BBOOL      bReload;
      char          szPath[GUI_PATH_MAX];
      char          szStatus[GUI_STATUS_TEXT_MAX];
      CK_ULONG      ulCount;
      P11_SLOT_ROW  rows[GUI_MAX_SLOT_ROWS];
   } GUI_LOAD_RESULT;

#ifdef _GUI_C
#define _EXT
#else
#define _EXT extern
#endif

   _EXT  CK_BBOOL GUI_InitPkcs11(void);
   _EXT  CK_BBOOL GUI_BeginLibraryLoad(HWND hwndNotify, const char* path, CK_BBOOL bReload);
   _EXT  CK_BBOOL GUI_IsLoadInProgress(void);
   _EXT  void     GUI_TermPkcs11(void);
   _EXT  CK_BBOOL GUI_IsLibraryLoaded(void);
   _EXT  void     GUI_GetLibraryStatus(char* buffer, unsigned int bufferSize);
   _EXT  void     GUI_GetChrystokiPath(char* buffer, unsigned int bufferSize);
   _EXT  CK_BBOOL GUI_SetChrystokiPath(const char* path);
   _EXT  CK_BBOOL GUI_IsSameLoadedPath(const char* path);
   _EXT  CK_BBOOL GUI_PreflightLibrary(const char* path, char* error, unsigned int errorSize);
   _EXT  void     GUI_SuggestDefaultChrystokiPath(char* buffer, unsigned int bufferSize);
   _EXT  void     GUI_SecureClear(void* buffer, unsigned int size);
   _EXT  void     GUI_SetLastObjectHandle(CK_OBJECT_HANDLE hObj);
   _EXT  CK_OBJECT_HANDLE GUI_GetLastObjectHandle(void);
   _EXT  CK_OBJECT_HANDLE GUI_ResolveKeyFromEdits(HWND hHandle, HWND hLabel, HWND hId,
                                                 char* err, unsigned int errMax);

#undef _EXT

#ifdef __cplusplus
}
#endif

#endif   /* _GUI_H_ */
