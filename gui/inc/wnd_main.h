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

#ifndef _WND_MAIN_H_
#define _WND_MAIN_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OS_WIN32
#include <windows.h>
#endif

#define IDC_LIST_SLOTS            1001
#define IDC_BTN_REFRESH           1002
#define IDC_LBL_PASSWORD          1003
#define IDC_EDIT_PASSWORD         1004
#define IDC_CHK_CRYPTO_USER       1005
#define IDC_BTN_LOGIN             1006
#define IDC_BTN_LOGOUT            1007
#define IDC_STATUS                1008
#define IDC_LBL_CLIENT_PATH       1009
#define IDC_EDIT_CLIENT_PATH      1010
#define IDC_BTN_BROWSE            1011
#define IDC_BTN_LIST_KEYS         1012
#define IDC_BTN_GENERATE          1013
#define IDC_BTN_CREATEDO          1014
#define IDC_BTN_IMPORT            1015
#define IDC_BTN_EXPORT            1016
#define IDC_BTN_MORE              1017
#define IDM_FILE_EXIT             40001
#define IDM_HELP_ABOUT            40002
#define IDM_FILE_CAPABILITIES     40003
#define IDM_FILE_CONVERT          40004
#define IDM_MORE_ENCRYPT          40010
#define IDM_MORE_DECRYPT          40011
#define IDM_MORE_SIGN             40012
#define IDM_MORE_VERIFY           40013
#define IDM_MORE_DERIVE           40014
#define IDM_MORE_MZMK             40015

#ifdef _WND_MAIN_C
#define _EXT
#else
#define _EXT extern
#endif

   _EXT  ATOM  WndMain_Register(HINSTANCE hInstance);
   _EXT  HWND  WndMain_Create(HINSTANCE hInstance, int nCmdShow);

#undef _EXT

#ifdef __cplusplus
}
#endif

#endif   /* _WND_MAIN_H_ */
