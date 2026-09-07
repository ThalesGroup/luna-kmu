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

#ifndef _GUI_THEME_H_
#define _GUI_THEME_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OS_WIN32
#include <windows.h>
#endif
#include "p11.h"

#ifdef _GUI_THEME_C
#define _EXT
#else
#define _EXT extern
#endif

   _EXT  void     GUI_ThemeInit(void);
   _EXT  void     GUI_ThemeTerm(void);
   _EXT  HBRUSH   GUI_ThemeBgBrush(void);
   _EXT  void     GUI_ThemeMarkStatus(HWND hCtrl);
   _EXT  void     GUI_ThemeStyleList(HWND hList);
   _EXT  LRESULT  GUI_ThemeCtlColor(UINT uMsg, WPARAM wParam, LPARAM lParam);
   _EXT  void     GUI_FormatKeyTypeName(CK_KEY_TYPE keyType, char* buffer, unsigned int bufferSize);
   _EXT  void     GUI_FormatKeyTypeCliName(const char* cliName, char* buffer, unsigned int bufferSize);

#undef _EXT

#ifdef __cplusplus
}
#endif

#endif   /* _GUI_THEME_H_ */
