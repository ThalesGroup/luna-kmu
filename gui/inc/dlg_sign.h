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

#ifndef _DLG_SIGN_H_
#define _DLG_SIGN_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OS_WIN32
#include <windows.h>
#endif
#include "p11.h"

#ifdef _DLG_SIGN_C
#define _EXT
#else
#define _EXT extern
#endif

   /* bVerify CK_FALSE = sign file, CK_TRUE = verify signature. */
   _EXT  void DlgSign_Show(HWND hwndParent, CK_BBOOL bVerify);

#undef _EXT

#ifdef __cplusplus
}
#endif

#endif   /* _DLG_SIGN_H_ */
