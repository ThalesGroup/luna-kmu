/****************************************************************************\
*
* This file is part of the "Luna KMU" tool.
*
* The "KMU" tool is provided under the MIT license (see the
* following Web site for further details: https://mit-license.org/ ).
*
* Author: Sebastien Chapellier
*
* Copyright © 2023-2024 Thales Group
*
\****************************************************************************/

#ifndef _KMU_H_
#define _KMU_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KMU_C
#define _EXT
#else
#define _EXT extern
#endif

   typedef CK_LONG(*P_ConsoleFunction)();

   _EXT CK_BBOOL kmu_exitConsole();
#ifdef _TRIALVERSION
   _EXT void kmu_checkTrial();
   _EXT void kmu_checkTrialChecksum();
#endif
#undef _EXT

#endif