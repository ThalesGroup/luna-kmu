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

#ifndef _CONSOLE_H_
#define _CONSOLE_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _CONSOLE_C_
#define _EXT
#else
#define _EXT extern
#endif

   typedef struct console_autocomplete_match
   {
      CK_ULONG uMatchCommandIndex;
      CK_ULONG uOffsetMatch;
      CK_BBOOL bMatch;

   }CONSOLE_AUTOCOMPLETE_MATCH;


   _EXT  CK_ULONG       Console_RequestInteger();
   _EXT  CK_ULONG       Console_RequestHexString();
   _EXT  CK_LONG        Console_RequestString();
   _EXT  CK_CHAR_PTR    Console_GetBuffer();
   _EXT  CK_ULONG       Console_RequestPassword();
   _EXT  CK_LONG        Console_RequestStringWithAutoComplete();
   _EXT  CK_BBOOL       Console_Init();
   _EXT  CK_BBOOL       Console_Terminate();
   _EXT  CK_BBOOL       Console_SetAutocompleteList(CK_CHAR_PTR* pList, CK_ULONG uListNumber);

   _EXT  void           Console_TerminalCursorChangeVisibility(CK_BBOOL show);
   _EXT  void           Console_TerminalCursorChangeSize(CK_BBOOL bBigSize);
   _EXT  void           Console_TerminalDeleteCharactersEndOfLine(CK_ULONG uLength);
   _EXT  CK_BBOOL       Console_TerminalCursorMove(CK_BBOOL bDirection, CK_ULONG sValue);
   _EXT  void           Console_TerminalCursorMoveEndOfLine();
   _EXT  void           Console_TerminalCursorMoveLeft();
   _EXT  void           Console_TerminalCursorMoveRigth();
   _EXT  void           Console_TerminalDelete(CK_ULONG uLength);
   _EXT  void           Console_TerminalDeleteLine();
   _EXT  void           Console_TerminalDeleteCharacterMiddleOfLine(CK_BBOOL isBack);
   _EXT  void           Console_TerminalCursorMoveBeginingOfLine();
   _EXT  CK_BBOOL       Console_TerminalCursorIsEndOfLine();
   _EXT  void           Console_TerminalWriteCharactersMiddleOfLine(CK_CHAR_PTR sString);
   _EXT  void           Console_TerminalWriteCharactersEndOfLine(CK_CHAR_PTR sString, CK_BBOOL bInsertMode);
   _EXT CK_CHAR         Console_KeyBoardGetCharacter();
   _EXT  void           Console_KeyBoardOtherCharacter(CK_CHAR_PTR sChar);
   _EXT  void           Console_HistoryCurrentSaveLine();
   _EXT  void           Console_AutoComplete();
   _EXT  void           Console_AutoCompleteFirst();
   _EXT  void           Console_AutoCompleteNext();
   _EXT  void           Console_AutoCompleteStop(CK_CHAR_PTR sChar);
   _EXT  void           Console_KeyBoardEscape();
   _EXT  void           Console_KeyBoardBack();
   _EXT  CK_ULONG       Console_KeyBoardReturn();
   _EXT  void           Console_KeyBoardInsert();
   _EXT  void           Console_HistoryMove(CK_BYTE bDirection);
   _EXT  void           Console_KeyBoardDelete();
   _EXT  void           Console_Clear();


#undef _EXT
#endif // _CONSOLE_H_