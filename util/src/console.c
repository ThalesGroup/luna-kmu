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

#define _CONSOLE_C_

#ifdef OS_WIN32
#include <windows.h>
//#include <conio.h>
#else
#include <dlfcn.h>
#include <termios.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "console.h"
#include "str.h"

// alterative to _getch from conio.h
#define  CARACTER_BREAK                0x03
#define  CARACTER_BACK                 0x08
#define  CARACTER_TAB                  0x09
#define  CARACTER_ESC                  0x1B
#define  CARACTER_RETURN               0x0D
#define  CARACTER_NEWLINE              0x0A

#define EXTENDED_CODE                  0xE0
#define EXTENDED_CODE_ARROW_RIGTH      0x4B
#define EXTENDED_CODE_ARROW_LEFT       0x4D
#define EXTENDED_CODE_ARROW_UP         0x48
#define EXTENDED_CODE_ARROW_DOWN       0x50
#define EXTENDED_CODE_DELETE           0x53
#define EXTENDED_CODE_BEGIN            0x47
#define EXTENDED_CODE_END              0x4f
#define EXTENDED_CODE_PAGE_UP          0x49
#define EXTENDED_CODE_PAGE_DOWN        0x51
#define EXTENDED_CODE_INSERT           0x52

#define EXTENDED_CODE_F1               0x3B
#define EXTENDED_CODE_F2               0x3C
#define EXTENDED_CODE_F3               0x3D
#define EXTENDED_CODE_F4               0x3E
#define EXTENDED_CODE_F5               0x3F
#define EXTENDED_CODE_F6               0x40
#define EXTENDED_CODE_F7               0x41
#define EXTENDED_CODE_F8               0x42
#define EXTENDED_CODE_F9               0x43
#define EXTENDED_CODE_F10              0x44
#define EXTENDED_CODE_F11              0x85
#define EXTENDED_CODE_F12              0x86

#define DIRECTION_RIGTH                CK_TRUE
#define DIRECTION_LEFT                 CK_FALSE

#define CURSOR_SIZE_SMALL              0x19
#define CURSOR_SIZE_BIG                0x35

#define CURSOR_SMALL                   CK_FALSE 
#define CURSOR_BIG                     CK_TRUE

CK_BBOOL             bExtendedKeyFlag;
CK_CHAR              bExtendedKey;

CK_BBOOL             bInsert;

// allocate 10K max
#define TEMP_BUFFER_SIZE      10240
CK_CHAR_PTR          pConsoleBuffer;
CK_ULONG             uCursorOffset;
CK_ULONG             uConsoleBufferLength;


// auto complete
#define              AUTO_COMPLETE_STOPPED         CK_FALSE
#define              AUTO_COMPLETE_STARTED         CK_TRUE

CK_CHAR_PTR          *pCoAutoCompleteList;
CK_ULONG             uAutoCompleteListNumber; 
CK_CHAR_PTR          pAutoCompleteFirstCompleteBuffer;
CK_ULONG             pAutoCompleteFirstOffsetComplete;
CK_ULONG             pAutoCompleteCurrentIndex;
CK_BBOOL             bAutoCompleteState;

// history
#define  MAX_HISTORY_SIZE           256 
#define  HISTORY_SEARCH_INDEX_LAST  0x01
#define  HISTORY_SEARCH_INDEX_FIRST 0x02    

CK_CHAR_PTR          pConsoleHistory[MAX_HISTORY_SIZE];
CK_BYTE              bHistoryIndex;

HANDLE hOutput;
HANDLE hInput;


#define Console_TerminalCursorLeftN(x)       Console_TerminalCursorMove(DIRECTION_LEFT, x);
#define Console_TerminalCursorRigthN(x)      Console_TerminalCursorMove(DIRECTION_RIGTH, x);
#if 0
#define Console_TerminalClearLine()          fflush(stdout);printf("\33[2K\r");fflush(stdout)
#define Console_TerminalCursorForward(x)     printf("\033[%dC", (x))
#define Console_TerminalCursorBackward(x)    printf("\033[%dD", (x))
#endif
#define Console_TerminalHideCursor()         Console_TerminalCursorChangeVisibility(CK_FALSE)
#define Console_TerminalShowCursor()         Console_TerminalCursorChangeVisibility(CK_TRUE)



/*
    FUNCTION:        CK_BBOOL Console_Init()
*/
CK_BBOOL Console_Init()
{
   // allocate console buffer
   pConsoleBuffer = malloc(TEMP_BUFFER_SIZE);

   // reset auto complete pointer
   pAutoCompleteFirstCompleteBuffer = NULL;

   // reset extended call
   bExtendedKey = CK_FALSE;

   // set hsitroy index to 0
   bHistoryIndex = 0;

   // fill the history buffer with NULL
   for (CK_LONG uLoop = 0; uLoop < MAX_HISTORY_SIZE; uLoop++)
   {
      pConsoleHistory[uLoop] = NULL;
   }
   
   // Get Input and output handle
   hInput = GetStdHandle(STD_INPUT_HANDLE);
   hOutput = GetStdHandle(STD_OUTPUT_HANDLE);

   // set insert flag to false
   bInsert = CK_FALSE;

   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL Console_Terminate()
*/
CK_BBOOL Console_Terminate()
{
   // Release console buffer
   if (pConsoleBuffer != NULL)
   {
      free(pConsoleBuffer);
   }

   // Release auto complete buffer
   if (pAutoCompleteFirstCompleteBuffer != NULL)
   {
      free(pAutoCompleteFirstCompleteBuffer);
   }

   // set pointers to NULL
   pAutoCompleteFirstCompleteBuffer = NULL;
   pConsoleBuffer = NULL;

   // fill the history buffer with NULL
   for (CK_LONG uLoop = 0; uLoop < MAX_HISTORY_SIZE; uLoop++)
   {
      // if buffer at index is not null, free memory
      if (pConsoleHistory[uLoop] != NULL)
      {
         free(pConsoleHistory[uLoop]);
      }
      pConsoleHistory[uLoop] = NULL;
   }

   return CK_TRUE;
}

/*
    FUNCTION:        CK_ULONG Console_RequestInteger()
*/
CK_ULONG Console_RequestInteger()
{
   CK_LONG uReturn;

   // get string from the terminal
   uReturn = Console_RequestString();

   // check if positive
   if (uReturn > 0)
   {
      return str_StringtoInteger(pConsoleBuffer);
   }

   return -1;
}

/*
    FUNCTION:        CK_LONG Console_RequestString()
*/
CK_LONG Console_RequestString()
{
   CK_CHAR sChar;
   CK_ULONG uOffset = 0;

   uCursorOffset = 0;
   uConsoleBufferLength = 0;
   pConsoleBuffer[0] = 0;

   do
   {
      //fflush(stdin);
      sChar = getc(stdin);

      switch (sChar)
      {

      case CARACTER_RETURN: // return, stop the lool
      case CARACTER_NEWLINE:
         pConsoleBuffer[uOffset] = '\0';
         printf("\n");
         return uOffset;
      case CARACTER_BREAK: // break (ctrl + c)
      case (CK_CHAR)EOF:
         return -1;
      default:
         //push buffer in buffer
         pConsoleBuffer[uOffset] = sChar;
         uOffset++;

      }
   } while (sChar != '\r');

   pConsoleBuffer[uOffset] = 0;

   return -1;
}

/*
    FUNCTION:        CK_CHAR_PTR Console_GetBuffer()
*/
CK_CHAR_PTR Console_GetBuffer()
{
   return &pConsoleBuffer[0];
}

/*
    FUNCTION:        CK_LONG Console_RequestPassword()
*/
CK_ULONG Console_RequestPassword()
{
   CK_CHAR sChar[2] = { 0 };
   CK_ULONG uOffset = 0;

   uCursorOffset = 0;
   uConsoleBufferLength = 0;
   pConsoleBuffer[0] = 0;

   //fflush(stdin);
   do
   {

      sChar[0] = Console_KeyBoardGetCharacter();

      switch (sChar[0])
      {

      case CARACTER_NEWLINE: // return, stop the lool
      case CARACTER_RETURN:
         pConsoleBuffer[uOffset] = '\0';
         return uOffset;
      case CARACTER_BREAK: // break (ctrl + c)
      case (CK_CHAR)EOF:
         return -1;
      case CARACTER_BACK: // delete
         if (uOffset != 0)
         {
            // remove from console the *
            printf("\b");
            printf(" ");
            printf("\b");
            // clear previous password byte in the buffer
            uOffset--;
            pConsoleBuffer[uOffset] = 0;
         }
         break;


      case EXTENDED_CODE:
         // get extended character and ignore
         sChar[0] = Console_KeyBoardGetCharacter();
         break;
      case CARACTER_ESC: // 
      case 0x3B: // 
      case 0x00: // empty 
      case CARACTER_TAB: // tab

         break;
      default:
         printf("%s", sChar);
         Sleep(50);
         printf("\b");
         printf(" ");
         printf("\b");
         printf("*");
         //push buffer in buffer
         pConsoleBuffer[uOffset] = sChar[0];
         uOffset++;

      }

      // check for buffer overflow
      if (uOffset > TEMP_BUFFER_SIZE)
      {
         return -1;
      }

   } while (sChar[0] != '\r');

   pConsoleBuffer[uOffset] = 0;

   return -1;
}

/*
    FUNCTION:        CK_CHAR Console_KeyBoardGetCharacter()
*/
CK_CHAR Console_KeyBoardGetCharacter()
#ifdef OS_WIN32
{
   //HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
   INPUT_RECORD irInputRecord;
   DWORD dwEventsRead;
   CHAR cChar;

   // extended code, second call to key ascci code
   if (bExtendedKeyFlag == CK_TRUE)
   {
      bExtendedKeyFlag = CK_FALSE;
      return bExtendedKey;
   }

   while (ReadConsoleInput(hInput, &irInputRecord, 1, &dwEventsRead)) /* Read key press */
   {
      // wait for keyboard event and key down. Ignore all other event
      if ((irInputRecord.EventType == KEY_EVENT) && (irInputRecord.Event.KeyEvent.bKeyDown == TRUE))
      {
         // get the code. 
         switch (irInputRecord.Event.KeyEvent.wVirtualKeyCode)
         {
            // ignore some virtual codes
         case VK_SHIFT:
         case VK_MENU:
         case VK_CONTROL:
            break;
            // other virtal code return it as extended code
         case VK_HOME:
         case VK_END:
         case VK_DELETE:
         case VK_RIGHT:
         case VK_LEFT:
         case VK_UP:
         case VK_DOWN:
         case VK_PRIOR:
         case VK_NEXT:
         case VK_INSERT:
         case VK_F1:
         case VK_F2:
         case VK_F3:
         case VK_F4:
         case VK_F5:
         case VK_F6:
         case VK_F7:
         case VK_F8:
         case VK_F9:
         case VK_F10:
         case VK_F11:
         case VK_F12:
            cChar = EXTENDED_CODE;
            bExtendedKeyFlag = CK_TRUE;
            bExtendedKey = (CK_CHAR)irInputRecord.Event.KeyEvent.wVirtualScanCode;
            return cChar;
            // other code, get the ascci code
         default:
            cChar = irInputRecord.Event.KeyEvent.uChar.AsciiChar;
            return cChar;
         }
      }
   }
   return EOF;
}

#else
{
   char ch;
   initTermios(0);
   ch = getchar();
   resetTermios();
   return ch;
}

#endif



#ifdef OS_WIN32
/*
    FUNCTION:        CK_LONG Console_RequestStringWithAutoComplete()
*/
CK_LONG Console_RequestStringWithAutoComplete()
{
   CK_CHAR sChar[2] = { 0 };

   uCursorOffset = 0;
   uConsoleBufferLength = 0;
   pConsoleBuffer[0] = 0;

#ifdef _DEBUG
   // clear pConsoleArgList array
   memset(pConsoleBuffer, 0, sizeof(TEMP_BUFFER_SIZE));
#endif

   do
   {
      //fflush(stdin);
      // get character
      sChar[0] = Console_KeyBoardGetCharacter();
      //sChar[0] = _getch();

      // If auto complete started, and if character is different of tab or escape, stop auto complete
      Console_AutoCompleteStop(sChar);

      switch (sChar[0])
      {
         // Stop the loop
      case CARACTER_BREAK: // break (ctrl + c)
      case (CK_CHAR)EOF:
         printf("\r\n ctrl + c\n;");
         uCursorOffset = 0;
         uConsoleBufferLength = 0;
         pConsoleBuffer[uCursorOffset] = 0;
         return -1;

         // return, stop the loop, and return the buffer
      case CARACTER_RETURN:
      case CARACTER_NEWLINE:
         return Console_KeyBoardReturn();

      case 0x00: // F0 : receive 00 + code
         break;

      case CARACTER_TAB: // tab
         Console_AutoComplete();
         break;

      case CARACTER_ESC: // (esc) clear current line or auto complete

         // escape
         Console_KeyBoardEscape();
         break;

      case CARACTER_BACK: // back
         Console_KeyBoardBack();
         break;

      case EXTENDED_CODE: // extended code

         // Get extended character
         sChar[0] = Console_KeyBoardGetCharacter();
         //sChar[0] = _getch();

         // Character up : show the previous command
         if (sChar[0] == EXTENDED_CODE_ARROW_UP) // up
         {
            Console_HistoryMove(EXTENDED_CODE_ARROW_UP);
            break;
         }

         // Character Down : show the next command
         if (sChar[0] == EXTENDED_CODE_ARROW_DOWN) // down
         {
            Console_HistoryMove(EXTENDED_CODE_ARROW_DOWN);
            break;
         }
         // Character page up : for tho first element of history
         if (sChar[0] == EXTENDED_CODE_PAGE_UP) // page up
         {
            Console_HistoryMove(EXTENDED_CODE_PAGE_UP);
            break;
         }
         // Character page down : for tho last element of history
         if (sChar[0] == EXTENDED_CODE_PAGE_DOWN) // page down
         {
            Console_HistoryMove(EXTENDED_CODE_PAGE_DOWN);
            break;
         }
         // Character left : cursor left
         if (sChar[0] == EXTENDED_CODE_ARROW_LEFT) // left
         {
            // move cursor the the left
            Console_TerminalCursorMoveLeft();
            break;
         }
         // Character rigth : cursor rigth
         if (sChar[0] == EXTENDED_CODE_ARROW_RIGTH) // 
         {
            // move cursor to the rigth
            Console_TerminalCursorMoveRigth();
            break;
         }
         // Character end : set cursor to the end
         if (sChar[0] == EXTENDED_CODE_BEGIN) // 
         {
            Console_TerminalCursorMoveBeginingOfLine();
            break;
         }

         // Character end : set cursor to the end
         if (sChar[0] == EXTENDED_CODE_END) // 
         {
            Console_TerminalCursorMoveEndOfLine();
            break;
         }
         // Character delete : detele the character in the left
         if (sChar[0] == EXTENDED_CODE_DELETE) // delete
         {
            Console_KeyBoardDelete();
            break;
         }
         // Character delete : detele the character in the left
         if (sChar[0] == EXTENDED_CODE_INSERT) // insert
         {
            Console_KeyBoardInsert();
            break;
         }
         break;

      default:
         Console_KeyBoardOtherCharacter(&sChar[0]);
         break;
      }
   } while (sChar[0] != '\r');

   pConsoleBuffer[uCursorOffset] = 0;

   return -1;
}

/*
    FUNCTION:        void Console_HistoryCurrentSaveLine()
*/
void Console_HistoryCurrentSaveLine()
{
   CK_BYTE bPreviousIndex;
   CK_BYTE bNextIndex;

   // save history only of charcter in the console
   if (uConsoleBufferLength != 0)
   {

      // search for last history index. In case we run a command in the previous index history. 
      // append command in the last index
      while (pConsoleHistory[bHistoryIndex] != NULL)
      {
         bHistoryIndex++;
      };

      bPreviousIndex = bHistoryIndex - 1;
      if (pConsoleHistory[bPreviousIndex] != NULL)
      {
         // check if the string of previous index is the same
         // in case we run twice the same command
         if (strcmp(pConsoleHistory[bPreviousIndex], pConsoleBuffer) == 0)
         {
            return;
         }
      }

      // as it is a cycle buffer, check if already allocated. In such case release it and allocate new one. 
      if (pConsoleHistory[bHistoryIndex] != NULL)
      {
         free(pConsoleHistory[bHistoryIndex]);
      }

      // allocate a buffer of the size of the current line
      pConsoleHistory[bHistoryIndex] = malloc((CK_ULONG)(uConsoleBufferLength + 1));

      bNextIndex = bHistoryIndex + 1;
      // cycling buffer, if the next buffer in the list in not null, release it 2 next slot (2 null slots required)
      if (pConsoleHistory[bNextIndex] != NULL)
      {
         free(pConsoleHistory[bNextIndex]);
         pConsoleHistory[bNextIndex] = NULL;
         bNextIndex++;
      }

      // if buffer allocate, increment index. 
      if (pConsoleHistory[bHistoryIndex] != NULL)
      {
         // Save the current line in the index buffer
         strcpy(pConsoleHistory[bHistoryIndex], pConsoleBuffer);

         // increment index
         bHistoryIndex++;
      }
   }
}

/*
    FUNCTION:        CK_BYTE Console_HistorySearch(CK_BYTE bmode)
*/
CK_BYTE Console_HistorySearch(CK_BYTE bmode)
{
   CK_BYTE bIndexSearch = bHistoryIndex;

   // if search first decrement index until null
   if (bmode == HISTORY_SEARCH_INDEX_FIRST)
   {
      while (pConsoleHistory[(CK_BYTE)(bIndexSearch - (CK_BYTE)1)] != NULL)
      {
         // decrement index for next loop
         bIndexSearch--;

      }
   }
   // if search last increment index until null
   else
   {
      // check if next index is null
      while (pConsoleHistory[(CK_BYTE)(bIndexSearch + (CK_BYTE)1)] != NULL)
      {
         // increment index for next loop
         bIndexSearch++;
      }
   }
   // return index
   return bIndexSearch;
}

/*
    FUNCTION:        void Console_HistoryMove(CK_BYTE bDirection)
*/
void Console_HistoryMove(CK_BYTE bDirection)
{
   CK_BYTE bSavedHistoryIndex = bHistoryIndex;
   
   switch (bDirection)
   {
   case EXTENDED_CODE_ARROW_UP:
      // decrement local index according key direction
      bSavedHistoryIndex--;
      break;
   case EXTENDED_CODE_ARROW_DOWN:
      // increment local index according key direction
      bSavedHistoryIndex++;
      break;
   case EXTENDED_CODE_PAGE_UP:
      // find first index
      bSavedHistoryIndex = Console_HistorySearch(HISTORY_SEARCH_INDEX_FIRST);
      break;
   case EXTENDED_CODE_PAGE_DOWN:
      // find last index
      bSavedHistoryIndex = Console_HistorySearch(HISTORY_SEARCH_INDEX_LAST);
      break;
   }

   // if the current history index is null, ignore the press
   if (pConsoleHistory[bSavedHistoryIndex] == NULL)
   {
      // print current index
      bSavedHistoryIndex = bHistoryIndex;
   }

   // hide the cursor
   Console_TerminalHideCursor();

   // if the buffer is not null
   if (pConsoleHistory[bSavedHistoryIndex] != NULL)
   {
      // check if already printed
      if (strcmp(pConsoleHistory[bSavedHistoryIndex], pConsoleBuffer) != 0)
      {
         // Clear console and print saved line from the index
         Console_TerminalDeleteLine();

         // Write in terminal the string
         Console_TerminalWriteCharactersEndOfLine(pConsoleHistory[bSavedHistoryIndex], CK_FALSE);

         // set the index value (increment or decrement before)
         bHistoryIndex = bSavedHistoryIndex;
      }
   }

   // show the cursor
   Console_TerminalShowCursor();
}

/*
    FUNCTION:        CK_BBOOL Console_SetAutocompleteList(CK_CHAR_PTR * pList, CK_ULONG uListNumber)
*/
CK_BBOOL Console_SetAutocompleteList(CK_CHAR_PTR* pList, CK_ULONG uListNumber)
{
   pCoAutoCompleteList = pList;
   uAutoCompleteListNumber = uListNumber;
   CK_ULONG uMaxLength = 0;

   // get the max size of auto complete list argument
   for (CK_ULONG uLoop = 0; uLoop < uListNumber; uLoop++)
   {
      uMaxLength = (CK_ULONG)max(uMaxLength, strlen(pList[uLoop]));
   }
   // add one
   uMaxLength++;

   // allocate buffer for auto completion first command
   pAutoCompleteFirstCompleteBuffer = malloc((CK_ULONG)(uMaxLength));

   // auto complete stop
   bAutoCompleteState = AUTO_COMPLETE_STOPPED;

   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL Console_AutoCompleteGetBeginingOfArgument()
*/
CK_ULONG Console_AutoCompleteGetBeginingOfArgument(CK_ULONG uOffsetPreviousSpace)
{
   // Init to cursor
   uOffsetPreviousSpace = uCursorOffset;

   // if cursor if in the begining, don't execute
   if (uCursorOffset != 0)
   {
      do
      {
         // space found, stop the loop
         if (pConsoleBuffer[uOffsetPreviousSpace] == strSpace)
         {
            // space found, move to the next character
            uOffsetPreviousSpace++;
            break;
         }
         uOffsetPreviousSpace--;
      } while (uOffsetPreviousSpace != 0);
   }

   return uOffsetPreviousSpace;
}

/*
    FUNCTION:        CK_BBOOL Console_AutoCompleteSearchMatch(CONSOLE_AUTOCOMPLETE_MATCH * sAutoCompleteMatch, CK_ULONG uFirstIndex, CK_ULONG uLastIndex, CK_CHAR_PTR sBuffer, CK_ULONG uBufferLength, CK_BBOOL bIgnoreFullMatch)
*/
CK_BBOOL Console_AutoCompleteSearchMatch(CONSOLE_AUTOCOMPLETE_MATCH * sAutoCompleteMatch, CK_ULONG uFirstIndex, CK_ULONG uLastIndex, CK_CHAR_PTR sBuffer, CK_ULONG uBufferLength, CK_BBOOL bIgnoreFullMatch)
{
   CK_ULONG uCommandListLength;
   // loop for each entry in the all complete list
   for (sAutoCompleteMatch->uMatchCommandIndex = uFirstIndex; sAutoCompleteMatch->uMatchCommandIndex < uLastIndex; sAutoCompleteMatch->uMatchCommandIndex++)
   {

      // search there is a match between partial written command and command list
      sAutoCompleteMatch->uOffsetMatch = str_ComparePartialString(sBuffer, pCoAutoCompleteList[sAutoCompleteMatch->uMatchCommandIndex]);

      uCommandListLength = (CK_ULONG)strlen(pCoAutoCompleteList[sAutoCompleteMatch->uMatchCommandIndex]);

      // if something match, stop the loop
      if ((sAutoCompleteMatch->uOffsetMatch != 0) && (bIgnoreFullMatch || (sAutoCompleteMatch->uOffsetMatch != uCommandListLength)) && (sAutoCompleteMatch->uOffsetMatch >= uBufferLength))
      {
         // check flag full match
         if (bIgnoreFullMatch == CK_TRUE)
         {
            // in case of full match, ignore it
            // example : start auto completion for a command that is already in the list. skip and go to next one
            // example command list and listslot. If autocompletion start with list, should go to listslot
            if (sAutoCompleteMatch->uOffsetMatch != uCommandListLength)
            {
               sAutoCompleteMatch->bMatch = CK_TRUE;
               return CK_FALSE;
            }
         }
         else
         {
            sAutoCompleteMatch->bMatch = CK_TRUE;
            return CK_FALSE;
         }
      }
   }
   return CK_FALSE;
}

/*
    FUNCTION:        void Console_AutoCompleteStop(CK_CHAR_PTR sChar)
*/
void Console_AutoCompleteStop(CK_CHAR_PTR sChar)
{
   // Check if auto complete is starter
   if (bAutoCompleteState == AUTO_COMPLETE_STARTED)
   {
      // if character is not tab or escape, stop auto completion
      if ((sChar[0] != CARACTER_TAB) && (sChar[0] != CARACTER_ESC))
      {
         bAutoCompleteState = AUTO_COMPLETE_STOPPED;
      }
   }
}

/*
    FUNCTION:        void Console_AutoComplete()
*/
void Console_AutoComplete()
{
   if (bAutoCompleteState == AUTO_COMPLETE_STOPPED)
   {
      Console_AutoCompleteFirst();
   }
   else
   {
      Console_AutoCompleteNext();
   }
}

/*
    FUNCTION:        void Console_AutoCompleteFirst()
*/
void Console_AutoCompleteFirst()
{
   CK_ULONG uOffsetPreviousSpace;
   CONSOLE_AUTOCOMPLETE_MATCH sAutoCompleteMatch = { 0 };
   CK_CHAR_PTR uMatchCommandCommand;
      
   // push the cursor to the end of the line
   Console_TerminalCursorMoveEndOfLine(),

   // search begining of current argument
   uOffsetPreviousSpace = Console_AutoCompleteGetBeginingOfArgument(uCursorOffset);

   do
   {
      // in case, the cursor is in the begining of the line, start with fist element of the list
      if (uCursorOffset == 0)
      {
         sAutoCompleteMatch.uMatchCommandIndex = 0;
         sAutoCompleteMatch.uOffsetMatch = 0;
         sAutoCompleteMatch.bMatch = CK_TRUE;
      }
      else
      {
         // continue to search in the index table from begining
         Console_AutoCompleteSearchMatch(&sAutoCompleteMatch, 0, uAutoCompleteListNumber, &pConsoleBuffer[uOffsetPreviousSpace], (uCursorOffset - uOffsetPreviousSpace), CK_TRUE);
      }

      if (sAutoCompleteMatch.bMatch == CK_TRUE)
      {
         // Get the command string in the table
         uMatchCommandCommand = pCoAutoCompleteList[sAutoCompleteMatch.uMatchCommandIndex];

         // Save the first match string, the index in the table, the cursor offset, to be called after a second push of tab
         pAutoCompleteFirstOffsetComplete = uCursorOffset;
         strcpy(pAutoCompleteFirstCompleteBuffer, &pConsoleBuffer[uOffsetPreviousSpace]);
         pAutoCompleteCurrentIndex = sAutoCompleteMatch.uMatchCommandIndex;
         bAutoCompleteState = AUTO_COMPLETE_STARTED;

         // write the new match string
         Console_TerminalWriteCharactersEndOfLine(&uMatchCommandCommand[sAutoCompleteMatch.uOffsetMatch], CK_FALSE);
      }
   } while (FALSE);
}

/*
    FUNCTION:        void Console_AutoCompleteFirst()
*/
void Console_AutoCompleteNext()
{
   CK_ULONG uOffsetPreviousSpace;
   CK_CHAR_PTR uMatchCommandCommand;
   CONSOLE_AUTOCOMPLETE_MATCH sAutoCompleteMatch = { 0 };

   Console_TerminalCursorMoveEndOfLine();

   // search begining of current argument
   uOffsetPreviousSpace = Console_AutoCompleteGetBeginingOfArgument(pAutoCompleteFirstOffsetComplete);

   do
   {
      // in case of autocomplemention made in empty line, just list all commands
      if (pAutoCompleteFirstOffsetComplete == 0)
      {
         // Set the curent match index to current + 1
         sAutoCompleteMatch.uMatchCommandIndex = pAutoCompleteCurrentIndex;
         sAutoCompleteMatch.uMatchCommandIndex++;

         // if the index reach the end of table, start from 0
         if (sAutoCompleteMatch.uMatchCommandIndex >= uAutoCompleteListNumber)
         {
            sAutoCompleteMatch.uMatchCommandIndex = 0;
         }
         // Set match offset to 0
         sAutoCompleteMatch.uOffsetMatch = 0;
         // Set match equal true         
         sAutoCompleteMatch.bMatch = CK_TRUE;
      }
      else
      {
         // continue to search in the index table. Start from current index
         Console_AutoCompleteSearchMatch(&sAutoCompleteMatch, pAutoCompleteCurrentIndex + 1, uAutoCompleteListNumber, pAutoCompleteFirstCompleteBuffer, (pAutoCompleteFirstOffsetComplete - uOffsetPreviousSpace), CK_FALSE);

         // in case the match is false, search from the begining of the table
         if (sAutoCompleteMatch.bMatch == CK_FALSE)
         {
            // search from the begining of the table
            Console_AutoCompleteSearchMatch(&sAutoCompleteMatch, 0, pAutoCompleteCurrentIndex, pAutoCompleteFirstCompleteBuffer, (pAutoCompleteFirstOffsetComplete - uOffsetPreviousSpace), CK_FALSE);
         }
      }

      if (sAutoCompleteMatch.bMatch == CK_TRUE)
      {
         // Get the command string in the table
         uMatchCommandCommand = pCoAutoCompleteList[sAutoCompleteMatch.uMatchCommandIndex];

         // update index
         pAutoCompleteCurrentIndex = sAutoCompleteMatch.uMatchCommandIndex;

         // hide the cursor
         Console_TerminalHideCursor();

         // delete in the terminal the previous auto complete
         Console_TerminalDeleteCharactersEndOfLine(uCursorOffset - pAutoCompleteFirstOffsetComplete);

         // write the new match string
         Console_TerminalWriteCharactersEndOfLine(&uMatchCommandCommand[sAutoCompleteMatch.uOffsetMatch], CK_FALSE);

         // show the cursor
         Console_TerminalShowCursor();
      }
      else
      {
         // if not match, reset the index to the begining of the table
         // should not happen
         pAutoCompleteCurrentIndex = 0;
         bAutoCompleteState = AUTO_COMPLETE_STOPPED;
      }
   } while (FALSE);
}


/*
    FUNCTION:        void void Console_KeyBoardOtherCharacter()
*/
void Console_KeyBoardOtherCharacter(CK_CHAR_PTR sChar)
{
   Console_TerminalHideCursor();

   // If insert button false
   if (bInsert == CK_FALSE)
   {
      // in case the cursor is not at the end of line, shift the line of the new string lenght
      if (uCursorOffset < uConsoleBufferLength)
      {

         Console_TerminalWriteCharactersMiddleOfLine(sChar);
      }

      else
      {
         Console_TerminalWriteCharactersEndOfLine(sChar, CK_FALSE);
      }
   }
   else
   {
      Console_TerminalWriteCharactersEndOfLine(sChar, CK_TRUE);
   }

   Console_TerminalShowCursor();
}

/*
    FUNCTION:        CK_LONG Console_KeyBoardEscape()
*/
void Console_KeyBoardEscape()
{
   if (bAutoCompleteState == AUTO_COMPLETE_STOPPED)
   {
      Console_TerminalDeleteLine();
   }
   else
   {
      // Delete a character from end of line until offset before auto complete
      Console_TerminalDelete(uConsoleBufferLength - pAutoCompleteFirstOffsetComplete);

      bAutoCompleteState = AUTO_COMPLETE_STOPPED;
   }
}

/*
    FUNCTION:        void Console_KeyBoardInsert()
*/
void Console_KeyBoardInsert()
{
   if (bInsert == CK_TRUE)
   {
      Console_TerminalCursorChangeSize(CURSOR_SMALL);
      bInsert = CK_FALSE;
   }
   else
   {
      Console_TerminalCursorChangeSize(CURSOR_BIG);
      bInsert = CK_TRUE;
   }
}


/*
    FUNCTION:        void Console_KeyBoardBack()
*/
void Console_KeyBoardBack()
{
   // only if the cursor is not in begining of the line
   if (uCursorOffset != 0)
   {
      // if the cursor is at the end of the line, just delete the last charcter
      if (uCursorOffset == uConsoleBufferLength)
      {
         // hide the cursor
         Console_TerminalHideCursor();

         // delete character from end of line
         Console_TerminalDeleteCharactersEndOfLine(1);

         // hide the cursor
         Console_TerminalShowCursor();
      }
      else
      {
         // hide the cursor
         Console_TerminalHideCursor();

         // Delete one character in the middle of the line in mode back
         Console_TerminalDeleteCharacterMiddleOfLine(CK_TRUE);

         // show the cursor
         Console_TerminalShowCursor();
      }
   }
}

/*
    FUNCTION:        CK_ULONG Console_KeyBoardReturn()
*/
CK_ULONG Console_KeyBoardReturn()
{
   // move cursor to end of line
   Console_TerminalCursorMoveEndOfLine();

   // set end of string
   pConsoleBuffer[uConsoleBufferLength] = 0;

   // save current buffer
   Console_HistoryCurrentSaveLine();

   // return and new line on the console
   printf("\r\n");

   // return the console length buffer
   return uConsoleBufferLength;
}

/*
    FUNCTION:        void void Console_KeyBoardDelete()
*/
void Console_KeyBoardDelete()
{
   // only if the line length is not 0
   if (uConsoleBufferLength != 0)
   {
      // hide the cursor
      Console_TerminalHideCursor();

      // delete a character in mode delete
      Console_TerminalDeleteCharacterMiddleOfLine(CK_FALSE);

      // show the cursor
      Console_TerminalShowCursor();
   }
}

/*
    FUNCTION:        void Console_TerminalDeleteCharactersEndOfLine()
*/
void Console_TerminalDeleteCharactersEndOfLine(CK_ULONG uLength)
{
   CK_BBOOL bEndofLine;

   while (uLength != 0)
   {
      // move last character, and return if reach end of line
      bEndofLine = Console_TerminalCursorRigthN(1);
      printf(" ");

      // if end of line is false, move backward the cursor
      if (bEndofLine == CK_FALSE)
      {
         Console_TerminalCursorRigthN(1);
      }

      // update the console buffer, offset and length
      uConsoleBufferLength--;
      uCursorOffset--;
      pConsoleBuffer[uCursorOffset] = 0;


      // decrement loop
      uLength--;
   }
}

/*
    FUNCTION:        void Console_TerminalDeleteCharactersMiddleOfLine()
*/
void Console_TerminalDeleteCharacterMiddleOfLine(CK_BBOOL isBack)
{
   CK_ULONG uDataLengthToShift;
   CK_ULONG uLoop;
   CK_BBOOL bEndOfLine;
   CK_CHAR sChar[2] = { 0 };

   // Get the length of data to shift. The total length of the line minus the cursor offset
   uDataLengthToShift = (CK_ULONG)(uConsoleBufferLength - uCursorOffset);

   // if length to shift is null, return
   if (uDataLengthToShift == 0)
   {
      return;
   }

   if (isBack == CK_TRUE)
   {
      // Shift the memory of 1 byte in the buffer.
      memcpy(&pConsoleBuffer[uCursorOffset - 1], &pConsoleBuffer[uCursorOffset], (CK_ULONG)(uDataLengthToShift));
   }
   else
   {
      // Shift the memory of 1 byte in the buffer.
      memcpy(&pConsoleBuffer[uCursorOffset], &pConsoleBuffer[uCursorOffset + 1], (CK_ULONG)(uDataLengthToShift));
   }

   // Put end of string in the old last byte
   pConsoleBuffer[uConsoleBufferLength] = 0;

   // decrement the length
   uConsoleBufferLength--;
   // put a space of the old position of the last byte
   pConsoleBuffer[uConsoleBufferLength] = ' ';

   if (isBack == CK_TRUE)
   {
      // push the cursor to the rigth
      Console_TerminalCursorMoveRigth();
   }
   else
   {
      // special case where a line is deleted and end of line cross the console line. The size to delete is one byte lower than delete with back
      uDataLengthToShift--;
   }

   // print the string shifted of one byte, including a space to delete last character in old position
   for (uLoop = 0; uLoop <= uDataLengthToShift; uLoop++)
   {
      bEndOfLine = Console_TerminalCursorIsEndOfLine();

      sChar[0] = pConsoleBuffer[uCursorOffset + uLoop];
      printf("%s", &sChar[0]);

      // if end of line, move the cursor the next line
      if (bEndOfLine == CK_TRUE)
      {
         Console_TerminalCursorLeftN(1);
      }
   }

   // replace the space in the buffer by end of string
   pConsoleBuffer[uConsoleBufferLength] = 0;

   // move the cursor to the position after delete
   Console_TerminalCursorRigthN(uConsoleBufferLength + 1 - uCursorOffset);
}

/*
    FUNCTION:        void Console_TerminalDeleteLine()
*/
void Console_TerminalDeleteLine()
{
   // hide the cursor
   Console_TerminalHideCursor();

   // move cursor to the end of line
   Console_TerminalCursorLeftN(uConsoleBufferLength - uCursorOffset);
   uCursorOffset = uConsoleBufferLength;

   // delete character
   Console_TerminalDeleteCharactersEndOfLine(uConsoleBufferLength);

   // show the cursor
   Console_TerminalShowCursor();
}

/*
    FUNCTION:        void Console_TerminalDelete(CK_ULONG uLength)
*/
void Console_TerminalDelete(CK_ULONG uLength)
{
   // hide the cursor
   Console_TerminalHideCursor();

   // move cursor to the end of line
   Console_TerminalCursorLeftN(uConsoleBufferLength - uCursorOffset);
   uCursorOffset = uConsoleBufferLength;

   // delete character
   Console_TerminalDeleteCharactersEndOfLine(uLength);

   // show the cursor
   Console_TerminalShowCursor();
}

/*
    FUNCTION:        void Console_TerminalWriteCharactersEndOfLine(CK_CHAR_PTR sString, CK_BBOOL bInsertMode)
*/
void Console_TerminalWriteCharactersEndOfLine(CK_CHAR_PTR sString, CK_BBOOL bInsertMode)
{
   CK_BBOOL bEndOfLine;
   CK_ULONG uLoop;
   CK_CHAR sChar[2] = { 0 };
   CK_ULONG uSize = (CK_ULONG)strlen(sString);

   // copy the new string
   for (uLoop = 0; uLoop < uSize; uLoop++)
   {
      // Check if end of line is reach
      bEndOfLine = Console_TerminalCursorIsEndOfLine();

      // Write the chartacter
      sChar[0] = sString[uLoop];
      printf("%s", &sChar[0]);
      
      //push buffer in buffer
      pConsoleBuffer[uCursorOffset] = sString[uLoop];

      // if insert is false, increment length. 
      // if insert is true, increment length only if end of the line
      if ((bInsertMode == CK_FALSE) || (uCursorOffset == uConsoleBufferLength))
      {
         // increment buffer length
         uConsoleBufferLength++;
      }
      // increment cursor
      uCursorOffset++;

      // write end of string on next buffer
      pConsoleBuffer[uCursorOffset] = 0;

      // if end of line, move the cursor the next line
      if (bEndOfLine == CK_TRUE)
      {
         Console_TerminalCursorLeftN(1);
      }
   }
}

/*
    FUNCTION:        void Console_TerminalWriteCharactersMiddleOfLine(CK_CHAR_PTR sString)
*/
void Console_TerminalWriteCharactersMiddleOfLine(CK_CHAR_PTR sString)
{
   CK_ULONG uSize = (CK_ULONG)strlen(sString);
   CK_ULONG uShiftSize;
   CK_BBOOL bEndOfLine;
   CK_ULONG uLoop;
   CK_CHAR sChar[2] = { 0 };

   // shift on one byte to the left
   uShiftSize = (uConsoleBufferLength - uCursorOffset + uSize);
   memcpy(&pConsoleBuffer[uCursorOffset + uSize], &pConsoleBuffer[uCursorOffset], uShiftSize);

   // Set the \0 at the end
   pConsoleBuffer[uConsoleBufferLength + uSize] = 0;

   // push the caracter at the position of the cursor
   memcpy(&pConsoleBuffer[uCursorOffset], &sString[0], uSize);

   // increment buffer length
   uConsoleBufferLength += uSize;

   for (uLoop = 0; uLoop < uShiftSize; uLoop++)
   {
      // Check if end of line is reach
      bEndOfLine = Console_TerminalCursorIsEndOfLine();

      // Write the chartacter
      sChar[0] = pConsoleBuffer[uCursorOffset + uLoop];
      printf("%s", &sChar[0]);

      // if end of line, move the cursor the next line
      if (bEndOfLine == CK_TRUE)
      {
         Console_TerminalCursorLeftN(1);
      }
   }
   // increment cursor offset
   uCursorOffset++;

   // Move the terminal cursor after the new character
   if (uConsoleBufferLength != uCursorOffset)
   {
      Console_TerminalCursorRigthN(uConsoleBufferLength - uCursorOffset);
   }
}

/*
    FUNCTION:        void Console_TerminalCursorMoveLeft()
*/
void Console_TerminalCursorMoveLeft()
{
   if (uCursorOffset < uConsoleBufferLength)
   {
      // move cursor to the end
      Console_TerminalCursorLeftN(1);
      uCursorOffset++;
   }
}

/*
    FUNCTION:        void Console_TerminalCursorMoveLeft()
*/
void Console_TerminalCursorMoveRigth()
{
   if (uCursorOffset > 0)
   {
      // move cursor to the end
      Console_TerminalCursorRigthN(1);
      uCursorOffset--;
   }
}

/*
    FUNCTION:        void Console_TerminalCursorMoveBeginingOfLine()
*/
void Console_TerminalCursorMoveBeginingOfLine()
{
   // hide the cursor
   Console_TerminalHideCursor();

   // move cursor to the end
   Console_TerminalCursorRigthN(uCursorOffset);
   uCursorOffset = 0;

   // show the cursor
   Console_TerminalShowCursor();
}

/*
    FUNCTION:        void Console_TerminalCursorMoveEndOfLine()
*/
void Console_TerminalCursorMoveEndOfLine()
{
   // hide the cursor
   Console_TerminalHideCursor();

   // move cursor to the end
   Console_TerminalCursorLeftN(uConsoleBufferLength - uCursorOffset);
   uCursorOffset = uConsoleBufferLength;

   // show the cursor
   Console_TerminalShowCursor();
}
/*
    FUNCTION:        CK_BBOOL Console_TerminalCursorMove(CK_BBOOL bDirection, CK_ULONG sValue)
*/
CK_BBOOL Console_TerminalCursorMove(CK_BBOOL bDirection, CK_ULONG sValue)
#ifdef OS_WIN32
{
   //HANDLE hOutput = NULL;
   CONSOLE_SCREEN_BUFFER_INFO screeninfo;
   CK_BBOOL bIsCrossLine = CK_FALSE;
   SHORT uShift = 0;

   if (sValue == 0)
   {
      return CK_FALSE;
   }

   // get handle on output buffer
   //hOutput = GetStdHandle(STD_OUTPUT_HANDLE);

   // get current position
   GetConsoleScreenBufferInfo(hOutput, &screeninfo);

   // loop while cursor is not fully moved
   while (sValue > 0)
   {
      // check direction
      if (bDirection == DIRECTION_RIGTH)
      {
         // if cursor x position is 0, it means it is begining of line, need to go top end of previous line
         if (screeninfo.dwCursorPosition.X == 0)
         {
            // go to previous line
            screeninfo.dwCursorPosition.Y--;
            // go to end of previous line
            screeninfo.dwCursorPosition.X = screeninfo.dwSize.X - 1;
            // set crossing line flag
            bIsCrossLine = CK_TRUE;
            sValue--;
         }
         else
         {
            // get the shifv value
            uShift = (SHORT)sValue;

            // if the shift value implies a line crossing, split the value
            if (uShift > screeninfo.dwCursorPosition.X)
            {
               // get the max shift value to begning of line
               uShift = screeninfo.dwCursorPosition.X;
               screeninfo.dwCursorPosition.X -= uShift;
            }
            else
            {
               // shift the cursor
               screeninfo.dwCursorPosition.X = screeninfo.dwCursorPosition.X - (SHORT)uShift;
            }
            // decrement value loop
            sValue -= uShift;
         }
      }
      else
      {
         // if cursor x position is lower than max position, shift the cursor
         if (screeninfo.dwCursorPosition.X < (screeninfo.dwSize.X - 1))
         {
            uShift = (SHORT)(sValue);

            // if the shift value + position is higher than max line length, split the split value
            if ((uShift + screeninfo.dwCursorPosition.X) > (screeninfo.dwSize.X - 1))
            {
               // get the difference between max position and current position
               uShift = screeninfo.dwSize.X - 1 - screeninfo.dwCursorPosition.X;
               // shift the cursor
               screeninfo.dwCursorPosition.X += uShift;
            }
            else
            {
               // move left the cursor of sValue
               screeninfo.dwCursorPosition.X = screeninfo.dwCursorPosition.X + (SHORT)uShift;
            }
            // decrement value loop
            sValue -= uShift;
         }
         // if cursor x position is end of line, it means it is end of line, need to go to begining of next line, need to cross the line
         else
         {
            // go to next line
            screeninfo.dwCursorPosition.Y++;
            // go to the begining
            screeninfo.dwCursorPosition.X = 0;

            // set crossing line flag
            bIsCrossLine = CK_TRUE;
            // decrement value loop
            sValue--;
         }
      }
      // set new cursor position
      SetConsoleCursorPosition(hOutput, screeninfo.dwCursorPosition);
   }
   return bIsCrossLine;
}
#else
{

   if (sValue == 0)
   {
      return;
   }

   // check direction
   if (bDirection == DIRECTION_BACKWARD)
   {
      // backward the cursor of sValue
      printf("\033[%dD", sValue);
   }
   else
   {
      // forward the cursor of sValue
      printf("\033[%dC", sValue);
   }
}


#endif

/*
    FUNCTION:        void Console_TerminalCursorChangeSize(CK_BBOOL bBigSize)
*/
void Console_TerminalCursorChangeSize(CK_BBOOL bBigSize)
{
#if defined(OS_WIN32)
   //HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
   CONSOLE_CURSOR_INFO cci;
   GetConsoleCursorInfo(hOutput, &cci);
   if (bBigSize == CK_TRUE)
   {
      cci.dwSize = CURSOR_SIZE_BIG;
   }
   else
   {
      cci.dwSize = CURSOR_SIZE_SMALL;
   }

   SetConsoleCursorInfo(hOutput, &cci);
#else

#endif
}

/*
    FUNCTION:        void Console_TerminalCursorChangeVisibility(CK_BBOOL show)
*/
void Console_TerminalCursorChangeVisibility(CK_BBOOL show)
{
#if defined(OS_WIN32)
   //HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
   CONSOLE_CURSOR_INFO cci;
   GetConsoleCursorInfo(hOutput, &cci);
   cci.bVisible = show; // show/hide cursor
   SetConsoleCursorInfo(hOutput, &cci);
#else
   if (show == CK_TRUE)
   {
      printf("\e[?25h");

   }
   else
   {
      printf("\e[?25l");
   }
#endif
}

/*
    FUNCTION:        CK_BBOOL Console_TerminalCursorIsEndOfLine()
*/

CK_BBOOL Console_TerminalCursorIsEndOfLine()
{
#ifdef OS_WIN32

   //HANDLE handle = NULL;
   CONSOLE_SCREEN_BUFFER_INFO screeninfo;

   if (hOutput != NULL)
   {
      // get current position
      GetConsoleScreenBufferInfo(hOutput, &screeninfo);

      // if the cursor is at the end, return true
      if (screeninfo.dwCursorPosition.X == screeninfo.dwSize.X - 1)
      {
         return CK_TRUE;
      }
   }
   return CK_FALSE;
#endif
}

#endif

