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

#ifndef _PARSER_H_
#define _PARSER_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _PARSER_C
#define _EXT
#else
#define _EXT extern
#endif // _PARSER_C

#define MAX_ARGUMENT                35

   typedef struct parser_cmd_arg
   {
      CK_CHAR_PTR s_argName;
      CK_BYTE  s_argType;
      CK_CHAR_PTR s_argHelp;

   }PARSER_CMD_ARG;


   typedef struct parser_command
   {
      const CK_CHAR_PTR       s_cmdName;
      const P_fCMD            pCmd;
      const CK_CHAR_PTR       s_cmdHelp;
      const PARSER_CMD_ARG    sArg[MAX_ARGUMENT];

   }PARSER_COMMAND;


   typedef struct parser_current_cmd_arg
   {
      CK_BYTE  s_argType;
      CK_CHAR_PTR s_argPart1;
      CK_CHAR_PTR s_argPart2;
   }PARSER_CURRENT_CMD_ARG;


   typedef struct parser_current_command
   {
      CK_CHAR_PTR s_cmdName;
      P_fCMD pCmd;
      CK_BYTE  bArgNumber;
      PARSER_CURRENT_CMD_ARG sArg[MAX_ARGUMENT];
      PARSER_CMD_ARG* sCommand;

   }PARSER_CURRENT_COMMAND;


   _EXT  CK_BBOOL                   parser_Init(PARSER_COMMAND* parserCmd, CK_ULONG parserCmdLength);
   _EXT  CK_BBOOL                   parser_CommandParser(int argc, char* argv[]);
   _EXT  CK_BBOOL                   parser_CommandHelp();
   _EXT  CK_BBOOL                   parser_ExecuteCommand(CK_BBOOL bIsConsole);
   _EXT  PARSER_CURRENT_CMD_ARG*    parser_SearchArgument(CK_BYTE bArgType);
   _EXT  CK_BBOOL                   parser_IsCommand(CK_CHAR_PTR sCommand);
   
#undef _EXT

#endif // _PARSER_H_