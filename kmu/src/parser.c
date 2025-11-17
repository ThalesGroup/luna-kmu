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

#define _PARSER_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "parser.h"
#include "str.h"



PARSER_CURRENT_COMMAND kmu_current_cmd;

PARSER_COMMAND*   parserCommand;
CK_ULONG          parserCommandLength;


CK_BBOOL parser_Init(PARSER_COMMAND* parserCmd,  CK_ULONG parserCmdLength)
{
   parserCommand = parserCmd;
   parserCommandLength = parserCmdLength;

   return CK_TRUE;
}

/*
    FUNCTION:        P_fCMD parser_CheckCommand(STRING argv)
*/
CK_BBOOL parser_CheckCommand(CK_CHAR_PTR argv)
{
   CK_ULONG u32count;
   P_fCMD pf_command = NULL;

   if (argv == NULL)
   {
      parser_CommandHelp();
      return CK_FALSE;
   }

   // convert from up case to lower case
   argv = str_tolower(argv);

   // Check command, loop on command
   for (u32count = 0; u32count < parserCommandLength; u32count++)
   {
      // check if command string match
      if (strcmp(argv, parserCommand[u32count].s_cmdName) == 0)
      {
         // Command match
         kmu_current_cmd.pCmd = parserCommand[u32count].pCmd;
         kmu_current_cmd.sCommand = (PARSER_CMD_ARG*)&parserCommand[u32count].sArg;
         kmu_current_cmd.s_cmdName = argv;
         return CK_TRUE;
      }
   }

   printf("Unknown command: %s\n", argv);
   return CK_FALSE;
}


/*
    FUNCTION:        CK_BBOOL parser_isCommandHelp()
*/
/*
CK_BBOOL parser_isCommandHelp()
{
   // check if command help
  // if (strcmp(kmu_current_cmd.s_cmdName, CMD_HELP) == 0)
   {
      return CK_FALSE;
   }
   return CK_FALSE;
}
*/
/*
    FUNCTION:        CK_BBOOL parser_CommandHelp()
*/
CK_BBOOL parser_CommandHelp()
{
   CK_ULONG u32count;
   // loop on all command list table
   for (u32count = 0; u32count < parserCommandLength; u32count++)
   {
      // print the command name
      printf("%s \t\t", parserCommand[u32count].s_cmdName);

      // if command name is shorter than 7, add an extra tag
      if (strlen(parserCommand[u32count].s_cmdName) < 7)
      {
         printf("\t");
      }

      // if command name is shorter than 15, add an extra tag
      if (strlen(parserCommand[u32count].s_cmdName) < 15)
      {
         printf("\t");
      }

      // print the command help
      printf("%s\n", parserCommand[u32count].s_cmdHelp);

   }

   printf("\nuse argument help for each command to display help. (ie: list help)\n");
   return CK_TRUE;
}

/*
    FUNCTION:        void parser_ArgHelp()
*/
void parser_ArgHelp()
{
   CK_LONG u32count;

   printf("\n");
   printf("\n");

   printf("***************** Help for command %s ****************** \n", kmu_current_cmd.s_cmdName);


   for (u32count = 0; u32count < MAX_ARGUMENT; u32count++)
   {
      // if arg is NULL stop the loop
      if (kmu_current_cmd.sCommand[u32count].s_argName == NULL)
      {
         // if command without argument, just stop the loop and print it
         if (u32count == 0)
         {
            printf("\nThis command doesn't need arguments\n");
            return;
         }
         break;
      }

      printf("%s \t\t", kmu_current_cmd.sCommand[u32count].s_argName);

      if (strlen(kmu_current_cmd.sCommand[u32count].s_argName) < 7)
      {
         printf("\t");
      }

      if (strlen(kmu_current_cmd.sCommand[u32count].s_argName) < 14)
      {
         printf("\t");
      }

      printf("%s \n", kmu_current_cmd.sCommand[u32count].s_argHelp);
   } 

   printf("\nSee below an example:\n");
   printf("%s -slot=0 -password xxxxxxxx\n\n", kmu_current_cmd.s_cmdName);
   printf("Note: Argument with space or equal is allowed. As example: -slot 0 or -slot=0\n");
}


/*
    FUNCTION:        CK_BBOOL parser_CheckArg(STRING str_argument_part1, STRING str_argument_part2)
*/
CK_BBOOL parser_IsArgExists(CK_CHAR_PTR str_argument_part1)
{
   CK_LONG s32count;
   CK_BYTE bArgNumber = kmu_current_cmd.bArgNumber;

   // loop on all existing command
   for (s32count = 0; s32count < bArgNumber; s32count++)
   {
      if (strcmp(kmu_current_cmd.sArg[s32count].s_argPart1, str_argument_part1) == 0)
      {
         return CK_TRUE;
      }
   }

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL parser_CheckArg(STRING str_argument_part1, STRING str_argument_part2)
*/
CK_BBOOL parser_CheckArg(CK_CHAR_PTR str_argument_part1, CK_CHAR_PTR str_argument_part2)
{

   CK_LONG u32count;
   CK_BYTE bArgNumber = kmu_current_cmd.bArgNumber;
   CK_BBOOL bFound = CK_FALSE;
   CK_CHAR_PTR sArg;

   // convert from upper case to lower case if needed
   str_argument_part1 = str_tolower(str_argument_part1);

   for (u32count = 0; u32count < MAX_ARGUMENT; u32count++)
   {
      sArg = kmu_current_cmd.sCommand[u32count].s_argName;

      if (sArg == NULL)
      {
         break;
      }

      // check if command string match
      if (strcmp(str_argument_part1, sArg) == 0)
      {
         if (parser_IsArgExists(str_argument_part1) == CK_TRUE)
         {
            printf("argument already exists: %s\n", str_argument_part1);
            return CK_FALSE;
         }
         // Command match
         kmu_current_cmd.sArg[bArgNumber].s_argPart1 = str_argument_part1;
         kmu_current_cmd.sArg[bArgNumber].s_argPart2 = str_argument_part2;
         kmu_current_cmd.sArg[bArgNumber].s_argType = kmu_current_cmd.sCommand[u32count].s_argType;
         bArgNumber++;
         kmu_current_cmd.bArgNumber = bArgNumber;

         bFound = CK_TRUE;
         break;
      }
   }

   if (bFound == CK_TRUE)
   {
      return CK_TRUE;
   }

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL parser_ParseArg(int argc, char* argv[])
*/
CK_BBOOL parser_ParseArg(int argc, char* argv[])
{
   int		s32count;
   CK_CHAR_PTR	str_argument_part1;
   CK_CHAR_PTR	str_argument_part2;


   for (s32count = 0; s32count < argc; s32count++)
   {
      // printf_s("  argv[%d]   %s\n", s32count, argv[s32count]);

      str_argument_part1 = argv[s32count];
      str_argument_part2 = argv[s32count];

      // Search for dash
      if (str_argument_part1[0] != strDash)
      {
         if (s32count == 0)
         {
            // print help
            parser_ArgHelp();
         }
         else
         {
            // case where argument doesn't start by a dash
            printf("Invalid Argument: %s \n", str_argument_part1);
         }

         return CK_FALSE;
      }

      // Move pointer just after -
      //str_argument_part1++;

      // Search for character "=". Fonction return NULL is absent
      str_argument_part2 = strchr(str_argument_part2, strEqual);

      // if character = is absent, search for next argument
      if (str_argument_part2 == NULL)
      {
         if (s32count < argc)
         {
            // move to next argument
            str_argument_part2 = argv[s32count + 1];

            // if argument is null, return an error
            if (str_argument_part2 == NULL)
            {
               printf("unknown parameters: %s\n", str_argument_part1);
               return CK_FALSE;
            }

            // if next arguement start with dash "-", return error
            if (str_argument_part2[0] == strDash)
            {
               printf("unknown parameters: %s %s\n", str_argument_part1, str_argument_part2);
               return CK_FALSE;
            }
            else
            {
               // next argument does not contains dash, skip it on the next loop
               s32count++;
            }
         }
         else
         {
            printf("Wrong parameters: %s %s\n", str_argument_part1, str_argument_part2);
            return CK_FALSE;
         }
      }
      else
      {
         // replace character "=" by \0 (end of string)
         str_argument_part2[0] = '\0';
         // Move pointer after =
         str_argument_part2++;
      }

      // Check argument part 1 and part 2
      if (parser_CheckArg(str_argument_part1, str_argument_part2) == CK_FALSE)
      {

         printf("unknown parameters: %s ", str_argument_part1);
         if (str_argument_part2 != NULL)
         {
            printf("%s", str_argument_part2);
         }
         printf("\n");
         return CK_FALSE;
      }
   }
   return CK_TRUE;
}

/*
    FUNCTION:        PARSER_CURRENT_CMD_ARG * parser_SearchArgument(BYTE bArgType)
*/
PARSER_CURRENT_CMD_ARG* parser_SearchArgument(CK_BYTE bArgType)
{
   int u32count;
   for (u32count = 0; u32count < kmu_current_cmd.bArgNumber; u32count++)
   {
      if (kmu_current_cmd.sArg[u32count].s_argType == bArgType)
      {
         return &kmu_current_cmd.sArg[u32count];
      }
   }
   return NULL;
}

/*
    FUNCTION:        CK_BBOOL parser_IsCommand(CK_CHAR_PTR sCommand)
*/
CK_BBOOL parser_IsCommand(CK_CHAR_PTR sCommand)
{
   if (strcmp(kmu_current_cmd.s_cmdName, sCommand) == 0)
   {
      return CK_TRUE;
   }

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL parser_CommandParser(int argc, char* argv[], char** envp)
*/
CK_BBOOL parser_CommandParser(int argc, char* argv[])
{
   memset(&kmu_current_cmd, 0, sizeof(PARSER_COMMAND));

   // Check if valid command
   if (parser_CheckCommand(argv[0]) == CK_FALSE)
   {

      // display help
      return CK_FALSE;
   }
   argc--;
   return parser_ParseArg(argc, &argv[1]);
}

/*
    FUNCTION:        CK_BBOOL parser_ExecuteCommand(CK_BBOOL bIsConsole)
*/
CK_BBOOL parser_ExecuteCommand(CK_BBOOL bIsConsole)
{
   return kmu_current_cmd.pCmd(bIsConsole);
}





