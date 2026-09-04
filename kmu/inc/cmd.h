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

#ifndef _CMD_H_
#define _CMD_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _CMD_C
#define _EXT
#else
#define _EXT extern
#endif

   _EXT  CK_BBOOL    cmd_kmu_list(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_login(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_logout(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_list_SLot(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_getcapabilities(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_getattribute(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_setattribute(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_readattribute(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_writeattribute(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_generateKey(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_createDO(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_import(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_export(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_encrypt(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_decrypt(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_derive(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_convert(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_delete(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_digestKey(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_compute_KCV(CK_BBOOL bIsConsole);
   _EXT  CK_BBOOL    cmd_kmu_remote_mzmk(CK_BBOOL bIsConsole);

   _EXT  CK_BYTE     cmd_setattributeBoolean(CK_OBJECT_HANDLE hHandle, CK_BYTE bArgType, CK_ATTRIBUTE_TYPE cAttribute);
   _EXT  CK_BYTE     cmd_setattributeString(CK_OBJECT_HANDLE hHandle, CK_BYTE bArgType, CK_ATTRIBUTE_TYPE cAttribute);
   _EXT  CK_BYTE     cmd_setattributeArray(CK_OBJECT_HANDLE hHandle, CK_BYTE bArgType, CK_ATTRIBUTE_TYPE cAttribute);
   _EXT  CK_BBOOL    cmd_WrapPrivateSecretkey(P11_WRAPTEMPLATE* sWrapTemplate, CK_CHAR_PTR sFilePath, CK_BYTE FileFormat);
   _EXT  CK_BBOOL    cmd_UnwrapPrivateSecretkey(P11_UNWRAPTEMPLATE* sUnwrapTemplate, CK_CHAR_PTR sFilePath, CK_BYTE FileFormat);
   _EXT  CK_BBOOL    cmd_ExportPublickey(P11_WRAPTEMPLATE* sExportTemplate, CK_CHAR_PTR sFilePath, CK_BYTE FileFormat);
   _EXT  CK_BBOOL    cmd_ImportPublickey(P11_UNWRAPTEMPLATE* sImportTemplate, CK_CHAR_PTR sFilePath, CK_BYTE FileFormat);
   _EXT  CK_BBOOL    cmd_GenerateSecretKeyWithComponent(P11_KEYGENTEMPLATE* sKeyGenTemplate, CK_LONG sCompomentNumber);
   _EXT  CK_BBOOL    cmd_ImportSecretKeyWithComponent(P11_UNWRAPTEMPLATE* sImportTemplate, CK_LONG sCompomentNumber);

#undef _EXT

#endif // _CMD_H_