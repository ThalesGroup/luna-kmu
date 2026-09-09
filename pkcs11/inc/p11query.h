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

#ifndef _P11_QUERY_H_
#define _P11_QUERY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "p11.h"

#ifdef _P11_QUERY_C
#define _EXT
#else
#define _EXT extern
#endif

#define P11_SLOT_LABEL_MAX    32  /* CK_TOKEN_INFO.label is 32 */
#define P11_OBJECT_LABEL_MAX  64
#define P11_KEY_TYPE_NONE     ((CK_KEY_TYPE)-1)
#define P11_OBJECT_FIND_BATCH 32
#define P11_OBJECT_PAGE_DEFAULT 50
#define P11_CAP_NAME_MAX      32
#define P11_CAP_NOTE_MAX      160
#define P11_CAP_MAX_ROWS      32
#define P11_QUERY_ERR_MAX     256
#define P11_FILE_FORMAT_TEXT    0x10
#define P11_FILE_FORMAT_BINARY  (0x10 | CK_TRUE)
#define P11_FILE_FORMAT_PKCS8   0x20
#define P11_FILE_FORMAT_TR31    0x80

   typedef struct
   {
      CK_SLOT_ID slotId;
      CK_CHAR    label[P11_SLOT_LABEL_MAX + 1];
      CK_CHAR    model[P11_SLOT_MODEL_MAX + 1];
      CK_CHAR    firmware[P11_SLOT_VERSION_MAX];
      CK_CHAR    software[P11_SLOT_VERSION_MAX];
      CK_CHAR    serial[P11_SLOT_SERIAL_MAX + 1];
      CK_BBOOL   bPasswordRequired; /* CK_FALSE when CKF_PROTECTED_AUTHENTICATION_PATH */
   } P11_SLOT_ROW;

   typedef struct
   {
      CK_OBJECT_HANDLE handle;
      CK_OBJECT_CLASS  ckClass;
      CK_KEY_TYPE      keyType; /* P11_KEY_TYPE_NONE when the object is not a key */
      CK_CHAR          label[P11_OBJECT_LABEL_MAX + 1];
   } P11_OBJECT_ROW;

   _EXT  CK_BBOOL P11_QuerySlots(P11_SLOT_ROW* rows, CK_ULONG maxRows, CK_ULONG* pCount);
   _EXT  CK_BBOOL P11_QueryObjects(P11_OBJECT_ROW* rows, CK_ULONG maxRows, CK_LONG lLimit, CK_ULONG* pCount);
   /* Incremental list (one find). UI thread only; Close when the dialog goes away. */
   _EXT  CK_BBOOL P11_QueryObjectsOpen(void);
   _EXT  CK_BBOOL P11_QueryObjectsNext(P11_OBJECT_ROW* rows, CK_ULONG maxRows, CK_ULONG* pCount, CK_BBOOL* pHasMore);
   _EXT  void     P11_QueryObjectsClose(void);
   _EXT  CK_BBOOL P11_QueryDestroyObject(CK_OBJECT_HANDLE hObj, CK_RV* pRv);
   _EXT  CK_BBOOL P11_QueryAttrBool(CK_OBJECT_HANDLE hObj, CK_ATTRIBUTE_TYPE type, CK_BBOOL* pVal);
   _EXT  CK_BBOOL P11_QueryAttrUlong(CK_OBJECT_HANDLE hObj, CK_ATTRIBUTE_TYPE type, CK_ULONG* pVal);
   _EXT  CK_BBOOL P11_QueryAttrBytes(CK_OBJECT_HANDLE hObj, CK_ATTRIBUTE_TYPE type,
                                    CK_BYTE** ppData, CK_ULONG* pLen, CK_RV* pRv);
   _EXT  CK_BBOOL P11_QueryCreateDO(P11_DOTEMPLATE* pTpl, CK_OBJECT_HANDLE* pHandle, CK_RV* pRv);
   /* Caller frees *ppDigest / *ppKcv. KCV is the first 3 bytes, same as the CLI. */
   _EXT  CK_BBOOL P11_QueryDigestKey(CK_OBJECT_HANDLE hKey, P11_HASH_MECH* sHash,
                                    CK_BYTE** ppDigest, CK_ULONG* pLen, CK_RV* pRv);
   _EXT  CK_BBOOL P11_QueryComputeKCV(CK_OBJECT_HANDLE hKey, BYTE bMethod,
                                     CK_BYTE** ppKcv, CK_ULONG* pLen, CK_RV* pRv);

   typedef struct
   {
      CK_CHAR     name[P11_CAP_NAME_MAX];
      CK_KEY_TYPE keyType;
      CK_BBOOL    bSupported;
      CK_BBOOL    bNoKeySize; /* HSS: mechanism exists but size is N/A */
      CK_ULONG    ulMinKeySize;
      CK_ULONG    ulMaxKeySize;
      CK_CHAR     note[P11_CAP_NOTE_MAX];
   } P11_CAP_ROW;

   /* Slot only; no session. Same key-gen mechanisms as CLI getcapabilities. */
   _EXT  CK_BBOOL P11_QueryCapabilities(CK_SLOT_ID slotId, P11_CAP_ROW* rows,
                                        CK_ULONG maxRows, CK_ULONG* pCount, CK_RV* pRv);

   /* Copy table wrap/PBE params and overlay optional IV / AAD / OAEP hash / password.
      ivBuf and aadBuf must stay alive until wrap/unwrap returns. */
   _EXT  CK_BBOOL P11_QueryBuildWrapMech(const char* algoName, CK_ULONG uFlag,
                                        const char* ivHex, const char* aadHex, CK_ULONG tagBits,
                                        const char* oaepHashName, P11_ENCRYPTION_MECH* pMech,
                                        CK_BYTE* ivBuf, CK_ULONG ivBufMax,
                                        CK_BYTE* aadBuf, CK_ULONG aadBufMax,
                                        char* err, CK_ULONG errMax);
   _EXT  CK_BBOOL P11_QueryBuildPbeMech(const char* algoName, const char* password,
                                       const char* saltHex, CK_LONG iterations, const char* ivHex,
                                       P11_ENCRYPTION_MECH* pMech, char* err, CK_ULONG errMax);

   _EXT  CK_BBOOL P11_QueryExportKey(P11_WRAPTEMPLATE* pTpl, const char* path, CK_BYTE format,
                                    CK_ULONG* pWritten, char* err, CK_ULONG errMax);
   _EXT  CK_BBOOL P11_QueryImportKey(P11_UNWRAPTEMPLATE* pTpl, const char* path, CK_BYTE format,
                                    const char* pbePassword, CK_OBJECT_HANDLE* pHandle,
                                    char* err, CK_ULONG errMax);
   /* No session. text <-> bin only. */
   _EXT  CK_BBOOL P11_QueryConvertFile(const char* inPath, CK_BYTE inFmt,
                                      const char* outPath, CK_BYTE outFmt,
                                      CK_ULONG* pWritten, char* err, CK_ULONG errMax);
   /* bDecrypt CK_FALSE = encrypt. Format is text or binary. Caller owns pMech. */
   _EXT  CK_BBOOL P11_QueryCryptFile(CK_BBOOL bDecrypt, CK_OBJECT_HANDLE hKey,
                                    P11_ENCRYPTION_MECH* pMech, const char* inPath,
                                    const char* outPath, CK_BYTE format,
                                    CK_ULONG* pWritten, char* err, CK_ULONG errMax);

   _EXT  CK_BBOOL P11_QueryBuildSignMech(const char* algoName, const char* pssHashName,
                                        P11_SIGN_MECH* pMech, char* err, CK_ULONG errMax);
   /* Sign writes the signature to outPath. Verify reads data from inPath and signature from sigPath. */
   _EXT  CK_BBOOL P11_QuerySignFile(CK_OBJECT_HANDLE hKey, P11_SIGN_MECH* pMech,
                                   const char* inPath, const char* outPath, CK_BYTE format,
                                   CK_ULONG* pWritten, char* err, CK_ULONG errMax);
   _EXT  CK_BBOOL P11_QueryVerifyFile(CK_OBJECT_HANDLE hKey, P11_SIGN_MECH* pMech,
                                     const char* inPath, const char* sigPath, CK_BYTE format,
                                     char* err, CK_ULONG errMax);

   /* labelBuf / ctxBuf must stay alive until C_DeriveKey returns. */
   _EXT  CK_BBOOL P11_QueryBuildDeriveMech(const char* algoName, const char* kdfType,
                                          const char* kdfScheme, CK_ULONG counter,
                                          const char* labelHex, const char* contextHex,
                                          P11_DERIVE_MECH* pMech,
                                          CK_BYTE* labelBuf, CK_ULONG labelMax,
                                          CK_BYTE* ctxBuf, CK_ULONG ctxMax,
                                          char* err, CK_ULONG errMax);
   _EXT  CK_BBOOL P11_QueryDeriveKey(P11_DERIVETEMPLATE* pTpl, CK_OBJECT_HANDLE* pHandle,
                                    char* err, CK_ULONG errMax);
   /* Handle wins if handleText is a number. Otherwise find by CKA_LABEL and/or CKA_ID (hex). */
   _EXT  CK_OBJECT_HANDLE P11_QueryResolveKey(const char* handleText, const char* label,
                                             const char* idHex, char* err, CK_ULONG errMax);
   /* For aes-encrypt-ecb. dataBuf must stay alive until C_DeriveKey. */
   _EXT  CK_BBOOL P11_QueryApplyDeriveEncryptData(P11_DERIVE_MECH* pMech, const char* dataHex,
                                                 CK_BYTE* dataBuf, CK_ULONG dataMax,
                                                 char* err, CK_ULONG errMax);
   /* Payshield TMD remote MZMK. csvPath receives the generated CSV path when provided. */
   _EXT  CK_BBOOL P11_QueryRemoteMzmk(P11_DERIVETEMPLATE* pTpl, const char* tmdPubPath,
                                     CK_OBJECT_HANDLE* pHandle,
                                     char* kcvHex, CK_ULONG kcvHexMax,
                                     char* csvPath, CK_ULONG csvPathMax,
                                     char* err, CK_ULONG errMax);

#undef _EXT

#ifdef __cplusplus
}
#endif

#endif   /* _P11_QUERY_H_ */
