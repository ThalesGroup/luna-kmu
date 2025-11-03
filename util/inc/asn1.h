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

#ifndef _ASN1_H_
#define _ASN1_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _ASN1_C
#define _EXT
#else
#define _EXT extern
#endif

#define TAG_SEQUENCE             0x30
#define TAG_OID                  0x06
#define TAG_BITSTRING            0x03
#define TAG_OCTECTSTRING         0x04
#define TAG_INTEGER              0x02
#define TAG_NULL                 0x05



   _EXT  CK_BBOOL       asn1_Build_Init();
   _EXT  CK_ULONG       asn1_Build_tlv(CK_BYTE tag, CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_ULONG       asn1_Build_tlv_Long(CK_BYTE tag, CK_ULONG Value);
   _EXT  CK_ULONG       asn1_Build_tl(CK_BYTE tag, CK_ULONG size);
   _EXT  CK_ULONG       asn1_Build_t(CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_ULONG       asn1_BuildNullByte();
   _EXT  CK_CHAR_PTR    asn1_BuildGetBuffer();
   _EXT  CK_ULONG       asn1_GetBufferSize();

   _EXT  void           asn1_Check_SetTlv(CK_CHAR_PTR data, CK_ULONG size);
   _EXT  CK_BBOOL       asn1_Check_t(CK_BYTE tag);
   _EXT  CK_BBOOL       asn1_Check_tl(CK_BYTE tag);
   _EXT  CK_CHAR_PTR    asn1_Check_GetCurrentValueBuffer();
   _EXT  CK_CHAR_PTR    asn1_Check_GetCurrentTagBuffer();
   _EXT  CK_BBOOL       asn1_Check_GetCurrentValueLong(CK_ULONG_PTR pulInteger);
   _EXT  CK_ULONG       asn1_Check_GetCurrentValueLen();
   _EXT  CK_ULONG       asn1_Check_GetCurrentTlvLen();
   _EXT  CK_BBOOL       asn1_Check_StepIn();
   _EXT  CK_BBOOL       asn1_Check_StepOut();
   _EXT  CK_BBOOL       asn1_Check_Next(CK_BYTE tag);
   _EXT  CK_BBOOL       asn1_Check_NoNextTlv();

#undef _EXT

#endif // _ASN1_H_