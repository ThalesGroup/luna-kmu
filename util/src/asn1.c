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

#define _ASN1_C

#ifdef OS_WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
#include "asn1.h"


#define LENGTH_TAG_ONE_BYTE      0x81
#define LENGTH_TAG_TWO_BYTE      0x82

#define LENGTH_128               (CK_ULONG)(0x0080)
#define LENGTH_256               (CK_ULONG)(0x0100)
#define LENGTH_64K               (CK_ULONG)(0x10000)


#define ASN1_WORKING_BUFFER_SIZE    10240 // enough for all keys

CK_CHAR           asn1_BuildBuffer[10240];
CK_ULONG          asn1_BuildBufferoffset;
CK_ULONG          asn1_BuildBufferSize;

#define           ASN1_MAX_TLV_LEVEL             10
CK_CHAR_PTR       asn1_CheckBuffer;
CK_ULONG          asn1_CheckBufferoffset;
CK_ULONG          asn1_CheckBufferSize;
CK_ULONG          asn1_CheckOffsetValue[ASN1_MAX_TLV_LEVEL];
CK_ULONG          asn1_CheckLengthValue[ASN1_MAX_TLV_LEVEL];
CK_BYTE           asn1_CheckLevel;


/*
    FUNCTION:        CK_BBOOL asn1_Build_Init(CK_LONG uSize)
*/
CK_BBOOL asn1_Build_Init()
{
   asn1_BuildBufferoffset = ASN1_WORKING_BUFFER_SIZE;
   asn1_BuildBufferSize = 0;
   memset(asn1_BuildBuffer, 0, ASN1_WORKING_BUFFER_SIZE);
   return CK_TRUE;
}

/*
    FUNCTION:        CK_CHAR_PTR asn1_BuildGetBuffer()
*/
CK_CHAR_PTR asn1_BuildGetBuffer()
{
   return &asn1_BuildBuffer[asn1_BuildBufferoffset];
}

/*
    FUNCTION:        CK_ULONG asn1_GetBufferSize()
*/
CK_ULONG asn1_GetBufferSize()
{
   return asn1_BuildBufferSize;
}

/*
    FUNCTION:        CK_ULONG asn1_Build_tl(CK_BYTE tag, CK_ULONG uSize)
*/
CK_ULONG asn1_Build_tl(CK_BYTE tag, CK_ULONG size)
{
   CK_ULONG uCurrentTlvSize = asn1_BuildBufferSize;

   // if tag integer
   if (tag == TAG_INTEGER)
   {
      // if the last byte is greater than 128, add zero to set integer positive
      if (asn1_BuildBuffer[asn1_BuildBufferoffset] >= 0x80)
      {
         // add null byte
         size += asn1_BuildNullByte();
      }
   }
   // if tag bit string add null byte
   if (tag == TAG_BITSTRING)
   {
      size += asn1_BuildNullByte();
   }

   if (size < LENGTH_128)
   {
      asn1_BuildBufferoffset--;
      asn1_BuildBuffer[asn1_BuildBufferoffset] = (CK_BYTE)size;
      asn1_BuildBufferSize++;
   }
   else if (size < LENGTH_256)
   {
      asn1_BuildBufferoffset--;
      asn1_BuildBuffer[asn1_BuildBufferoffset] = (CK_BYTE)size;
      asn1_BuildBufferoffset--;
      asn1_BuildBuffer[asn1_BuildBufferoffset] = LENGTH_TAG_ONE_BYTE;
      asn1_BuildBufferSize += 2;
   }
   else if (size < LENGTH_64K)
   {
      asn1_BuildBufferoffset--;
      asn1_BuildBuffer[asn1_BuildBufferoffset] = (CK_BYTE)size;
      asn1_BuildBufferoffset--;
      asn1_BuildBuffer[asn1_BuildBufferoffset] = (CK_BYTE)(size >> 8);
      asn1_BuildBufferoffset--;
      asn1_BuildBuffer[asn1_BuildBufferoffset] = LENGTH_TAG_TWO_BYTE;
      asn1_BuildBufferSize += 3;
   };
   asn1_BuildBufferoffset--;
   asn1_BuildBuffer[asn1_BuildBufferoffset] = tag;
   asn1_BuildBufferSize++;

   // return uSize of this TLV
   return (asn1_BuildBufferSize - uCurrentTlvSize);
}

/*
    FUNCTION:        CK_ULONG asn1_Build_tlv(CK_BYTE tag,CK_CHAR_PTR data, CK_ULONG uSize)
*/
CK_ULONG asn1_Build_tlv(CK_BYTE tag, CK_CHAR_PTR data, CK_ULONG size)
{
   CK_ULONG uCurrentTlvSize = asn1_BuildBufferSize;

   asn1_BuildBufferSize += size;

   // copy the data to the end of the buffer
   memcpy(&asn1_BuildBuffer[asn1_BuildBufferoffset - size], data, size);
   asn1_BuildBufferoffset -= size;

   asn1_Build_tl(tag, size);

   // return uSize of this TLV
   return (asn1_BuildBufferSize - uCurrentTlvSize);
}

/*
    FUNCTION:        CK_ULONG asn1_Build_tlv_Long(CK_BYTE tag, CK_ULONG Value)
*/
CK_ULONG asn1_Build_tlv_Long(CK_BYTE tag, CK_ULONG Value)
{
   CK_ULONG size = 0;
   CK_ULONG uCurrentTlvSize = asn1_BuildBufferSize;

   if (Value < 0xFF)
   {
      size = 1;
      asn1_BuildBuffer[--asn1_BuildBufferoffset] = (CK_BYTE)Value;
   }
   else if (Value < 0xFFFF)
   {
      size = 2;
      asn1_BuildBuffer[--asn1_BuildBufferoffset] = (CK_BYTE)Value;
      asn1_BuildBuffer[--asn1_BuildBufferoffset] = (CK_BYTE)(Value >> 8);
   }
   else if (Value < 0xFFFFFF)
   {
      size = 3;
      asn1_BuildBuffer[--asn1_BuildBufferoffset] = (CK_BYTE)Value;
      asn1_BuildBuffer[--asn1_BuildBufferoffset] = (CK_BYTE)(Value >> 8);
      asn1_BuildBuffer[--asn1_BuildBufferoffset] = (CK_BYTE)(Value >> 16);
   }
   else
   {
      size = 4;
      asn1_BuildBuffer[--asn1_BuildBufferoffset] = (CK_BYTE)Value;
      asn1_BuildBuffer[--asn1_BuildBufferoffset] = (CK_BYTE)(Value >> 8);
      asn1_BuildBuffer[--asn1_BuildBufferoffset] = (CK_BYTE)(Value >> 16);
      asn1_BuildBuffer[--asn1_BuildBufferoffset] = (CK_BYTE)(Value >> 24);
   }


   asn1_BuildBufferSize += size;

   asn1_Build_tl(tag, size);

   // return uSize of this TLV
   return (asn1_BuildBufferSize - uCurrentTlvSize);
}

/*
    FUNCTION:        CK_ULONG asn1_Build_tlv(CK_BYTE tag,CK_CHAR_PTR data, CK_ULONG uSize)
*/
CK_ULONG asn1_Build_t(CK_CHAR_PTR data, CK_ULONG size)
{
   CK_ULONG uCurrentTlvSize = asn1_BuildBufferSize;

   asn1_BuildBufferSize += size;

   // copy the data to the end of the buffer
   memcpy(&asn1_BuildBuffer[asn1_BuildBufferoffset - size], data, size);
   asn1_BuildBufferoffset -= size;

   // return uSize of this TLV
   return (asn1_BuildBufferSize - uCurrentTlvSize);
}

/*
    FUNCTION:        CK_ULONG asn1_BuildNullByte()
*/
CK_ULONG asn1_BuildNullByte()
{
   asn1_BuildBufferoffset--;
   asn1_BuildBuffer[asn1_BuildBufferoffset] = (CK_BYTE)0x00;
   asn1_BuildBufferSize++;

   return 1;
}

/*
    FUNCTION:        void asn1_Check_SetTlv(CK_CHAR_PTR data, CK_ULONG uSize)
*/
void asn1_Check_SetTlv(CK_CHAR_PTR data, CK_ULONG size)
{
   asn1_CheckBuffer = data;
   asn1_CheckBufferoffset = 0;
   asn1_CheckBufferSize = size;
   asn1_CheckLevel = 0;
   memset(asn1_CheckOffsetValue, 0, sizeof(asn1_CheckOffsetValue));
   memset(asn1_CheckLengthValue, 0, sizeof(asn1_CheckLengthValue));

}

/*
    FUNCTION:        CK_BBOOL asn1_Check_t(CK_CHAR_PTR data, CK_ULONG uSize)
*/
CK_BBOOL asn1_Check_t(CK_BYTE tag)
{
   CK_ULONG uSize;
   CK_BYTE  bTagLen;
   CK_ULONG uCurrentSize = 0;
   CK_BYTE  btest;

   do
   {
      // Check tag match
      btest = asn1_CheckBuffer[asn1_CheckBufferoffset];
      if (asn1_CheckBuffer[asn1_CheckBufferoffset] != tag)
      {
         break;
      }
      uCurrentSize++;

      // check Length
      bTagLen = asn1_CheckBuffer[asn1_CheckBufferoffset + 1];
      if (bTagLen < LENGTH_128)
      {
         // get the size
         uSize = (CK_ULONG)bTagLen;
         uCurrentSize++;
      }
      else if (bTagLen == LENGTH_TAG_ONE_BYTE)
      {
         // get the size
         uSize = asn1_CheckBuffer[asn1_CheckBufferoffset + 2];
         uCurrentSize += 2;
      }
      else if (bTagLen == LENGTH_TAG_TWO_BYTE)
      {
         // get the size
         uSize = (CK_ULONG)(asn1_CheckBuffer[asn1_CheckBufferoffset + 2] << 8) + asn1_CheckBuffer[asn1_CheckBufferoffset + 3];
         uCurrentSize += 3;
      }
      else
      {
         break;
      }

      // if tag string, check the null byte
      if (tag == TAG_BITSTRING)
      {
         if (asn1_CheckBuffer[asn1_CheckBufferoffset + uCurrentSize] != 0x00)
         {
            break;
         }
         uCurrentSize++;
         uSize--;
      }

      // if tag string, check the null byte
      if (tag == TAG_INTEGER)
      {
         // check value zero
         if (asn1_CheckBuffer[asn1_CheckBufferoffset + uCurrentSize] == 0x00)
         {
            // check if next byte is greater than 128
            if (asn1_CheckBuffer[asn1_CheckBufferoffset + uCurrentSize + 1] > 0x80)
            {
               // if positive, increment value offset
               uCurrentSize++;
               uSize--;
            }

         }
      }

      // Set offset to data
      asn1_CheckOffsetValue[asn1_CheckLevel] = asn1_CheckBufferoffset + uCurrentSize;
      asn1_CheckLengthValue[asn1_CheckLevel] = uSize;

      return CK_TRUE;


   } while (FALSE);

   return CK_FALSE;
}

/*
    FUNCTION:        CK_BBOOL asn1_Check_tl(CK_CHAR_PTR data, CK_ULONG uSize)
*/
CK_BBOOL asn1_Check_tl(CK_BYTE tag)
{
   CK_ULONG uCurrentSize = 0;

   if (asn1_Check_t(tag) == CK_TRUE)
   {
      uCurrentSize = asn1_CheckOffsetValue[asn1_CheckLevel] + asn1_CheckLengthValue[asn1_CheckLevel];
      // check the size of tlv buffer mtach with size of T + L
      if (uCurrentSize == asn1_CheckBufferSize)
      {
         return CK_TRUE;
      }
   }

   return CK_FALSE;
}

/*
    FUNCTION:       CK_CHAR_PTR asn1_Check_GetCurrentValueBuffer()
*/
CK_CHAR_PTR asn1_Check_GetCurrentValueBuffer()
{
   return &asn1_CheckBuffer[asn1_CheckOffsetValue[asn1_CheckLevel]];
}

/*
    FUNCTION:       CK_BBOOL asn1_Check_GetCurrentValueLong(CK_ULONG_PTR pulInteger)
*/
CK_BBOOL asn1_Check_GetCurrentValueLong(CK_ULONG_PTR pulInteger)
{
   CK_ULONG uOffset = asn1_CheckBufferoffset;
   CK_BYTE  bLen;
   CK_ULONG ulInteger = 0;

   // go to length
   uOffset++;

   bLen = asn1_CheckBuffer[uOffset];

   if (bLen == 0x01)
   {
      uOffset++;
      ulInteger = (CK_ULONG)asn1_CheckBuffer[uOffset];
   }
   else if (bLen == 0x02)
   {
      uOffset++;
      ulInteger = (CK_ULONG)(asn1_CheckBuffer[uOffset]) << 8;
      uOffset++;
      ulInteger = ulInteger + (CK_ULONG)asn1_CheckBuffer[uOffset];
   }

   else if (bLen == 0x03)
   {
      uOffset++;
      ulInteger = (CK_ULONG)(asn1_CheckBuffer[uOffset]) << 16;
      uOffset++;
      ulInteger = (CK_ULONG)(asn1_CheckBuffer[uOffset]) << 8;
      uOffset++;
      ulInteger = ulInteger + (CK_ULONG)asn1_CheckBuffer[uOffset];
   }

   else if (bLen == 0x04)
   {
      uOffset++;
      ulInteger = (CK_ULONG)(asn1_CheckBuffer[uOffset]) << 24;
      uOffset++;
      ulInteger = (CK_ULONG)(asn1_CheckBuffer[uOffset]) << 16;
      uOffset++;
      ulInteger = (CK_ULONG)(asn1_CheckBuffer[uOffset]) << 8;
      uOffset++;
      ulInteger = ulInteger + (CK_ULONG)asn1_CheckBuffer[uOffset];
   }
   else
   {
      return CK_FALSE;
   }

   *pulInteger = ulInteger;

   return CK_TRUE;
}

/*
    FUNCTION:        CK_CHAR_PTR asn1_Check_GetCurrentTagBuffer()
*/
CK_CHAR_PTR asn1_Check_GetCurrentTagBuffer()
{
   return &asn1_CheckBuffer[asn1_CheckBufferoffset];
}

/*
    FUNCTION:        CK_ULONG asn1_Check_GetCurrentValueLen()
*/
CK_ULONG asn1_Check_GetCurrentValueLen()
{
   return asn1_CheckLengthValue[asn1_CheckLevel];
}
/*
    FUNCTION:        CK_ULONG asn1_Check_GetCurrentTlvLen()
*/
CK_ULONG asn1_Check_GetCurrentTlvLen()
{
   return asn1_CheckLengthValue[asn1_CheckLevel] + asn1_CheckOffsetValue[asn1_CheckLevel] - asn1_CheckBufferoffset;
}

/*
    FUNCTION:        CK_BBOOL asn1_Check_StepIn()
*/
CK_BBOOL asn1_Check_StepIn()
{
   asn1_CheckBufferoffset = asn1_CheckOffsetValue[asn1_CheckLevel];
   asn1_CheckLevel++;
   // check if level max not reached
   if (asn1_CheckLevel >= ASN1_MAX_TLV_LEVEL)
   {
      return CK_FALSE;
   }
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL asn1_Check_StepIn()
*/
CK_BBOOL asn1_Check_StepOut()
{
   // if level zero, return error
   if (asn1_CheckLevel == 0)
   {
      return CK_FALSE;
   }

   asn1_CheckLevel--;
   asn1_CheckBufferoffset = asn1_CheckOffsetValue[asn1_CheckLevel];
   return CK_TRUE;
}

/*
    FUNCTION:        CK_BBOOL asn1_Check_Next(CK_BYTE tag)
*/
CK_BBOOL asn1_Check_Next(CK_BYTE tag)
{
   asn1_CheckBufferoffset = asn1_CheckOffsetValue[asn1_CheckLevel] + asn1_CheckLengthValue[asn1_CheckLevel];
   return asn1_Check_t(tag);
}
/*
    FUNCTION:        CK_BBOOL asn1_Check_NoNextTlv()
*/
CK_BBOOL asn1_Check_NoNextTlv()
{
   // if level zero, return error
   if (asn1_CheckLevel == 0)
   {
      if (asn1_CheckBufferSize == (asn1_CheckOffsetValue[asn1_CheckLevel] + asn1_CheckLengthValue[asn1_CheckLevel]))
      {
         return CK_TRUE;
      }
   }
   else
   {
      // check data offset offset + data length in current level is equal to the end offset of the upper level (upper level data offset + upper level data length)
      if ((asn1_CheckOffsetValue[asn1_CheckLevel - 1] + asn1_CheckLengthValue[asn1_CheckLevel - 1]) == (asn1_CheckOffsetValue[asn1_CheckLevel] + asn1_CheckLengthValue[asn1_CheckLevel]))
      {
         return CK_TRUE;
      }
   }

   return CK_FALSE;
}