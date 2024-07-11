/****************************************************************************\
*
* This file is part of the "Luna KMU" tool.
*
* The "KMU" tool is provided under the MIT license (see the
* following Web site for further details: https://mit-license.org/ ).
*
* Copyright © 2023-2024 Thales Group
*
\****************************************************************************/

#ifndef _BASE64_H_
#define _BASE64_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _BASE64_C
#define _EXT
#else
#define _EXT extern
#endif


   _EXT  char*    b64_encode(const unsigned char* in, size_t len);
   _EXT  int      b64_decode(const char* in, unsigned char* out, size_t outlen);
   _EXT  size_t   b64_decoded_size(const char* in);
   _EXT  size_t   b64_encoded_size(size_t inlen);


#undef _EXT
#endif // _BASE64_H_