#ifndef _TCPS_CBOR_ID_H
#define _TCPS_CBOR_ID_H
/******************************************************************************
* Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
*
*    Permission to use, copy, modify, and/or distribute this software for any
*    purpose with or without fee is hereby granted, provided that the above
*    copyright notice and this permission notice appear in all copies.
*
*    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
*    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
*    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
*    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
*    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
*    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
*    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

// TODO: define a common header that tooling and agent can 
//  share the following defines.
#define TCPS_ID_MAP_VER_CURENT    1

#define MAX_ASSERTION_KEY_LEN      0xf
#define TCPS_IDENTITY_MAP_VER      "VER"
#define TCPS_IDENTITY_MAP_FWID     "FIRMWID"
#define TCPS_IDENTITY_MAP_AUTH     "CODEAUTH"
#define TCPS_IDENTITY_MAP_PUBKEY   "PUBKEY"


#define ASSERT_TYPE_BUFFER      0
#define ASSERT_TYPE_INT         1

typedef struct _TcpsAssertion {
    char Name[MAX_ASSERTION_KEY_LEN];
    uint32_t DataType;
    union {
        struct {
            const uint8_t *Value;
            uint32_t Size;
        } Buff;
        int Value;
    } Data;
}TcpsAssertion;

RIOT_STATUS
BuildTCPSAliasIdentity(
    RIOT_ECC_PUBLIC *AuthKeyPub,
    uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t **Id,
    uint32_t *IdSize
);

RIOT_STATUS
BuildTCPSDeviceIdentity(
    RIOT_ECC_PUBLIC *Pub,
    RIOT_ECC_PUBLIC *AuthKeyPub,
    uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t **Id,
    uint32_t *IdSize
);

RIOT_STATUS
ModifyTCPSDeviceIdentity(
    uint8_t *ExistingId,
    uint32_t ExistingIdSize,
    RIOT_ECC_PUBLIC *Pub,
    RIOT_ECC_PUBLIC *AuthKeyPub,
    uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t **NewId,
    uint32_t *NewIdSize
);
void
FreeTCPSId(
    uint8_t *Id
);

#ifdef __cplusplus
}
#endif
#endif
