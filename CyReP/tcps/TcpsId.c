/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include <RiotTarget.h>
#include <RiotStatus.h>
#include <RiotEcc.h>
#include <TcpsId.h>
#include <cbor.h>
#include <stdlib.h>
#include <RiotCrypt.h>


// Ignore OutOfMemory to allow CBOR to gather size requirements.
#define CLEANUP_ENCODER_ERR(_e) \
    err = _e; \
    if(err != CborErrorOutOfMemory && \
       err != CborNoError) \
    { goto Cleanup; }

#define CLEANUP_DECODER_ERR(_e) \
    err = (_e); \
    if (err != CborNoError) \
    { goto Cleanup; }

//  Stack size of max assertion in a single ID
#define MAX_ASSERTION_COUNT        4


typedef struct _TcpsIdenity {
    TcpsAssertion AssertionArray[MAX_ASSERTION_COUNT];
    uint32_t Used;
} TcpsIdenity;

void
FreeTCPSId(
    uint8_t *Id
)
{
    if (Id != NULL)
    {
        free( Id );
    }
}

CborError
pBuildTCPSIdentity(
    TcpsAssertion *Assertions,
    size_t AssertionCount,
    uint8_t *Id,
    uint32_t IdSize,
    uint32_t *SizeNeeded
)
{
    CborError err;
    CborEncoder encodedId;
    CborEncoder map;
    size_t entryCount = AssertionCount;

    if (AssertionCount == 0 ||
        Assertions == NULL ||
        SizeNeeded == NULL)
    {
        err = CborUnknownError;
        goto Cleanup;
    }

    cbor_encoder_init( &encodedId, Id, IdSize, 0 );

    CLEANUP_ENCODER_ERR( cbor_encoder_create_map( &encodedId, &map, entryCount ) );

    for (uint32_t i = 0; i < AssertionCount; i++)
    {
        CLEANUP_ENCODER_ERR( cbor_encode_text_stringz( &map, Assertions[i].Name ) );
        if (Assertions[i].DataType == ASSERT_TYPE_BUFFER) 
        {
            CLEANUP_ENCODER_ERR( cbor_encode_byte_string( &map, Assertions[i].Data.Buff.Value, Assertions[i].Data.Buff.Size ) );
        }
        else
        {
            CLEANUP_ENCODER_ERR( cbor_encode_int( &map, Assertions[i].Data.Value ) );
        }
    }

    CLEANUP_ENCODER_ERR( cbor_encoder_close_container( &encodedId, &map ) );

    *SizeNeeded = (uint32_t) cbor_encoder_get_extra_bytes_needed( &encodedId );

    err = (*SizeNeeded != 0) ? CborErrorOutOfMemory : CborNoError;

Cleanup:

    return err;
}


CborError _cbor_value_extract_number( const uint8_t **ptr, const uint8_t *end, uint64_t *len );
CborError
cbor_value_ref_byte_string(
    CborValue *Cborstring,
    const uint8_t **Bstr,
    size_t *BstrSize,
    CborValue *Next
)

/*++

Routine Description:

Returns a pointer to the bstr or text str located at Cborstring.
The caller should NOT free the returned buffer.
Advances the Value to the next cbor object.

--*/

{
    CborError err;
    const uint8_t *ptr;
    uint64_t len;

    *Bstr = NULL;
    *BstrSize = 0;

    if (Cborstring == NULL ||
        Bstr == NULL ||
        BstrSize == NULL ||
        Next == NULL)
    {
        return CborErrorInternalError;
    }

    if (!cbor_value_is_byte_string(Cborstring) &&
        !cbor_value_is_text_string(Cborstring)) {
        return CborErrorIllegalType;
    }

    // Utilize the API to validate the value as well as obtaining the size.
    err = cbor_value_get_string_length(Cborstring, BstrSize);

    if (err == CborNoError) {
        ptr = Cborstring->ptr;
        _cbor_value_extract_number(&ptr, Cborstring->parser->end, &len);
        if (len > 0) {
            *Bstr = ptr;
        }
        assert(*BstrSize == len);
        err = cbor_value_advance(Next);
    }

    return err;
}

CborError
pDecodeAssertionKvP(
    CborValue *KvpValue,
    TcpsAssertion *Assertion
)
{
    CborError err;
    size_t keySize = MAX_ASSERTION_KEY_LEN;

    CLEANUP_DECODER_ERR( cbor_value_get_string_length( KvpValue, &keySize ) );
    if (keySize > MAX_ASSERTION_KEY_LEN) {
        err = CborErrorOutOfMemory;
        goto Cleanup;
    }
    CLEANUP_DECODER_ERR( cbor_value_copy_text_string( KvpValue,
                                                      Assertion->Name,
                                                      &keySize, 
                                                      KvpValue ) );

    //
    //  Special case the VERSION. This is the version of the catalog, not a true assertion.
    //  Just store the version on the catalog structure and do not advance the assertion.
    //  N.G: Note that we do not validate the version here as we are just translating structures.
    //

    if (strcmp(TCPS_IDENTITY_MAP_VER, Assertion->Name) == 0) {
        CLEANUP_DECODER_ERR( cbor_value_get_int( KvpValue, &Assertion->Data.Value ) );
        CLEANUP_DECODER_ERR( cbor_value_advance( KvpValue ) );
        Assertion->DataType = ASSERT_TYPE_INT;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR( cbor_value_ref_byte_string( KvpValue,
                                                     &Assertion->Data.Buff.Value,
                                                     (size_t*)&Assertion->Data.Buff.Size,
                                                     KvpValue ) );
    Assertion->DataType = ASSERT_TYPE_BUFFER;

Cleanup:

    return err;
}


CborError
pDecodeTCPSIdentity(
    uint8_t *Id,
    uint32_t IdSize,
    TcpsIdenity *TcpsId
)
{
    CborError       err;
    CborParser      parser;
    CborValue       map;
    CborValue       kvp;
    size_t          len;

    if (TcpsId == NULL) {
        err = CborErrorOutOfMemory;
        goto Cleanup;
    }

    err = cbor_parser_init( Id, IdSize, 0, &parser, &map );

    if (err != CborNoError) {
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_get_map_length( &map, &len ));

    if (len > MAX_ASSERTION_COUNT) {
        err = CborErrorOutOfMemory;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR( cbor_value_enter_container( &map, &kvp ) );

    for (TcpsId->Used = 0; TcpsId->Used < len; TcpsId->Used++) {
        CLEANUP_DECODER_ERR( pDecodeAssertionKvP( &kvp, &TcpsId->AssertionArray[TcpsId->Used]) );
    }

    CLEANUP_DECODER_ERR( cbor_value_leave_container( &map, &kvp ) );

Cleanup:

    return err;
}


RIOT_STATUS
pAllocAndBuildIdentity(
    TcpsIdenity *TcpsId,
    uint8_t **Id,
    uint32_t *IdSize
)
{
    RIOT_STATUS     status = RIOT_FAILURE;
    CborError       err;
    uint8_t         *localId = NULL;
    uint32_t        localIdSize = 0;
    uint32_t        sizeNeeded;

    if (TcpsId == NULL ||
        TcpsId->Used == 0 ||
        Id == NULL ||
        IdSize == NULL )
    {
        status = RIOT_INVALID_PARAMETER;
        goto Cleanup;
    }

    err = pBuildTCPSIdentity( TcpsId->AssertionArray,
        TcpsId->Used,
        NULL,
        0,
        &sizeNeeded );
    if (err != CborErrorOutOfMemory)
    {
        goto Cleanup;
    }

    localId = (uint8_t*)malloc( sizeNeeded );
    localIdSize = sizeNeeded;
    memset( localId, 0x00, localIdSize );
    sizeNeeded = 0;

    err = pBuildTCPSIdentity( TcpsId->AssertionArray,
        TcpsId->Used,
        localId,
        localIdSize,
        &sizeNeeded );
    if (err != CborNoError)
    {
        goto Cleanup;
    }

    //
    //  Success.
    //  We can now free the incoming buffer if it is already allocated.
    //  Only do this now in order to preserve the callers state on failure.
    //

    status = RIOT_SUCCESS;

    if (*Id != NULL)
    {
        FreeTCPSId( *Id );
    }

    *Id = localId;
    localId = NULL;
    *IdSize = localIdSize;

Cleanup:

    FreeTCPSId( localId );
    return status;
}

int
pFindAssertion(
    char* Key,
    TcpsAssertion *Assertions,
    uint32_t AssertionCount
)
{
    for (uint32_t i = 0; i < AssertionCount; i++)
    {
        if (strcmp( Assertions[i].Name, Key ) == 0)
        {
            return i;
        }
    }

    return -1;
}

RIOT_STATUS
pAddAssertionBuffer(
    TcpsIdenity *TcpsId,
    char* Key,
    uint8_t *Value,
    uint32_t ValueSize
)
{
    size_t             index;

    index = pFindAssertion(Key, TcpsId->AssertionArray, TcpsId->Used);
    if (index == -1)
    {
        if (TcpsId->Used == MAX_ASSERTION_COUNT) {
            return RIOT_FAILURE;
        }
        index = TcpsId->Used++;
        memcpy(TcpsId->AssertionArray[index].Name, Key, strlen(Key));
    }
    TcpsId->AssertionArray[index].DataType = ASSERT_TYPE_BUFFER;
    TcpsId->AssertionArray[index].Data.Buff.Value = Value;
    TcpsId->AssertionArray[index].Data.Buff.Size =  ValueSize;

    return RIOT_SUCCESS;
}

RIOT_STATUS
pBuildTCPSAssertionTable(
    RIOT_ECC_PUBLIC *Pub,
    RIOT_ECC_PUBLIC *AuthKeyPub,
    uint8_t *Fwid,
    uint32_t FwidSize,
    TcpsIdenity *TcpsId,
    uint8_t **Id,
    uint32_t *IdSize
)
{
    RIOT_STATUS     status;
    uint8_t         encBuffer[65];
    uint32_t        encBufferLen;
    uint8_t         authBuffer[65];
    uint32_t        authBufferLen;

    if (Pub != NULL)
    {
        RiotCrypt_ExportEccPub(Pub, encBuffer, &encBufferLen);
        status = pAddAssertionBuffer( TcpsId, 
                                      TCPS_IDENTITY_MAP_PUBKEY,
                                      encBuffer,
                                      encBufferLen );
        if (status != RIOT_SUCCESS) {
            goto Cleanup;
        }
    }

    if (AuthKeyPub != NULL)
    {
        RiotCrypt_ExportEccPub(AuthKeyPub, authBuffer, &authBufferLen);
        status = pAddAssertionBuffer( TcpsId,
                                      TCPS_IDENTITY_MAP_AUTH,
                                      authBuffer,
                                      authBufferLen );
        if (status != RIOT_SUCCESS) {
            goto Cleanup;
        }
    }

    if (FwidSize > 0)
    {
        status = pAddAssertionBuffer( TcpsId,
                                      TCPS_IDENTITY_MAP_FWID,
                                      Fwid,
                                      FwidSize );
        if (status != RIOT_SUCCESS) {
            goto Cleanup;
        }
    }

    status =  pAllocAndBuildIdentity( TcpsId,
        Id,
        IdSize );

    if (status != RIOT_SUCCESS) {
        goto Cleanup;
    }

    status = RIOT_SUCCESS;

Cleanup:

    return status;
}


RIOT_STATUS
BuildTCPSAliasIdentity(
    RIOT_ECC_PUBLIC *AuthKeyPub,
    uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t **Id,
    uint32_t *IdSize
)
{
    TcpsIdenity aliasId = { 0 };

    return pBuildTCPSAssertionTable( NULL, 
                                     AuthKeyPub,
                                     Fwid,
                                     FwidSize,
                                     &aliasId,
                                     Id,
                                     IdSize );
}


RIOT_STATUS
BuildTCPSDeviceIdentity(
    RIOT_ECC_PUBLIC *Pub,
    RIOT_ECC_PUBLIC *AuthKeyPub,
    uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t **Id,
    uint32_t *IdSize
)
{
    TcpsIdenity deviceId = { 0 };

    return pBuildTCPSAssertionTable( Pub, 
                                     AuthKeyPub,
                                     Fwid,
                                     FwidSize,
                                     &deviceId,
                                     Id,
                                     IdSize );
}


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
)
{
    CborError       err;
    TcpsIdenity     tcpsId = { 0 };

    //
    //  We expect an existing Id that we will modify.
    //

    if (ExistingId == NULL ||
        ExistingIdSize == 0) {
        return RIOT_INVALID_PARAMETER;
    }

    err = pDecodeTCPSIdentity( ExistingId,
                               ExistingIdSize,
                               &tcpsId );

    if (err != CborNoError) {
        return RIOT_FAILURE;
    }

    return pBuildTCPSAssertionTable( Pub, 
                                     AuthKeyPub,
                                     Fwid,
                                     FwidSize,
                                     &tcpsId,
                                     NewId,
                                     NewIdSize );
}