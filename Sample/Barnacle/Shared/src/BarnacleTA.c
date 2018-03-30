/*
 * Barnacle.c
 *
 *  Created on: Oct 18, 2017
 *      Author: stefanth
 */

#include "main.h"
#include "stm32l4xx_hal.h"
#include <cyrep/RiotTarget.h>
#include <cyrep/RiotStatus.h>
#include <cyrep/RiotSha256.h>
#include <cyrep/RiotEcc.h>
#include <cyrep/RiotCrypt.h>
#include <cyrep/RiotDerEnc.h>
#include <cyrep/RiotX509Bldr.h>
#include <tcps/TcpsId.h>
#include <AgentInfo.h>
#include <BarnacleTA.h>
#include <StmUtil.h>

extern RNG_HandleTypeDef hrng;

#ifndef AGENTPROJECT
#define AGENTNAME         ""
#define AGENTVERSIONMAJOR (0)
#define AGENTVERSIONMINOR (0)
#define AGENTTIMESTAMP    (0)
#define AGENTVERSION      (uint32_t)((AGENTVERSIONMAJOR << 16) | AGENTVERSIONMAJOR)
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
__attribute__((section(".AGENTHDR"))) const BARNACLE_AGENT_HDR AgentHdrTA = {{{{BARNACLEMAGIC, BARNACLEVERSION, sizeof(BARNACLE_AGENT_HDR)}, {AGENTNAME, AGENTVERSION, 0, AGENTTIMESTAMP, {0}}}, {{0}, {0}}}};
#pragma GCC diagnostic pop

//#define BARNACLE_DATA_START (0x20000000)
//PBARNACLE_IDENTITY_PRIVATE pCompoundId = (const PBARNACLE_IDENTITY_PRIVATE)BARNACLE_DATA_START;
//PBARNACLE_CERTSTORE pCertStore = (const PBARNACLE_CERTSTORE)(BARNACLE_DATA_START + sizeof(BARNACLE_IDENTITY_PRIVATE));
__attribute__((section(".PURW.Private"))) BARNACLE_IDENTITY_PRIVATE CompoundIdTA;
__attribute__((section(".PURW.Public"))) BARNACLE_CERTSTORE CertStoreTA;

void BarnacleTAPrintCertStore(FILE* out)
{

    for(uint32_t n = 0; n < NUMELEM(CertStoreTA.info.certTable); n++)
    {
        if(CertStoreTA.info.certTable[n].size > 0)
        {
            fprintf(out, "%s", (char*)&CertStoreTA.certBag[CertStoreTA.info.certTable[n].start]);
        }
    }
}

bool BarnacleTADerivePolicyIdentity(uint8_t* agentPolicy, uint32_t agentPolicySize)
{
    bool result = true;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    RIOT_ECC_PUBLIC policyPubKey;
    RIOT_ECC_PRIVATE policyPrivKey;
    RIOT_X509_TBS_DATA x509TBSData = { { 0 },
                                       AgentHdrTA.s.sign.agent.name, NULL, NULL,
                                       "170101000000Z", "370101000000Z",
                                       "AgentPolicy", NULL, NULL };
    DERBuilderContext derCtx = { 0 };
    uint8_t derBuffer[DER_MAX_TBS] = { 0 };
    uint32_t length = 0;
    RIOT_ECC_SIGNATURE  tbsSig = { 0 };
    uint8_t tcps[BARNACLE_TCPS_ID_BUF_LENGTH];
    uint32_t tcpsLen = 0;

    // Derive the policy compound key
    if(!(result = (RiotCrypt_Hash2(digest,
                                   sizeof(digest),
                                   agentPolicy,
                                   agentPolicySize,
                                   &CompoundIdTA.info.privKey,
                                   sizeof(CompoundIdTA.info.privKey)))) == RIOT_SUCCESS)
    {
        logError("RiotCrypt2_Hash() failed.\r\n");
        goto Cleanup;
    }
    if(!(result = (RiotCrypt_DeriveEccKey(&policyPubKey,
                                          &policyPrivKey,
                                          digest, sizeof(digest),
                                          (const uint8_t *)RIOT_LABEL_IDENTITY,
                                          lblSize(RIOT_LABEL_IDENTITY)) == RIOT_SUCCESS)))
    {
        logError("RiotCrypt_DeriveEccKey() failed.\r\n");
        goto Cleanup;
    }

    // Issue the policy compound cert
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    if(!(result = (RiotCrypt_Kdf(digest,
                                 sizeof(digest),
                                 (uint8_t*)&policyPubKey, sizeof(policyPubKey),
                                 NULL, 0,
                                 (const uint8_t *)RIOT_LABEL_SERIAL,
                                 lblSize(RIOT_LABEL_SERIAL),
                                 sizeof(digest)) == RIOT_SUCCESS)))
    {
        logError("RiotCrypt_Kdf() failed.\r\n");
        goto Cleanup;
    }
    digest[0] &= 0x7F; // Ensure that the serial number is positive
    digest[0] |= 0x01; // Ensure that the serial is not null
    memcpy(x509TBSData.SerialNum, digest, sizeof(x509TBSData.SerialNum));

    // Calculate agent policy digest
    if(!(result = (RiotCrypt_Hash(digest,
                                  sizeof(digest),
                                  agentPolicy,
                                  agentPolicySize))) == RIOT_SUCCESS)
    {
        logError("RiotCrypt2_Hash() failed.\r\n");
        goto Cleanup;
    }

    if(!(result = (BuildTCPSAliasIdentity(&CertStoreTA.info.devicePubKey,
                                          (uint8_t*)digest,
                                          sizeof(digest),
                                          tcps,
                                          sizeof(tcps),
                                          &tcpsLen) == RIOT_SUCCESS)))
    {
        logError("BuildTCPSAliasIdentity() failed.\r\n");
        goto Cleanup;
    }

    result = (X509GetAliasCertTBS(&derCtx,
                                  &x509TBSData,
                                  (RIOT_ECC_PUBLIC*)&policyPubKey,
                                  (RIOT_ECC_PUBLIC*)&CompoundIdTA.info.pubKey,
                                  (uint8_t*)digest,
                                  sizeof(digest),
                                  tcps,
                                  tcpsLen,
                                  0) == 0);
    if(!result)
    {
        logError("X509GetAliasCertTBS() failed.\r\n");
        goto Cleanup;
    }

    // Sign the agent compound key Certificate's TBS region
    if(!(result = (RiotCrypt_Sign(&tbsSig,
                                  derCtx.Buffer,
                                  derCtx.Position,
                                  &CompoundIdTA.info.privKey) == RIOT_SUCCESS)))
    {
        logError("RiotCrypt_Sign() failed.\r\n");
        goto Cleanup;
    }

    // Generate compound key Certificate
    if(!(result = (X509MakeAliasCert(&derCtx, &tbsSig) == 0)))
    {
        logError("X509MakeAliasCert() failed.\r\n");
        goto Cleanup;
    }

    // Copy compound key Certificate into the cert store
    CertStoreTA.info.certTable[BARNACLE_CERTSTORE_POLICY].start = CertStoreTA.info.cursor;
    length = sizeof(CertStoreTA.certBag) - CertStoreTA.info.cursor;
    if(!(result = (DERtoPEM(&derCtx, R_CERT_TYPE, (char*)&CertStoreTA.certBag[CertStoreTA.info.cursor], &length) == 0)))
    {
        logError("DERtoPEM() failed.\r\n");
        goto Cleanup;
    }
    CertStoreTA.info.certTable[BARNACLE_CERTSTORE_POLICY].size = (uint16_t)length;
    CertStoreTA.info.cursor += length;
    CertStoreTA.certBag[CertStoreTA.info.cursor] = '\0';

    // Overwrite the agent compound key
    memcpy(&CompoundIdTA.info.privKey, &policyPrivKey, sizeof(CompoundIdTA.info.privKey));
    memcpy(&CompoundIdTA.info.pubKey, &policyPubKey, sizeof(CompoundIdTA.info.pubKey));

Cleanup:
    return result;
}
