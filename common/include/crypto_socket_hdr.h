// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "stdint.h"
#include "crypto_codes.h"

#define CRYPTO_MAGIC_REQ 0x43525121 // "CRQ!" (Crypto Request)
#define CRYPTO_MAGIC_RES 0x43525321 // "CRS!" (Crypto Response)
#define CRYPTO_PROTO_VERSION 0x0001

typedef enum
{
    OP_TYPE_HMAC = 1,
    OP_TYPE_ECDSA = 2
} crypto_op_type_t;

typedef enum
{
    STEP_SINGLE = 0, // For one-shot operations
    STEP_INIT = 1,
    STEP_UPDATE = 2,
    STEP_FINISH = 3
} crypto_step_t;

typedef uint32_t crypto_key_id;

struct crypto_msg_header
{
    uint32_t magic; // CRYPTO_MAGIC_REQ or CRYPTO_MAGIC_RES
    uint16_t version;
    uint32_t session_id;
    uint32_t op_type;
    uint32_t op_step;
    uint32_t status;
    uint32_t payload_len;
};

static bool valid_crypto_msg_req(crypto_msg_header *hdr)
{
    return (hdr->magic == CRYPTO_MAGIC_REQ) && (hdr->version == CRYPTO_PROTO_VERSION);
}

static bool valid_crypto_msg_res(crypto_msg_header *hdr)
{
    return (hdr->magic == CRYPTO_MAGIC_RES) && (hdr->version == CRYPTO_PROTO_VERSION);
}

static bool valid_crypto_msg_ok(crypto_msg_header *hdr)
{
    return (crypto_code_t)(hdr->status) == crypto_code_t::OK;
}

static const char *dump_crypto_msg(crypto_msg_header *hdr)
{
    static char buf[256];
    sprintf(buf, "m=0x%x, v=%d, session_id=%d, op_type=%d, op_step=%d, status=%d, len=%d",
            hdr->magic, hdr->version, hdr->session_id, hdr->op_type, hdr->op_step, hdr->status, hdr->payload_len);
    return buf;
}

/* Parameters for HMAC Initialization */
struct hmac_params
{
    crypto_key_id key_id;
    uint32_t hash_alg;
};

/* Parameters for ECDSA Initialization */
struct ecdsa_params
{
    crypto_key_id key_id;
    uint32_t hash_alg; // Hash to be used for the signature
    uint32_t encoding; // e.g., DER vs Raw
};
