/*
 * H3XER - Optimized SHA-256 for CUDA
 */

#ifndef H3XER_SHA256_CUH
#define H3XER_SHA256_CUH

#include "h3xer_types.cuh"

namespace h3xer {

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define SHA256_EP1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SHA256_SIG0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

__device__ __forceinline__ uint32_t swap32(uint32_t x) {
    return __byte_perm(x, 0, 0x0123);
}

__device__ __forceinline__ void store_be32(uint8_t* dst, uint32_t val) {
    dst[0] = (val >> 24); dst[1] = (val >> 16); dst[2] = (val >> 8); dst[3] = val;
}

__device__ __forceinline__ uint32_t load_be32(const uint8_t* src) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

struct Sha256State {
    uint32_t h[8];
    uint8_t buf[64];
    uint32_t buflen;
    uint64_t total;
};

__device__ void sha256_compress(uint32_t* state, const uint8_t* block) {
    uint32_t w[64];
    #pragma unroll
    for (int i = 0; i < 16; i++) w[i] = load_be32(block + i * 4);
    #pragma unroll
    for (int i = 16; i < 64; i++)
        w[i] = SHA256_SIG1(w[i-2]) + w[i-7] + SHA256_SIG0(w[i-15]) + w[i-16];
    
    uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint32_t e=state[4], f=state[5], g=state[6], h=state[7];
    
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + SHA256_K[i] + w[i];
        uint32_t t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

__device__ void sha256_init(Sha256State* ctx) {
    ctx->h[0]=0x6a09e667; ctx->h[1]=0xbb67ae85; ctx->h[2]=0x3c6ef372; ctx->h[3]=0xa54ff53a;
    ctx->h[4]=0x510e527f; ctx->h[5]=0x9b05688c; ctx->h[6]=0x1f83d9ab; ctx->h[7]=0x5be0cd19;
    ctx->buflen=0; ctx->total=0;
}

__device__ void sha256_update(Sha256State* ctx, const uint8_t* data, uint32_t len) {
    ctx->total += len;
    if (ctx->buflen > 0) {
        uint32_t need = 64 - ctx->buflen;
        if (len < need) {
            for (uint32_t i = 0; i < len; i++) ctx->buf[ctx->buflen + i] = data[i];
            ctx->buflen += len; return;
        }
        for (uint32_t i = 0; i < need; i++) ctx->buf[ctx->buflen + i] = data[i];
        sha256_compress(ctx->h, ctx->buf);
        data += need; len -= need; ctx->buflen = 0;
    }
    while (len >= 64) { sha256_compress(ctx->h, data); data += 64; len -= 64; }
    for (uint32_t i = 0; i < len; i++) ctx->buf[i] = data[i];
    ctx->buflen = len;
}

__device__ void sha256_final(Sha256State* ctx, uint8_t* digest) {
    uint64_t total_bits = ctx->total * 8;
    ctx->buf[ctx->buflen++] = 0x80;
    if (ctx->buflen > 56) {
        while (ctx->buflen < 64) ctx->buf[ctx->buflen++] = 0;
        sha256_compress(ctx->h, ctx->buf); ctx->buflen = 0;
    }
    while (ctx->buflen < 56) ctx->buf[ctx->buflen++] = 0;
    store_be32(ctx->buf + 56, (uint32_t)(total_bits >> 32));
    store_be32(ctx->buf + 60, (uint32_t)total_bits);
    sha256_compress(ctx->h, ctx->buf);
    for (int i = 0; i < 8; i++) store_be32(digest + i * 4, ctx->h[i]);
}

__device__ void sha256(const uint8_t* data, uint32_t len, uint8_t* digest) {
    Sha256State ctx; sha256_init(&ctx); sha256_update(&ctx, data, len); sha256_final(&ctx, digest);
}

__device__ void hmac_sha256(const uint8_t* key, uint32_t keylen, const uint8_t* data, uint32_t datalen, uint8_t* mac) {
    uint8_t k_ipad[64], k_opad[64], keybuf[32];
    if (keylen > 64) { sha256(key, keylen, keybuf); key = keybuf; keylen = 32; }
    for (uint32_t i = 0; i < 64; i++) {
        k_ipad[i] = (i < keylen) ? (key[i] ^ 0x36) : 0x36;
        k_opad[i] = (i < keylen) ? (key[i] ^ 0x5c) : 0x5c;
    }
    Sha256State ctx;
    sha256_init(&ctx); sha256_update(&ctx, k_ipad, 64); sha256_update(&ctx, data, datalen);
    uint8_t inner[32]; sha256_final(&ctx, inner);
    sha256_init(&ctx); sha256_update(&ctx, k_opad, 64); sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, mac);
}

} // namespace h3xer
#endif
