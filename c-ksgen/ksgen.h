#include <stdio.h>
#include <dlfcn.h>

#define u32 u_int32_t
#define usize size_t

#define CIPHER_LEN 11 + 1
#define IV_LEN 32 + 1
#define CIPHERTEXT_LEN 64 + 1
#define KDF_LEN 6 + 1
#define SALT_LEN 32 + 1
#define MAC_LEN 64 + 1

#define APTOS_ADDRESS_LEN 64 + 1
#define BITCOIN_ADDRESS_LEN 34 + 1
#define ETHEREUM_ADDRESS_LEN 40 + 1
#define LITECOIN_ADDRESS_LEN BITCOIN_ADDRESS_LEN
#define SOLANA_ADDRESS_LEN 44 + 1
#define SUI_ADDRESS_LEN 64 + 1
#define TRON_ADDRESS_LEN 34 + 1

typedef struct sized_str
{
    char *str;
    usize len;
} sized_str;

typedef struct cipherparams
{
    sized_str iv;
} cipherparams;

typedef struct kdfparams
{
    usize *dklen;
    u32 *n;
    u32 *r;
    u32 *p;
    sized_str salt;
} kdfparams;

typedef struct keystore
{
    sized_str cipher;
    cipherparams cipherparams;
    sized_str ciphertext;
    sized_str kdf;
    kdfparams kdfparams;
    sized_str mac;
} keystore;

typedef enum network {
    NETWORK_APTOS,
    NETWROK_BITCOIN,
    NETWORK_ETHEREUM,
    NETWORK_LITECOIN,
    NETWORK_SOLANA,
    NETWORK_SUI,
    NETWORK_TRON,
} network;

extern char *init_keystore(keystore *k, sized_str address, sized_str password, network network);
extern void free_cstring(char *ptr);