#include <stdio.h>
#include "ksgen.h"

// Your password is securely stored in encrypted config or HSM storage
const sized_str PASSWORD = { "STRONG_PASSWORD", 16 };

int main()
{
    char cipher[CIPHER_LEN] = {0};

    char iv[IV_LEN] = {0};
    cipherparams cipher_params = {
        .iv = { iv, IV_LEN }
    };

    char ciphertext[CIPHERTEXT_LEN] = {0};

    char kdf[KDF_LEN] = {0};

    char salt[SALT_LEN] = {0};
    usize dklen = 0;
    u32 n = 0;
    u32 r = 0;
    u32 p = 0;
    kdfparams kdf_params = {
        .dklen = &dklen,
        .n = &n,
        .r = &r,
        .p = &p,
        .salt = { salt, SALT_LEN },
    };

    char mac[MAC_LEN] = {0};

    keystore k = {
        .cipher = { cipher, CIPHER_LEN },
        .cipherparams = cipher_params,
        .ciphertext = { ciphertext, CIPHERTEXT_LEN },
        .kdf = { kdf, KDF_LEN },
        .kdfparams = kdf_params,
        .mac = { mac, MAC_LEN }
    };

    char address_str[ETHEREUM_ADDRESS_LEN] = {0};
    sized_str address = { address_str, ETHEREUM_ADDRESS_LEN };

    char *err = init_keystore(&k, address, PASSWORD, NETWORK_ETHEREUM);
    if (err != NULL) {
        printf("err: %s", err);
        free_cstring(err);
        return 1;
    }

    printf("cipher: %s\n", k.cipher.str);
    printf("iv: %s\n", k.cipherparams.iv.str);
    printf("ciphertext: %s\n", k.ciphertext.str);
    printf("kdf: %s\n", k.kdf.str);
    printf("dklen: %zu\n", *k.kdfparams.dklen);
    printf("n: %d\n", *k.kdfparams.n);
    printf("r: %d\n", *k.kdfparams.r);
    printf("p: %d\n", *k.kdfparams.p);
    printf("salt: %s\n", k.kdfparams.salt.str);
    printf("mac: %s\n", k.mac.str);
    printf("address: %s\n", address.str);

    return 0;
}