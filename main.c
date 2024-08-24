#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

void dump(unsigned char* data, int length) {
    for (int i = 0; i < length; i++) {
        unsigned char e = data[i];
        printf("%#04x ", e);
    }

    printf("%s", "\n");
}

static int ExerciseHkdf(char* algorithm) {
    printf("Attempting HKDF with '%s'\n", algorithm);

    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);

    if (kdf == NULL) {
        ERR_print_errors_fp(stdout);
        return 1;
    }

    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);

    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        return 1;
    }

    unsigned char key[]  = { 0xA0, 0x01, 0x02, 0x03, 0x04 };
    unsigned char salt[] = { 0xB0, 0x01, 0x02, 0x03, 0x04 };
    unsigned char info[] = { 0xC0, 0x01, 0x02, 0x03, 0x04 };

    OSSL_PARAM params[] =
    {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, 5),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, algorithm, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, 5),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, 5),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "EXTRACT_AND_EXPAND", 0),
        OSSL_PARAM_construct_end(),
    };

    unsigned char dk[16] = { 0 };

    if (EVP_KDF_derive(ctx, dk, 16, params) <= 0) {
        ERR_print_errors_fp(stdout);
        return 1;
    }

    printf("Result: ");
    dump(dk, 16);
    printf("\n");
    return 0;
}

int main() {
    ExerciseHkdf("SHA256");
    ExerciseHkdf("BLAH384");
    ExerciseHkdf("SHA3-256");
    return 0;
}