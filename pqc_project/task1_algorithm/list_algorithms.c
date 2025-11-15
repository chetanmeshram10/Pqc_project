// list_algorithms.c
// Task 1: List all available KEM and SIG algorithms in your liboqs build

#include <stdio.h>
#include <oqs/oqs.h>

int main(void) {
    printf("=== Listing all available KEM algorithms ===\n\n");

    size_t kem_count = OQS_KEM_alg_count();
    for (size_t i = 0; i < kem_count; i++) {
        const char *alg_name = OQS_KEM_alg_identifier(i);
        OQS_KEM *kem = OQS_KEM_new(alg_name);
        if (kem == NULL) {
            printf("[%zu] %s (not enabled in this build)\n", i, alg_name);
            continue;
        }
        printf("[%zu] %s\n", i, alg_name);
        printf("   Public key length : %zu bytes\n", kem->length_public_key);
        printf("   Secret key length : %zu bytes\n", kem->length_secret_key);
        printf("   Ciphertext length : %zu bytes\n", kem->length_ciphertext);
        printf("   Shared secret len : %zu bytes\n\n", kem->length_shared_secret);
        OQS_KEM_free(kem);
    }

    printf("=== Listing all available Signature (SIG) algorithms ===\n\n");

    size_t sig_count = OQS_SIG_alg_count();
    for (size_t i = 0; i < sig_count; i++) {
        const char *alg_name = OQS_SIG_alg_identifier(i);
        OQS_SIG *sig = OQS_SIG_new(alg_name);
        if (sig == NULL) {
            printf("[%zu] %s (not enabled in this build)\n", i, alg_name);
            continue;
        }
        printf("[%zu] %s\n", i, alg_name);
        printf("   Public key length : %zu bytes\n", sig->length_public_key);
        printf("   Secret key length : %zu bytes\n", sig->length_secret_key);
        printf("   Signature length  : %zu bytes\n\n", sig->length_signature);
        OQS_SIG_free(sig);
    }

    return 0;
}

