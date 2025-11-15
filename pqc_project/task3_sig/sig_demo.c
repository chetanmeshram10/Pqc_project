/*
 * sig_demo.c
 *
 * Task 3: Digital Signatures (SIG)
 *
 * Demonstrates:
 *   - PQC signature (Dilithium2 or fallback)
 *   - RSA-2048 and ECDSA P-256 using OpenSSL
 *   - Timing of keygen/sign/verify
 *   - Prints key and signature sizes
 *
 * Compile:
 *   gcc -O2 -o sig_demo sig_demo.c -I/usr/local/include -L/usr/local/lib -loqs -lcrypto
 *
 * Run:
 *   LD_LIBRARY_PATH=/usr/local/lib ./sig_demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>

static inline double timespec_to_ms(const struct timespec *t) {
    return (double)t->tv_sec * 1000.0 + (double)t->tv_nsec / 1e6;
}
static inline double elapsed_ms(const struct timespec *start, const struct timespec *end) {
    return timespec_to_ms(end) - timespec_to_ms(start);
}

void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

/* --- PQC SIGNATURE DEMO --- */
void pqc_signature_demo(void) {
    printf("\n=== PQC Signature Demo ===\n");

    const char *msg = "Post-Quantum Cryptography is the future";
    const size_t msglen = strlen(msg);

    const char *candidates[] = {
        "Dilithium2", "Dilithium3", "Dilithium5",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", NULL
    };
    const char *alg = NULL;
    OQS_SIG *sig = NULL;

    for (int i = 0; candidates[i] != NULL; i++) {
        sig = OQS_SIG_new(candidates[i]);
        if (sig != NULL) {
            alg = candidates[i];
            break;
        }
    }

    if (!sig) {
        fprintf(stderr, "No PQC signature algorithm found.\n");
        return;
    }

    printf("Using PQC signature algorithm: %s\n", sig->method_name);
    printf("  Public key length: %zu\n", sig->length_public_key);
    printf("  Secret key length: %zu\n", sig->length_secret_key);
    printf("  Signature length:  %zu\n", sig->length_signature);

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    struct timespec t0, t1;
    double keygen_ms, sign_ms, verify_ms;

    /* Keygen */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_SIG_keypair failed\n");
        goto cleanup;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    keygen_ms = elapsed_ms(&t0, &t1);

    /* Sign */
    size_t siglen;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (OQS_SIG_sign(sig, signature, &siglen, (const uint8_t*)msg, msglen, sk) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_SIG_sign failed\n");
        goto cleanup;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sign_ms = elapsed_ms(&t0, &t1);

    /* Verify */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_STATUS rc = OQS_SIG_verify(sig, (const uint8_t*)msg, msglen, signature, siglen, pk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    verify_ms = elapsed_ms(&t0, &t1);

    printf("\nMessage: \"%s\"\n", msg);
    print_hex("Signature", signature, siglen);

    if (rc == OQS_SUCCESS)
        printf("Verification: SUCCESS ✅\n");
    else
        printf("Verification: FAILURE ❌\n");

    printf("\nTimings (ms):\n");
    printf("  Key generation : %.3f ms\n", keygen_ms);
    printf("  Signing        : %.3f ms\n", sign_ms);
    printf("  Verification   : %.3f ms\n", verify_ms);

cleanup:
    OQS_SIG_free(sig);
    free(pk); free(sk); free(signature);
}

/* --- RSA-2048 & ECDSA P-256 for comparison --- */
void classical_comparison(void) {
    printf("\n=== Classical RSA-2048 and ECDSA-P256 Comparison ===\n");

    const char *msg = "Post-Quantum Cryptography is the future";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)msg, strlen(msg), hash);

    struct timespec t0, t1;
    double keygen_ms, sign_ms, verify_ms;

    /* RSA-2048 */
    printf("\n-- RSA-2048 --\n");
    clock_gettime(CLOCK_MONOTONIC, &t0);
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    keygen_ms = elapsed_ms(&t0, &t1);

    unsigned char sig[256];
    unsigned int siglen;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    RSA_sign(NID_sha256, hash, sizeof(hash), sig, &siglen, rsa);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sign_ms = elapsed_ms(&t0, &t1);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    int ok = RSA_verify(NID_sha256, hash, sizeof(hash), sig, siglen, rsa);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    verify_ms = elapsed_ms(&t0, &t1);

    printf("Public key size: ~%d bytes (approx)\n", i2d_RSAPublicKey(rsa, NULL));
    printf("Signature size : %u bytes\n", siglen);
    printf("Verification: %s\n", ok ? "SUCCESS ✅" : "FAILURE ❌");
    printf("Timings (ms): keygen=%.3f, sign=%.3f, verify=%.3f\n", keygen_ms, sign_ms, verify_ms);
    RSA_free(rsa); BN_free(e);

    /* ECDSA P-256 */
    printf("\n-- ECDSA P-256 --\n");
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    EC_KEY_generate_key(ec);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    keygen_ms = elapsed_ms(&t0, &t1);

    unsigned int ecdsa_siglen;
    unsigned char ecdsa_sig[256];
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ECDSA_sign(0, hash, sizeof(hash), ecdsa_sig, &ecdsa_siglen, ec);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sign_ms = elapsed_ms(&t0, &t1);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    ok = ECDSA_verify(0, hash, sizeof(hash), ecdsa_sig, ecdsa_siglen, ec);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    verify_ms = elapsed_ms(&t0, &t1);

    printf("Public key size: ~65 bytes\n");
    printf("Signature size : %u bytes\n", ecdsa_siglen);
    printf("Verification: %s\n", ok ? "SUCCESS ✅" : "FAILURE ❌");
    printf("Timings (ms): keygen=%.3f, sign=%.3f, verify=%.3f\n", keygen_ms, sign_ms, verify_ms);

    EC_KEY_free(ec);
}

int main(void) {
    pqc_signature_demo();
    classical_comparison();
    return 0;
}
