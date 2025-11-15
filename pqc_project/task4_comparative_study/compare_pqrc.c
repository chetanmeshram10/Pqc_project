#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main() {
    printf("=== PQC vs Classical Comparative Study ===\n\n");

    // --- List PQC KEMs ---
    size_t kem_count = OQS_KEM_alg_count();
    printf("Available KEMs (%zu):\n", kem_count);
    for (size_t i = 0; i < kem_count; i++) {
        const char *kem = OQS_KEM_alg_identifier(i);
        if (OQS_KEM_alg_is_enabled(kem)) {
            printf(" %s\n", kem);
        }
    }

    printf("\n");

    // --- List PQC SIGs ---
    size_t sig_count = OQS_SIG_alg_count();
    printf("Available SIGs (%zu):\n", sig_count);
    for (size_t i = 0; i < sig_count; i++) {
        const char *sig = OQS_SIG_alg_identifier(i);
        if (OQS_SIG_alg_is_enabled(sig)) {
            printf(" %s\n", sig);
        }
    }

    printf("\n");

    // ========================
    // --- PQC: KEM Kyber512 ---
    // ========================
    if (OQS_KEM_alg_is_enabled("Kyber512")) {
        printf("--- PQC KEM: Kyber512 Demo ---\n");
        OQS_KEM *kem = OQS_KEM_new("Kyber512");

        uint8_t *pk = malloc(kem->length_public_key);
        uint8_t *sk = malloc(kem->length_secret_key);
        uint8_t *ct = malloc(kem->length_ciphertext);
        uint8_t *ss1 = malloc(kem->length_shared_secret);
        uint8_t *ss2 = malloc(kem->length_shared_secret);

        clock_t t0 = clock();
        OQS_KEM_keypair(kem, pk, sk);
        clock_t t1 = clock();
        OQS_KEM_encaps(kem, ct, ss1, pk);
        clock_t t2 = clock();
        OQS_KEM_decaps(kem, ss2, ct, sk);
        clock_t t3 = clock();

        printf("KeyGen time: %.4f ms\n", (t1-t0)*1000.0/CLOCKS_PER_SEC);
        printf("Encaps time: %.4f ms\n", (t2-t1)*1000.0/CLOCKS_PER_SEC);
        printf("Decaps time: %.4f ms\n", (t3-t2)*1000.0/CLOCKS_PER_SEC);
        printf("Public key length: %zu bytes\n", kem->length_public_key);
        printf("Secret key length: %zu bytes\n", kem->length_secret_key);
        printf("Ciphertext length: %zu bytes\n", kem->length_ciphertext);
        printf("Shared secrets match? %s\n", memcmp(ss1, ss2, kem->length_shared_secret) == 0 ? "YES" : "NO");

        free(pk); free(sk); free(ct); free(ss1); free(ss2);
        OQS_KEM_free(kem);
    } else {
        printf("Kyber512 KEM not enabled\n");
    }

    printf("\n");

    // ===========================
    // --- PQC: SIG Dilithium2 ---
    // ===========================
    if (OQS_SIG_alg_is_enabled("Dilithium2")) {
        printf("--- PQC SIG: Dilithium2 Demo ---\n");
        OQS_SIG *sig = OQS_SIG_new("Dilithium2");
        uint8_t *pk = malloc(sig->length_public_key);
        uint8_t *sk = malloc(sig->length_secret_key);

        clock_t t0 = clock();
        OQS_SIG_keypair(sig, pk, sk);
        clock_t t1 = clock();

        uint8_t message[] = "Post-Quantum Cryptography is the future";
        size_t mlen = sizeof(message);
        uint8_t *sigbuf = malloc(sig->length_signature);
        size_t siglen;

        clock_t t2 = clock();
        OQS_SIG_sign(sig, sigbuf, &siglen, message, mlen, sk);
        clock_t t3 = clock();

        int verify_ok = OQS_SIG_verify(sig, message, mlen, sigbuf, siglen, pk);

        printf("KeyGen time: %.4f ms\n", (t1-t0)*1000.0/CLOCKS_PER_SEC);
        printf("Sign time: %.4f ms\n", (t3-t2)*1000.0/CLOCKS_PER_SEC);
        printf("Public key length: %zu bytes\n", sig->length_public_key);
        printf("Secret key length: %zu bytes\n", sig->length_secret_key);
        printf("Signature length: %zu bytes\n", sig->length_signature);
        printf("Signature verification: %s\n", verify_ok == OQS_SUCCESS ? "SUCCESS" : "FAILURE");

        free(pk); free(sk); free(sigbuf);
        OQS_SIG_free(sig);
    } else {
        printf("Dilithium2 SIG not enabled in liboqs\n");
    }

    printf("\n");

    // ===========================
    // --- Classical: RSA 2048 ---
    // ===========================
    printf("--- Classical SIG: RSA-2048 Demo ---\n");
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    clock_t t0 = clock();
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    clock_t t1 = clock();

    uint8_t message[] = "Post-Quantum Cryptography is the future";
    uint8_t sigbuf[256];
    unsigned int siglen;

    clock_t t2 = clock();
    RSA_sign(NID_sha256, message, sizeof(message), sigbuf, &siglen, rsa);
    clock_t t3 = clock();

    int verify_ok = RSA_verify(NID_sha256, message, sizeof(message), sigbuf, siglen, rsa);

    printf("KeyGen time: %.4f ms\n", (t1-t0)*1000.0/CLOCKS_PER_SEC);
    printf("Sign time: %.4f ms\n", (t3-t2)*1000.0/CLOCKS_PER_SEC);
    printf("Public key approx size: ~%d bytes\n", i2d_RSAPublicKey(rsa, NULL));
    printf("Private key approx size: ~%d bytes\n", i2d_RSAPrivateKey(rsa, NULL));
    printf("Signature length: %u bytes\n", siglen);
    printf("Signature verification: %s\n", verify_ok ? "SUCCESS" : "FAILURE");

    RSA_free(rsa);
    BN_free(e);

    printf("\n");

    // ===========================
    // --- Classical: ECDSA P-256 ---
    // ===========================
    printf("--- Classical SIG: ECDSA P-256 Demo ---\n");
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    clock_t t4 = clock();
    EC_KEY_generate_key(ec);
    clock_t t5 = clock();

    uint8_t ecdsa_sig[72]; // max signature size for P-256
    unsigned int ecdsa_siglen;

    clock_t t6 = clock();
    ECDSA_sign(0, message, sizeof(message), ecdsa_sig, &ecdsa_siglen, ec);
    clock_t t7 = clock();

    int ecdsa_ok = ECDSA_verify(0, message, sizeof(message), ecdsa_sig, ecdsa_siglen, ec);

    printf("KeyGen time: %.4f ms\n", (t5-t4)*1000.0/CLOCKS_PER_SEC);
    printf("Sign time: %.4f ms\n", (t7-t6)*1000.0/CLOCKS_PER_SEC);
    printf("Signature length: %u bytes\n", ecdsa_siglen);
    printf("Signature verification: %s\n", ecdsa_ok ? "SUCCESS" : "FAILURE");

    EC_KEY_free(ec);

    return 0;
}

