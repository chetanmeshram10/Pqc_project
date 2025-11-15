/*
 * kem_exchange.c
 *
 * Task 2: Key Encapsulation (KEM) demo with timings
 *
 * Behavior:
 *  - Tries several common liboqs KEM identifiers to pick a Kyber-like KEM
 *    (so the program works across different liboqs builds).
 *  - Alice: keypair
 *  - Bob: encapsulate using Alice's public key
 *  - Alice: decapsulate and compare shared secrets
 *  - Measure times for keygen, encaps, decaps
 *
 * Compile:
 *   gcc -O2 -o kem_exchange kem_exchange.c -I/usr/local/include -L/usr/local/lib -loqs -lcrypto
 *
 * Run:
 *   LD_LIBRARY_PATH=/usr/local/lib ./kem_exchange
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

static inline double timespec_to_ms(const struct timespec *t) {
    return (double)t->tv_sec * 1000.0 + (double)t->tv_nsec / 1e6;
}

/* compute elapsed ms between start and end (monotonic) */
static inline double elapsed_ms(const struct timespec *start, const struct timespec *end) {
    double s = timespec_to_ms(start);
    double e = timespec_to_ms(end);
    return e - s;
}

/* print buffer as hex (prefix label) */
void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    /* Candidate algorithm identifiers (common variations across liboqs versions) */
    const char *candidates[] = {
        "Kyber512",
        "Kyber768",
        "Kyber1024",
        "mlkem_512",   /* newer mlkem alias names */
        "mlkem_768",
        "mlkem_1024",
        "CRYSTALS-Kyber-512", /* some older/alternate identifiers */
        NULL
    };

    const char *alg = NULL;
    if (argc >= 2) {
        alg = argv[1];
        printf("Using algorithm from argv: %s\n", alg);
    } else {
        /* try candidates until one works */
        for (size_t i = 0; candidates[i] != NULL; ++i) {
            if (OQS_KEM_new(candidates[i]) != NULL) {
                alg = candidates[i];
                break;
            }
        }
        if (alg == NULL) {
            /* fallback: if nothing matched by object-creation test above (which created/destroyed the object),
             * try to take the first available from OQS list (best-effort).
             */
            size_t kem_count = OQS_KEM_alg_count();
            if (kem_count > 0) {
                alg = OQS_KEM_alg_identifier(0);
                printf("No Kyber candidate matched; falling back to first available: %s\n", alg);
            }
        } else {
            printf("Selected candidate algorithm: %s\n", alg);
        }
    }

    if (alg == NULL) {
        fprintf(stderr, "No KEM algorithm found in liboqs build.\n");
        return 2;
    }

    /* Create the KEM object */
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (kem == NULL) {
        fprintf(stderr, "OQS_KEM_new failed for algorithm '%s'\n", alg);
        return 3;
    }

    printf("Using KEM: %s\n", kem->method_name);
    printf("  public key len : %zu\n", kem->length_public_key);
    printf("  secret key len : %zu\n", kem->length_secret_key);
    printf("  ciphertext len : %zu\n", kem->length_ciphertext);
    printf("  shared secret len: %zu\n\n", kem->length_shared_secret);

    /* Allocate buffers */
    uint8_t *alice_pk = malloc(kem->length_public_key);
    uint8_t *alice_sk = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *ss_bob = malloc(kem->length_shared_secret);
    uint8_t *ss_alice = malloc(kem->length_shared_secret);

    if (!alice_pk || !alice_sk || !ciphertext || !ss_bob || !ss_alice) {
        fprintf(stderr, "Allocation failure\n");
        OQS_KEM_free(kem);
        return 4;
    }

    struct timespec t0, t1;

    /* Key generation (Alice) */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (OQS_KEM_keypair(kem, alice_pk, alice_sk) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_KEM_keypair failed\n");
        goto cleanup_err;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double keygen_ms = elapsed_ms(&t0, &t1);

    /* Encapsulation (Bob uses Alice's public key) */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (OQS_KEM_encaps(kem, ciphertext, ss_bob, alice_pk) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_KEM_encaps failed\n");
        goto cleanup_err;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double encaps_ms = elapsed_ms(&t0, &t1);

    /* Decapsulation (Alice uses her secret key + Bob's ciphertext) */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (OQS_KEM_decaps(kem, ss_alice, ciphertext, alice_sk) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_KEM_decaps failed\n");
        goto cleanup_err;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double decaps_ms = elapsed_ms(&t0, &t1);

    /* Print secrets in hex and confirm equality */
    print_hex("Bob's shared secret", ss_bob, kem->length_shared_secret);
    print_hex("Alice's shared secret", ss_alice, kem->length_shared_secret);

    if (memcmp(ss_bob, ss_alice, kem->length_shared_secret) == 0) {
        printf("Success: shared secrets match!\n");
    } else {
        printf("FAIL: shared secrets differ!\n");
    }

    printf("\nTimings (ms):\n");
    printf("  Key generation : %.3f ms\n", keygen_ms);
    printf("  Encapsulation  : %.3f ms\n", encaps_ms);
    printf("  Decapsulation  : %.3f ms\n", decaps_ms);

    /* successful exit */
    free(alice_pk);
    free(alice_sk);
    free(ciphertext);
    free(ss_bob);
    free(ss_alice);
    OQS_KEM_free(kem);
    return 0;

cleanup_err:
    free(alice_pk); free(alice_sk); free(ciphertext); free(ss_bob); free(ss_alice);
    OQS_KEM_free(kem);
    return 1;
}
