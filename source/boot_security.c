#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#ifndef __cplusplus
typedef unsigned char bool;
static const bool False = 0;
static const bool True = 1;
#endif
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_snprintf        snprintf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */
#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_RSA_C) ||  \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_FS_IO)
int main(void)
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_RSA_C and/or "
        "MBEDTLS_MD_C and/or "
        "MBEDTLS_SHA256_C and/or MBEDTLS_FS_IO not defined.\n");
    return(0);
}
#else
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include <stdio.h>
#include <string.h>
#endif
#include "boot_security.h"
#include <stdbool.h>
bool boot_authenticate_upgrade_package(const boot_upgrade_package_t* const package)
{
    mbedtls_rsa_context rsa;
    unsigned char hash[32];
    int exit_code = MBEDTLS_EXIT_FAILURE;
    int ret = 1;

    /*
     * Compute the SHA-256 hash of the input file and
     * verify the signature
     */
    uint8_t* imagePtr = package->image;
    uint8_t* signaturePtr = package->metadata.signature;

    mbedtls_printf("\n  . Verifying the SHA-256 signature");

    int mbedtls_md(const mbedtls_md_info_t * MBEDTLS_MD_SHA256, uint8_t * imagePtr, size_t ilen,
        unsigned char hash);

    if ((ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
        MBEDTLS_MD_SHA256, 20, hash, signaturePtr)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_verify returned -0x%0x\n\n", -ret);
        goto exit;
    }
    mbedtls_printf("\n  . OK (the signature is valid)\n\n");
    exit_code = MBEDTLS_EXIT_SUCCESS;
exit:
    mbedtls_rsa_free(&rsa);
    return true;
}
void boot_decrypt_upgrade_package(boot_upgrade_package_t* package)
{
}