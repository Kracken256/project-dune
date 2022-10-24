#ifndef __DUNE_CRYPTO__
#define __DUNE_CRYPTO__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#define ED25519_KEY_LENGTH 32

#include <iostream>
#include <string>
#include <fstream>
#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace dune::crypto
{
    static void Compute_SHA_256(std::string input, std::string *buffer)
    {
        uint32_t digest_length = SHA256_DIGEST_LENGTH;
        const EVP_MD *algorithm = EVP_sha256();;
        unsigned char digest[digest_length];
        EVP_MD_CTX *context = EVP_MD_CTX_new();
        EVP_DigestInit_ex(context, algorithm, nullptr);
        EVP_DigestUpdate(context, input.c_str(), input.length());
        EVP_DigestFinal_ex(context, digest, &digest_length);
        buffer->assign(std::string((const char *)digest, digest_length));
        EVP_MD_CTX_destroy(context);
        EVP_MD_free((EVP_MD*)algorithm);
    }

}

#endif