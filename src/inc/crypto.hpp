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
#include "config.hpp"

namespace dune::crypto
{
    /* Generates a NID_secp256k1 key. */
    static EVP_PKEY *generate_key()
    {
        /* Allocate memory for the EVP_PKEY structure. */
        EVP_PKEY *pkey = EVP_PKEY_new();
        if (!pkey)
        {
            std::cerr << "Unable to create EVP_PKEY structure." << std::endl;
            return NULL;
        }
        EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        /* Generate the NID_secp256k1 key and assign it to pkey. */
        EC_KEY_generate_key(eckey);
        if (!EVP_PKEY_assign_EC_KEY(pkey, eckey))
        {
            std::cerr << "Unable to generate NID_secp256k1 key." << std::endl;
            EVP_PKEY_free(pkey);
            return NULL;
        }

        /* The key has been generated, return it. */
        return pkey;
    }

    /* Generates a self-signed x509 certificate. */
    static X509 *generate_x509(EVP_PKEY *pkey)
    {
        /* Allocate memory for the X509 structure. */
        X509 *x509 = X509_new();
        if (!x509)
        {
            std::cerr << "Unable to create X509 structure." << std::endl;
            return NULL;
        }

        /* Set the serial number. */
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

        /* This certificate is valid from now until exactly one year from now. */
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

        /* Set the public key for our certificate. */
        X509_set_pubkey(x509, pkey);

        /* We want to copy the subject name to the issuer name. */
        X509_NAME *name = X509_get_subject_name(x509);

        /* Set the country code and common name. */
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"CA", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"DecentMC", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);

        /* Now set the issuer name. */
        X509_set_issuer_name(x509, name);

        /* Actually sign the certificate with our key. */
        if (!X509_sign(x509, pkey, EVP_sha1()))
        {
            std::cerr << "Error signing certificate." << std::endl;
            X509_free(x509);
            return NULL;
        }

        return x509;
    }

    static bool write_to_disk(EVP_PKEY *pkey, X509 *x509)
    {
        /* Open the PEM file for writing the key to disk. */
        FILE *pkey_file = fopen("key.pem", "wb");
        if (!pkey_file)
        {
            std::cerr << "Unable to open \"key.pem\" for writing." << std::endl;
            return false;
        }

        /* Write the key to disk. */
        bool ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(pkey_file);

        if (!ret)
        {
            std::cerr << "Unable to write private key to disk." << std::endl;
            return false;
        }

        /* Open the PEM file for writing the certificate to disk. */
        FILE *x509_file = fopen("cert.pem", "wb");
        if (!x509_file)
        {
            std::cerr << "Unable to open \"cert.pem\" for writing." << std::endl;
            return false;
        }

        /* Write the certificate to disk. */
        ret = PEM_write_X509(x509_file, x509);
        fclose(x509_file);

        if (!ret)
        {
            std::cerr << "Unable to write certificate to disk." << std::endl;
            return false;
        }

        return true;
    }
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
    bool check_bits(unsigned char byte, uint8_t bits)
    {
        if (bits > 0 && !(~byte & (0x80 >> 0)))
        {
            return false;
        }
        if (bits > 1 && !(~byte & (0x80 >> 1)))
        {
            return false;
        }
        if (bits > 2 && !(~byte & (0x80 >> 2)))
        {
            return false;
        }
        if (bits > 3 && !(~byte & (0x80 >> 3)))
        {
            return false;
        }
        if (bits > 4 && !(~byte & (0x80 >> 4)))
        {
            return false;
        }
        if (bits > 5 && !(~byte & (0x80 >> 5)))
        {
            return false;
        }
        if (bits > 6 && !(~byte & (0x80 >> 6)))
        {
            return false;
        }
        if (bits > 7 && !(~byte & (0x80 >> 7)))
        {
            return false;
        }
        return true;
    }
    static bool Verify_SHA_POW(const std::string input, uint64_t nonce, uint8_t difficulty)
    {
        if (difficulty > DUNE_CRYPTO_MAX_DIFFICULTY_POW) {
            return false;
        }
        std::string digest;
        Compute_SHA_256(input + std::to_string(nonce), &digest);
        unsigned char buf[32];
        memcpy(buf, digest.data(), 32);
        if (difficulty < 8)
        {
            if (!check_bits(buf[0], difficulty))
            {
                return false;
            }
            return true;
        }
        unsigned char cmp_test[32];
        memset(cmp_test, 0, 32);
        uint8_t first_bytes = difficulty / 8;
        if (memcmp(buf, cmp_test, first_bytes) != 0)
        {
            return false;
        }
        uint8_t last_bits_count = difficulty % 8;
        if (last_bits_count == 0)
        {
            return true;
        }
        if (!check_bits(buf[first_bytes], last_bits_count))
        {
            return false;
        }
        return true;
    }
    static bool Compute_SHA_POW(const std::string input, uint8_t difficulty, uint64_t *best_nonce)
    { // Be mindful this could take a while
        if (difficulty > DUNE_CRYPTO_MAX_DIFFICULTY_POW)
        {
            return false;
        }
        unsigned char cmp_test[32];
        memset(cmp_test, 0, 32);
        uint64_t nonce = 0;
        while (1)
        {
            std::string digest;
            Compute_SHA_256(input + std::to_string(nonce), &digest);
            unsigned char buf[32];
            memcpy(buf, digest.data(), 32);
            if (difficulty < 8)
            {
                if (!check_bits(buf[0], difficulty))
                {
                    nonce++;
                    continue;
                }
                else
                {
                    *best_nonce = nonce;
                    return true;
                }
            }
            uint8_t first_bytes = difficulty / 8;
            if (memcmp(buf, cmp_test, first_bytes) != 0)
            {
                nonce++;
                continue;
            }
            uint8_t last_bits_count = difficulty % 8;
            if (last_bits_count == 0)
            {
                *best_nonce = nonce;
                return true;
            }
            if (!check_bits(buf[first_bytes], last_bits_count))
            {
                nonce++;
                continue;
            }
            *best_nonce = nonce;
            return true;
        }
        return false;
    }

}

#endif