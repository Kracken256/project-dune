#!/bin/bash

# build ransomware
g++ main.cpp -o main -lcrypto  -std=c++17 -Wall

# Build decryptor
g++ decryptor.cpp -o decryptor -lcrypto -std=c++17 -Wall
