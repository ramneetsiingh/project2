#pragma once

#include <iostream>
#include <cstdlib>
#include <string>

#include "ssl.h"
#include "integer.h"
#include "handshake_structs.h"
#include "dh.h"

namespace Utils{
    void generate_rand(const int, byte*);
    void integerToCharArray(const CryptoPP::Integer&, byte*, size_t);
    void rsa_encrypt(CryptoPP::RSA::PublicKey, byte*, size_t, byte*, size_t&);
    void rsa_decrypt(CryptoPP::RSA::PrivateKey, byte*, size_t, byte*, size_t&);
}


class Handshake{

private:    

    bool doLogging;
    const uint16_t protocol_version;
    uint16_t cipher_suite;
    SSL* ssl;

    byte master_secret[32]; 
    byte client_random[32];
    byte server_random[32];

    // For RSA KE
    CryptoPP::RSA::PrivateKey private_key_rsa;
    CryptoPP::RSA::PublicKey public_key_rsa;
    byte pre_master_secret_rsa[48];

    // For DHE KE
    CryptoPP::DH dh;
    CryptoPP::Integer dh_p;
    CryptoPP::Integer dh_g;
    CryptoPP::Integer dh_q;
    CryptoPP::Integer dh_client_public_key;
    CryptoPP::Integer dh_client_private_key;
    CryptoPP::Integer dh_server_public_key;
    CryptoPP::Integer dh_server_private_key;
    byte pre_master_secret_DH[200];
    size_t pre_master_secret_DH_size;

    void log(std::string);
    void log_char_hex(char*, int);
    template<class T>
    void log_hex(T);

    SSL::Record pack_data(const uint8_t, const Handshake_Structs::handshake_body&);

    void generate_DH_pair(CryptoPP::Integer&, CryptoPP::Integer&, CryptoPP::Integer&, CryptoPP::Integer&, CryptoPP::Integer&);

    void generate_master_key();

    void generate_DE_pre_master_key(CryptoPP::Integer&, CryptoPP::Integer&);

    template<class T>
    void BERDecode(T&, byte*, uint16_t&);

    template<class T>
    void BEREncode(T&, byte*, uint16_t&);
public:

    Handshake(SSL*);
    Handshake(SSL*, uint16_t cipher_suite);

    // Function in the order of handshake

    // CLIENT
    void send_hello_client();

    // SERVER
    void wait_send_hello_server();

    // SERVER
    void send_server_key_exchange();

    // SERVER
    void send_server_hello_done();

    // CLIENT
    void wait_send_client_key_exchange();

    // CLIENT
    void send_wait_finished_client();

    // SERVER
    void wait_send_finished_server();
    
    void set_shared_key(SSL*);
};