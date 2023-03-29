#pragma once

#include <cstdlib>

namespace Handshake_Structs{
    
    struct RSAParams{
        uint16_t client_version;   
        byte pre_master_secret[500];
        uint16_t pre_master_secret_size;
        byte server_public_key[500]; 
        uint16_t server_public_key_size;
    };

    struct DHParams{
        byte dh_p[200];
        uint16_t dh_p_size;
        byte dh_g[200];
        uint16_t dh_g_size;
        byte dh_Y[200];
        uint16_t dh_Y_size;
    };

    union KeyExchangeParams{
        RSAParams rsa;
        DHParams dhe;
    };

    struct ClientHello{
        uint16_t client_version;
        byte random[32];
        //byte session_id[32];
        uint16_t cipher_suite;
   };

    struct ServerHello{
        uint16_t client_version;
        byte random[32];
        //byte session_id[32];
        uint16_t cipher_suite;
    };

    union handshake_body{
        ClientHello client_hello;
        ServerHello server_hello;
        KeyExchangeParams key_exchange;
    };

    struct Handshake_Msg{
        // char start = 'M';
        uint8_t msg_type;
        uint32_t length;
        handshake_body body;
        // char end = 'P';
    };
}