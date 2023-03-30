#include <sstream>
#include <iomanip>

#include "crypto_adaptor.h"
#include "handshake.h"
#include "dh.h"
#include "osrng.h"

#define LOGGING 1

// Generates n random bytes.
void Utils::generate_rand(const int n, byte* bytes){
    for (int i = 0; i < n; i++) {
        bytes[i] = rand() % 256;
    }
}
// Converts CryptoPP::Integer to byte array
void Utils::integerToCharArray(const CryptoPP::Integer& integer, byte* charArray, size_t bufferSize){
    size_t encodedSize = integer.MinEncodedSize();
    if (encodedSize > bufferSize) {
        throw std::runtime_error("Buffer size too small");
    }
    integer.Encode(charArray, encodedSize);
}

void Utils::rsa_encrypt(CryptoPP::RSA::PublicKey pk, byte* plaintext, size_t p_size, byte* ciphertext, size_t& c_size){
    std::string cipher;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(pk);
    CryptoPP::StringSource ss(std::string((char *)plaintext, p_size), true,
        new CryptoPP::PK_EncryptorFilter(rng, encryptor,
            new CryptoPP::StringSink(cipher)));

    c_size = cipher.size();
    std::copy(cipher.begin(), cipher.end(), ciphertext);
}

void Utils::rsa_decrypt(CryptoPP::RSA::PrivateKey sk, byte* ciphertext, size_t c_size, byte* plaintext, size_t& p_size){
    CryptoPP::AutoSeededRandomPool rng;

    // Decrypt the ciphertext using your private key
    std::string decrypted;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(sk);
    CryptoPP::StringSource ss2(std::string((char *)ciphertext, c_size), true,
        new CryptoPP::PK_DecryptorFilter(rng, decryptor,
            new CryptoPP::StringSink(decrypted)));

    p_size = decrypted.size();
    std::copy(decrypted.begin(), decrypted.end(), plaintext);
}

// Handshake constructor Used by server
Handshake::Handshake(SSL* ssl): doLogging(LOGGING), protocol_version(0x01), ssl(ssl){
}

// Handshake constructor Used by client
Handshake::Handshake(SSL* ssl, uint16_t cipher_suite):  doLogging(LOGGING),
                                                        protocol_version(0x01),
                                                        cipher_suite(cipher_suite),
                                                        ssl(ssl){
    // Init Here
}

// Log a String, if logging is enabled
void Handshake::log(std::string str){
    if(doLogging){
        std::cout << str << std::endl;
    }
}

template<class T>
void Handshake::log_hex(T obj){
    if(doLogging){
        std::cout << std::hex << obj << std::endl;
    }
}

// Log a char array of size n in Hex format
void Handshake::log_char_hex(char* str, int n){
    if(doLogging){
        for (int i=0; i<n; i++) {
            std::cout << std::hex << static_cast<byte>(str[i]);
        }
        std::cout << std::endl;
    }
}

// IN:This menthod takes msg_type (e.g. SSL::HS_CLIENT_HELLO) and handshake body.
// OUT: SSL::Record object ready to be sent.
SSL::Record Handshake::pack_data(const uint8_t msg_type, const Handshake_Structs::handshake_body &body){
    SSL::Record record;  
    Handshake_Structs::Handshake_Msg hs;

    record.hdr.type = SSL::REC_HANDSHAKE;
    record.hdr.version = SSL::VER_99;
    record.hdr.length = sizeof(hs);

    switch(msg_type){
        case SSL::HS_CLIENT_HELLO:
            hs.msg_type = SSL::HS_CLIENT_HELLO;
            hs.body.client_hello = body.client_hello;
            hs.length = sizeof(body.client_hello);
            break;
        case SSL::HS_SERVER_HELLO:
            hs.msg_type = SSL::HS_SERVER_HELLO;
            hs.body.server_hello = body.server_hello;
            hs.length = sizeof(body.server_hello);
            break;
        case SSL::HS_SERVER_KEY_EXCHANGE:
            hs.msg_type = SSL::HS_SERVER_KEY_EXCHANGE;
            hs.body.key_exchange.rsa = body.key_exchange.rsa;
            hs.length = sizeof(body.key_exchange);
            break;
        case SSL::HS_SERVER_HELLO_DONE:
            hs.msg_type = SSL::HS_SERVER_HELLO_DONE;
            break;
        case SSL::HS_CLIENT_KEY_EXCHANGE:
            hs.msg_type = SSL::HS_CLIENT_KEY_EXCHANGE;
            hs.body.key_exchange.rsa = body.key_exchange.rsa;
            hs.length = sizeof(body.key_exchange.rsa);
            break;
        case SSL::HS_FINISHED:
            hs.msg_type = SSL::HS_FINISHED;
            break;
        default:
            throw "[Handshake::pack_data] Exception: Invalid Message type: " + std::to_string(msg_type);
            break;
    }
    
    char *data = new char[record.hdr.length];
    memcpy(data, &hs, record.hdr.length);
    record.data = data;

    return record;
}

// IN: DH parameters p, q, and g
// OUT: Public Key (pk) and Private Key (sk) pair
// Note:: This function also intitalize the CryptoPP::DH object in Handshake
void Handshake::generate_DH_pair(CryptoPP::Integer& p, CryptoPP::Integer& q, CryptoPP::Integer& g, CryptoPP::Integer& pk, CryptoPP::Integer& sk){
        CryptoPP::AutoSeededRandomPool prng;
        generate_pqg(p, q, g);
        this->dh.AccessGroupParameters().Initialize(p, q, g);
        CryptoPP::SecByteBlock t1(dh.PrivateKeyLength()), t2(dh.PublicKeyLength());
        dh.GenerateKeyPair(prng, t1, t2);
        pk = CryptoPP::Integer(t1, t1.size());
        sk = CryptoPP::Integer(t2, t2.size());
}

// Encodes an object using ASN.1 BER encoding
// Serialize the object to byte array
template<class T>
void Handshake::BEREncode(T &obj, byte* out, uint16_t &n){
    std::string str;
    CryptoPP::StringSink ss(str);
    obj.BEREncode(ss);
    std::copy(str.begin(), str.end(), out);
    n = str.size();
}

// Decodes a byte array with ASN.1 BER encoding
// Deserialize to byte array to desired object
template<class T>
void Handshake::BERDecode(T &obj, byte* out, uint16_t &n){
    std::string str = std::string((char *)out, n);
    CryptoPP::StringSource source(str, true);
    obj.BERDecode(source);
}

// IN : Private key and other Public key
// OUT: pre master key
void Handshake::generate_DE_pre_master_key(CryptoPP::Integer& key1, CryptoPP::Integer& key2){
    byte *preMaster = new byte[this->dh.AgreedValueLength()];
    byte *private_ = new byte[key1.MinEncodedSize()];
    Utils::integerToCharArray(key1, private_, key1.MinEncodedSize());
    byte *public_ = new byte[key2.MinEncodedSize()];
    Utils::integerToCharArray(key2, public_, key2.MinEncodedSize());
    this->dh.Agree(preMaster, private_, public_);

    memcpy(this->pre_master_secret_DH, preMaster, this->dh.AgreedValueLength());
    this->pre_master_secret_DH_size = this->dh.AgreedValueLength();
}

void Handshake::send_hello_client(){
    Handshake_Structs::handshake_body send_hb;
    SSL::Record send_record;

    send_hb.client_hello.cipher_suite = cipher_suite;
    send_hb.client_hello.client_version = this->protocol_version;
    Utils::generate_rand(32, send_hb.client_hello.random);
    memcpy(this->client_random, send_hb.client_hello.random, 32);

    send_record = this->pack_data(SSL::HS_CLIENT_HELLO, send_hb);
    if(this->ssl->send(send_record) == 0){
        log("[CLIENT] Sent: SSL::HS_CLIENT_HELLO");
    } else{
        throw("[Handshake::send_hello_client] Error: ssl->send(), errno: " + std::to_string(errno));
    }
}

void Handshake::wait_send_hello_server(){

    SSL::Record *recv_record_hello_client = new SSL::Record;
    Handshake_Structs::handshake_body send_hb;
    int16_t chosen_cipher_suite;
    Handshake_Structs::Handshake_Msg *recv_hs;
    SSL::Record send_record;

    // Receiving Client Hello
    this->ssl->recv(recv_record_hello_client);
    recv_hs = (Handshake_Structs::Handshake_Msg*)recv_record_hello_client->data;

    if(recv_hs->msg_type != SSL::HS_CLIENT_HELLO){
        throw("[Handshake::wait_send_hello_server] Invalid Message type: " + std::to_string(recv_hs->msg_type) + ", expected: SSL::HS_CLIENT_HELLO");
    }
    log("[SERVER] Received: SSL::HS_CLIENT_HELLO");

    // Setting Cipher Suite
    chosen_cipher_suite = recv_hs->body.client_hello.cipher_suite;
    this->cipher_suite = chosen_cipher_suite;

    // Sending Server Hello
    send_hb.server_hello.cipher_suite = chosen_cipher_suite;
    send_hb.server_hello.client_version = this->protocol_version;
    Utils::generate_rand(28, send_hb.server_hello.random);
    memcpy(this->server_random, send_hb.server_hello.random, 32);
    memcpy(this->client_random, recv_hs->body.client_hello.random, 32);

    send_record = this->pack_data(SSL::HS_SERVER_HELLO, send_hb);
    if(this->ssl->send(send_record) == 0){
        log("[SERVER] Sent: SSL::HS_SERVER_HELLO");
    } else{
        throw("[Handshake::wait_send_hello_server] Error: ssl->send(), errno: " + std::to_string(errno));
    }
}

void Handshake::send_server_key_exchange(){
    Handshake_Structs::handshake_body send_hb;
    SSL::Record send_record;

    send_hb.key_exchange.rsa.client_version = this->protocol_version;

    if(this->cipher_suite == SSL::KE_RSA){
        generate_rsa_keys(this->private_key_rsa, this->public_key_rsa);
        BEREncode(this->public_key_rsa, send_hb.key_exchange.rsa.server_public_key, send_hb.key_exchange.rsa.server_public_key_size);
        //log(publicKeyString);
    } else if(this->cipher_suite == SSL::KE_DHE){
        //Generating Public and Private Key
        this->generate_DH_pair(this->dh_p, this->dh_g, this->dh_q, this->dh_server_public_key, this->dh_server_private_key);
        BEREncode(this->dh_p, send_hb.key_exchange.dhe.dh_p, send_hb.key_exchange.dhe.dh_p_size);
        BEREncode(this->dh_g, send_hb.key_exchange.dhe.dh_g, send_hb.key_exchange.dhe.dh_g_size);
        BEREncode(this->dh_server_public_key, send_hb.key_exchange.dhe.dh_Y, send_hb.key_exchange.dhe.dh_Y_size);

        // log("p:");
        // log_hex(this->dh_p);
        // log("g:");
        // log_hex(this->dh_g);
        // log("Server Public Key:");
        // log_hex(this->dh_server_public_key);
        // log("Server Private Key:");
        // log_hex(this->dh_server_private_key);

    } else{
        throw "[Handshake::send_server_key_exchange] Invalid Cipher Suite: " + std::to_string(this->cipher_suite);
    }

    send_record = this->pack_data(SSL::HS_SERVER_KEY_EXCHANGE, send_hb);
    if(this->ssl->send(send_record) == 0){
        log("[SERVER] Sent: SSL::HS_SERVER_KEY_EXCHANGE");
    } else{
        throw("[Handshake::send_server_key_exchange] Error: ssl->send(), errno: " + std::to_string(errno));
    }
}

void Handshake::send_server_hello_done(){
    Handshake_Structs::handshake_body send_hb; // Empty
    SSL::Record send_record = this->pack_data(SSL::HS_SERVER_HELLO_DONE, send_hb);
    if(this->ssl->send(send_record) == 0){
        log("[SERVER] Sent: SSL::HS_SERVER_HELLO_DONE");
    } else{
        throw("[Handshake::send_server_hello_done] Error: ssl->send(), errno: " + std::to_string(errno));
    }
}

void Handshake::wait_send_client_key_exchange(){
    Handshake_Structs::handshake_body send_hb;
    SSL::Record* recv_record_server_hello = new SSL::Record;
    SSL::Record* recv_record_server_key_exchange = new SSL::Record;
    SSL::Record* recv_record_hello_done = new SSL::Record;
    Handshake_Structs::Handshake_Msg *recv_server_hello;
    Handshake_Structs::Handshake_Msg *recv_server_key_exchange;
    Handshake_Structs::Handshake_Msg *recv_hello_done;
    std::string receivedEncodedPublicKey_rsa;
    CryptoPP::RSA::PublicKey receivedPublicKey_rsa;
    SSL::Record send_record;

    // Receiving Server Hello
    this->ssl->recv(recv_record_server_hello);
    recv_server_hello = (Handshake_Structs::Handshake_Msg*)recv_record_server_hello->data;
    if(recv_server_hello->msg_type != SSL::HS_SERVER_HELLO){
        throw("Invalid Message type: " + std::to_string(recv_server_hello->msg_type) + ", expected: SSL::HS_SERVER_HELLO");
    }
    log("[CLIENT] Received: SSL::HS_SERVER_HELLO");
    //Saving Server's random
    memcpy(this->server_random, recv_server_hello->body.server_hello.random, 32);

    // Receiving Server Key exchange
    this->ssl->recv(recv_record_server_key_exchange);
    recv_server_key_exchange = (Handshake_Structs::Handshake_Msg*)recv_record_server_key_exchange->data;
    if(recv_server_key_exchange->msg_type != SSL::HS_SERVER_KEY_EXCHANGE){
        throw("Invalid Message type: " + std::to_string(recv_server_key_exchange->msg_type) + ", expected: SSL::HS_SERVER_KEY_EXCHANGE");
    }
    log("[CLIENT] Received: SSL::HS_SERVER_KEY_EXCHANGE");

    //Receving Server Hello Done
    this->ssl->recv(recv_record_hello_done);
    recv_hello_done = (Handshake_Structs::Handshake_Msg*)recv_record_hello_done->data;
    if(recv_hello_done->msg_type != SSL::HS_SERVER_HELLO_DONE){
        throw("Invalid Message type: " + std::to_string(recv_hello_done->msg_type) + ", expected: SSL::HS_SERVER_HELLO_DONE");
    }
    log("[CLIENT] Received: SSL::HS_SERVER_HELLO_DONE");

    if(recv_server_hello->body.server_hello.cipher_suite == this->cipher_suite){
        if(this->cipher_suite == SSL::KE_RSA){
            BERDecode(receivedPublicKey_rsa, recv_server_key_exchange->body.key_exchange.rsa.server_public_key, recv_server_key_exchange->body.key_exchange.rsa.server_public_key_size);

            send_hb.key_exchange.rsa.client_version = this->protocol_version;

            {   
                // Generating random 48-bits pre master
                Utils::generate_rand(48, this->pre_master_secret_rsa);
                byte* cipher = new byte[500];
                size_t c_size;
                Utils::rsa_encrypt(receivedPublicKey_rsa, this->pre_master_secret_rsa, 48, cipher, c_size);

                memcpy(send_hb.key_exchange.rsa.pre_master_secret, cipher, c_size);
                send_hb.key_exchange.rsa.pre_master_secret_size = c_size;
            }

        }  else if(this->cipher_suite == SSL::KE_DHE){   
            BERDecode(this->dh_p, recv_server_key_exchange->body.key_exchange.dhe.dh_p, recv_server_key_exchange->body.key_exchange.dhe.dh_p_size);
            BERDecode(this->dh_g, recv_server_key_exchange->body.key_exchange.dhe.dh_g, recv_server_key_exchange->body.key_exchange.dhe.dh_g_size);
            BERDecode(this->dh_server_public_key, recv_server_key_exchange->body.key_exchange.dhe.dh_Y, recv_server_key_exchange->body.key_exchange.dhe.dh_Y_size);            

            this->generate_DH_pair(this->dh_p, this->dh_g, this->dh_q, this->dh_client_public_key, this->dh_client_private_key);

            BEREncode(this->dh_client_public_key, send_hb.key_exchange.dhe.dh_Y, send_hb.key_exchange.dhe.dh_Y_size);

            this->generate_DE_pre_master_key(this->dh_server_public_key, this->dh_client_private_key);

            // log("p:");
            // log_hex(this->dh_p);
            // log("g:");
            // log_hex(this->dh_g);
            // log("Client Public Key:");
            // log_hex(this->dh_client_public_key);
            // log("CLient Private Key:");
            // log_hex(this->dh_server_private_key);
            // log("Server Public Key:");
            // log_hex(this->dh_server_public_key);

        } else{
            throw "[Handshake::wait_send_client_key_exchange] Invalid Cipher Suite: " + std::to_string(this->cipher_suite);
        }
    } else{
        throw "[Handshake::wait_send_client_key_exchange] Server-Client Cipher Suite Mismatch";
    }

    send_record = this->pack_data(SSL::HS_CLIENT_KEY_EXCHANGE, send_hb);
    if(this->ssl->send(send_record) == 0){
        log("[CLIENT] Sent: SSL::HS_CLIENT_KEY_EXCHANGE");
    } else{
        throw("[Handshake::wait_send_client_key_exchange] Error: ssl->send(), errno: " + std::to_string(errno));
    }

    //log(receivedEncodedPublicKey_rsa);

}

void Handshake::send_wait_finished_client(){
    Handshake_Structs::handshake_body send_hb; // Empty
    SSL::Record* recv_record_server_finished = new SSL::Record;
    Handshake_Structs::Handshake_Msg *recv_server_finished;

    SSL::Record send_record = this->pack_data(SSL::HS_FINISHED, send_hb);
    if(this->ssl->send(send_record) == 0){
        log("[CLIENT] Sent: SSL::HS_FINISHED");
    } else{
        throw("[Handshake::send_finished_client] Error: ssl->send(), errno: " + std::to_string(errno));
    }

    // Receiving Server Finished
    this->ssl->recv(recv_record_server_finished);
    recv_server_finished = (Handshake_Structs::Handshake_Msg*)recv_record_server_finished->data;
    if(recv_server_finished->msg_type != SSL::HS_FINISHED){
        throw("Invalid Message type: " + std::to_string(recv_server_finished->msg_type) + ", expected: SSL::HS_FINISHED");
    }
    log("[CLIENT] Received: SSL::HS_FINISHED");

    generate_master_key();
}

void Handshake::wait_send_finished_server(){
    Handshake_Structs::handshake_body send_hb;
    SSL::Record* recv_record_client_key_exchange = new SSL::Record;
    SSL::Record* recv_record_client_finished = new SSL::Record;
    Handshake_Structs::Handshake_Msg *recv_client_key_exchange;
    Handshake_Structs::Handshake_Msg *recv_client_finished;

    // Receiving Client key exchange
    this->ssl->recv(recv_record_client_key_exchange);
    recv_client_key_exchange = (Handshake_Structs::Handshake_Msg*)recv_record_client_key_exchange->data;
    if(recv_client_key_exchange->msg_type != SSL::HS_CLIENT_KEY_EXCHANGE){
        throw("Invalid Message type: " + std::to_string(recv_client_key_exchange->msg_type) + ", expected: SSL::HS_CLIENT_KEY_EXCHANGE");
    }
    log("[SERVER] Received: SSL::HS_CLIENT_KEY_EXCHANGE");

    // Receiving Client Finished
    this->ssl->recv(recv_record_client_finished);
    recv_client_finished = (Handshake_Structs::Handshake_Msg*)recv_record_client_finished->data;
    if(recv_client_finished->msg_type != SSL::HS_FINISHED){
        throw("Invalid Message type: " + std::to_string(recv_client_finished->msg_type) + ", expected: SSL::HS_FINISHED");
    }
    log("[SERVER] Received: SSL::HS_FINISHED");

    //Receiving Client Finished
    SSL::Record send_record = this->pack_data(SSL::HS_FINISHED, send_hb);
    if(this->ssl->send(send_record) == 0){
        log("[SERVER] Sent: SSL::HS_FINISHED");
    } else{
        throw("[wait_send_finished_server()] Error: ssl->send(), errno: " + std::to_string(errno));
    }

    if(this->cipher_suite == SSL::KE_RSA){
        byte* plain = new byte[500];
        size_t p_size;
        Utils::rsa_decrypt(this->private_key_rsa, recv_client_key_exchange->body.key_exchange.rsa.pre_master_secret,
                                        recv_client_key_exchange->body.key_exchange.rsa.pre_master_secret_size,
                                        plain, p_size);
        if(p_size != 48){
            throw "[Handshake::wait_send_finished_server()] pre master does not decrypt to 48 bits.";
        }
        memcpy(this->pre_master_secret_rsa, plain, p_size);
        //log("Plain:"); log_char_hex((char*)plain, p_size);
    }  else if(this->cipher_suite == SSL::KE_DHE){
        BERDecode(this->dh_client_public_key, recv_client_key_exchange->body.key_exchange.dhe.dh_Y, recv_client_key_exchange->body.key_exchange.dhe.dh_Y_size);
        // log("Client Public Key:");
        // log_hex(this->dh_client_public_key);
        this->generate_DE_pre_master_key(this->dh_client_public_key, this->dh_server_private_key);
        // this->pre_master_secret_DH[5] = 'z'; // Fail Test
    } else{
        throw "[wait_send_finished_server()] Invalid Cipher Suite: " + std::to_string(this->cipher_suite);
    }

    generate_master_key();
    log("Key Exchange Complete :)");
}


void Handshake::generate_master_key(){
    CryptoPP::SecByteBlock randoms(2 * CryptoPP::SHA256::DIGESTSIZE);
    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    if(this->cipher_suite == SSL::KE_RSA){
        hmac.SetKey(this->pre_master_secret_rsa, sizeof(this->pre_master_secret_rsa));
    } else if(this->cipher_suite == SSL::KE_DHE){
        hmac.SetKey(this->pre_master_secret_DH, this->pre_master_secret_DH_size);
    }
    
    memcpy(randoms, this->client_random, CryptoPP::SHA256::DIGESTSIZE);
    memcpy(randoms + CryptoPP::SHA256::DIGESTSIZE, this->server_random, CryptoPP::SHA256::DIGESTSIZE);
    hmac.Update((byte *)"master secret", 13);
    hmac.Update(randoms, randoms.size());
    hmac.Final(this->master_secret);
    
    {
        // log("Client Random: ");
        // log_char_hex((char *)(this->client_random), 32);
        // log("Server Random: ");
        // log_char_hex((char *)(this->server_random), 32);
        // log("Pre Master: ");
        // log_char_hex((char *)(this->pre_master_secret_rsa), 48);
        // log("Shared master Key: ");
        // log_char_hex((char *)(this->master_secret), 32);
    }
}

void Handshake::set_shared_key(SSL* ssl){
    ssl->set_shared_key(this->master_secret, 32);
}