// keyutils.cpp
#include "keyutils.h"

// Header para Base58 (do seu base58.c via libbase58.c)
// Certifique-se que este header está em "base58/libbase58.h", tem guardas extern "C"
// e declara bool b58check_enc(...), bool b58tobin(...), e o ponteiro b58_sha256_impl.
#include "base58/libbase58.h"

#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <cstring> // Para memcpy, memset

// Headers para Hashes Nativos (SHA256 e RIPEMD160)
extern "C" {
    // De hash/sha256.c ou .cpp - Verifique o nome exato da função em sha256.h
    // Exemplo: void sha256(const uint8_t *data, size_t len, uint8_t *digest);
    #include "hash/sha256.h"

    // De rmd160/rmd160.c - Verifique o nome exato da função em rmd160.h
    // Exemplo: void RMD160Data(const unsigned char* data, unsigned int len, char* digest_out_20_bytes);
    // Ou se o seu rmd160.h usa: void rmd160(const unsigned char *message, unsigned int len, unsigned char *digest);
    #include "rmd160/rmd160.h"
}

// Para ECC nativo
#include "secp256k1/Int.h"
#include "secp256k1/Point.h"
#include "secp256k1/SECP256K1.h"
#define SHA256_DIGEST_LENGTH 32

bool (*b58_sha256_impl)(void*, const void*, size_t) = nullptr; // ponteiro global

// 🟩 FUNÇÃO NO ESCOPO GLOBAL, fora de qualquer outra
bool my_base58_to_sha256(void* hash_out, const void* base58_data, size_t data_len) {
    const char* input = static_cast<const char*>(base58_data);

    uint8_t decoded[64] = {0};
    size_t out_len = sizeof(decoded);

    if (!b58tobin(decoded, &out_len, input, data_len)) {
        return false;
    }

    sha256(decoded, out_len, static_cast<uint8_t*>(hash_out));
    return true;
}





// Função auxiliar para converter string hexadecimal para vetor de bytes
std::vector<unsigned char> hex_string_to_bytes_ku(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.length() % 2 != 0) {
        // std::cerr << "keyutils: Hex string com comprimento ímpar: " << hex << std::endl;
        return bytes;
    }
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char* end = nullptr;
        unsigned long byte_val = strtoul(byteString.c_str(), &end, 16);
        if (end != byteString.c_str() + 2 || byteString.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
            // std::cerr << "keyutils: Caractere hex inválido encontrado: " << byteString << std::endl;
            bytes.clear();
            return bytes;
        }
        bytes.push_back(static_cast<unsigned char>(byte_val));
    }
    return bytes;
}

// Função movida para o escopo global.
// ATENÇÃO: Esta função `my_base58_to_sha256` depende de uma `base58_decode` que não está definida aqui.
// Se `base58_decode` está em bitcoin_utils.cpp, você precisaria incluir bitcoin_utils.hpp
// ou mover/copiar a implementação de base58_decode para cá, ou usar b58tobin daqui.
// A lógica atual é um placeholder.
std::vector<uint8_t> my_base58_to_sha256(const std::string& b58str) {
    std::vector<uint8_t> hash_out(32); // SHA256_DIGEST_LENGTH
    unsigned char decoded_buffer[256]; // Buffer para dados decodificados
    size_t decoded_len = sizeof(decoded_buffer);

    // Para usar b58tobin (de libbase58.h):
    if (b58tobin(decoded_buffer, &decoded_len, b58str.c_str(), b58str.length())) {
        // Se b58tobin retorna o comprimento real dos dados decodificados em decoded_len:
        sha256(decoded_buffer, decoded_len, hash_out.data());
    } else {
        // std::cerr << "my_base58_to_sha256: Falha ao decodificar Base58" << std::endl;
        // Retorna hash vazio ou lida com o erro
        return {};
    }
    return hash_out;
}


std::string priv_hex_to_wif(const std::string& private_key_hex, bool compressed_wif) {
    if (private_key_hex.length() != 64) {
        return "";
    }
    std::vector<unsigned char> priv_key_bytes = hex_string_to_bytes_ku(private_key_hex);
    if (priv_key_bytes.size() != 32) {
        return "";
    }

    std::vector<unsigned char> payload_data = priv_key_bytes;
    if (compressed_wif) {
        payload_data.push_back(0x01);
    }

    char wif_buffer[128];
    size_t wif_buffer_size = sizeof(wif_buffer);
    uint8_t version_byte = 0x80; // Mainnet WIF

    if (!b58_sha256_impl) {
        std::cerr << "ERRO CRÍTICO em keyutils (priv_hex_to_wif): b58_sha256_impl não foi configurado!" << std::endl;
        return "WIF_SHA256_IMPL_ERROR";
    }

    bool success = b58check_enc(wif_buffer, &wif_buffer_size, version_byte, payload_data.data(), payload_data.size());

    if (success && wif_buffer_size > 0) {
        return std::string(wif_buffer, wif_buffer_size - 1);
    }
    return "";
}

std::string private_key_to_address(const std::string& private_key_hex, bool use_compressed_pubkey) {
    if (private_key_hex.length() != 64) {
        return "";
    }
    std::vector<unsigned char> priv_key_bytes_vec = hex_string_to_bytes_ku(private_key_hex);
    if (priv_key_bytes_vec.size() != 32) {
        return "";
    }

    static Secp256K1 secp_k1_instance;
    static bool secp_k1_initialized = false;
    if (!secp_k1_initialized) {
        secp_k1_instance.Init();
        secp_k1_initialized = true;
    }
    
    Int priv_int;
    priv_int.SetBase16(private_key_hex.c_str());
    Point pub_point = secp_k1_instance.ComputePublicKey(&priv_int);

    unsigned char pub_key_bytes_raw[65];
    int pub_key_len = use_compressed_pubkey ? 33 : 65;
    secp_k1_instance.GetPublicKeyRaw(use_compressed_pubkey, pub_point, reinterpret_cast<char*>(pub_key_bytes_raw));
    
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    sha256(pub_key_bytes_raw, pub_key_len, sha256_digest);

    unsigned char pub_key_hash[20]; // RIPEMD160_DIGEST_LENGTH é 20
    // Usando RMD160Data da sua biblioteca nativa rmd160/rmd160.h
    // A assinatura comum é: void RMD160Data(const unsigned char* data, unsigned int len, char* digest_out);
    // Se a sua rmd160.h usa 'unsigned char*' para o digest, remova o reinterpret_cast.
    RMD160Data(sha256_digest, SHA256_DIGEST_LENGTH, reinterpret_cast<char*>(pub_key_hash));
    
    char address_buffer[128];
    size_t address_buffer_size = sizeof(address_buffer);
    uint8_t version = 0x00; // P2PKH Bitcoin Mainnet

    if (!b58_sha256_impl) {
        std::cerr << "ERRO CRÍTICO em keyutils (private_key_to_address): b58_sha256_impl não foi configurado!" << std::endl;
        return "ADDR_SHA256_IMPL_ERROR";
    }

    bool success = b58check_enc(address_buffer, &address_buffer_size, version, pub_key_hash, 20 /*tamanho do pub_key_hash é 20*/);
    
    if (success && address_buffer_size > 0) {
        return std::string(address_buffer, address_buffer_size - 1);
    }
    return "";
    // em keyutils.cpp
// Deve estar em keyutils.cpp


}


// Se você precisar de uma função que converte uma CHAVE PÚBLICA para endereço:
// std::string public_key_to_address_util(const std::string& public_key_hex) {
//    // 1. Converta public_key_hex (string) para std::vector<unsigned char> pub_key_bytes.
//    //    Lembre-se de tratar os prefixos 04, 02, 03.
//    // 2. SHA256(pub_key_bytes) -> sha256_digest
//    // 3. RMD160Data(sha256_digest, ..., pub_key_hash)
//    // 4. Chame b58check_enc com version 0x00 e pub_key_hash
//    std::cerr << "public_key_to_address_util não implementada!" << std::endl;
//    return "PUBKEY_TO_ADDR_PLACEHOLDER";
// }