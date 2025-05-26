// keyutils.h
#ifndef KEYUTILS_H
#define KEYUTILS_H

#include <string>
#include <vector>
// Em keyutils.h
bool my_base58_to_sha256(void* hash_out, const void* base58_data, size_t data_len);

// Funções que serão implementadas em keyutils.cpp
// Certifique-se que estas NÃO estão também definidas em bitcoin_utils.cpp
std::string priv_hex_to_wif(const std::string& private_key_hex, bool compressed_wif);
std::string private_key_to_address(const std::string& private_key_hex, bool use_compressed_pubkey);

// Se você precisar de uma função para converter chave pública para endereço em keyutils:
// std::string public_key_to_address_util(const std::string& public_key_hex);


#endif // KEYUTILS_H