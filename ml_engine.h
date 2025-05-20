#pragma once
#include <string>
#include <vector>

// Estrutura para a IA comunicar uma sugestão de busca
struct AISearchSuggestion {
    std::string base_key_hex;       
    float priority_score;         
    std::string reasoning;          
    bool use_suggestion;          
};

// Inicializa a IA
void ml_init(const std::string &model_path = "models/model.pt", 
             const std::string &initial_hits_semicolon_csv_path = ""); 

// Score da chave/dados
float ml_score_key_data(const std::string &priv_hex,
                        const std::string &wif,
                        const std::string &addr1_p2pkh_comp,    
                        const std::string &addr2_p2pkh_uncomp,  
                        const std::string &seed_phrase,
                        const std::string &base64_data);

// Aprende com hit positivo em tempo real
void ml_learn_from_hit(const std::string &priv_hex,
                       const std::string &wif,
                       const std::string &addr1_p2pkh_comp,    
                       const std::string &addr2_p2pkh_uncomp,  
                       const std::string &seed_phrase,
                       const std::string &base64_data);

// Atualiza periodicamente a estratégia da IA (processa buffer de hits positivos)
void ml_periodic_update();

// Salva features de HITS POSITIVOS acumulados para re-treino
void ml_save_state(const std::string &state_path = "models/positive_hits_features.csv"); // Nome do arquivo alterado

// A IA sugere um próximo ponto de partida para a busca (lógica conceitual)
AISearchSuggestion ml_get_next_search_suggestion();

// << NOVA FUNÇÃO PÚBLICA >>
// Função para extrair features, que pode ser chamada pelo keyhunt.cpp para negativos
std::vector<float> ml_extract_features_for_data(
                        const std::string &priv_hex,
                        const std::string &wif,
                        const std::string &addr1_p2pkh_comp,
                        const std::string &addr2_p2pkh_uncomp,
                        const std::string &seed_phrase,
                        const std::string &base64_data);