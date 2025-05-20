#include "ml_engine.h"
#include <torch/torch.h>
#include <torch/script.h>
#include <iostream>
#include <mutex>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iterator> 
#include <set>      
#include <iomanip> 
#include <cstdlib> 
#include <ctime>   

// --- Variáveis Globais Estáticas ---
static torch::jit::script::Module g_model;
static std::mutex g_mutex;
static std::vector<std::vector<float>> g_positive_hits_buffer; // Buffer para features de HITS POSITIVOS
static std::string g_current_search_focus = "Exploração inicial baseada em modelo padrão.";
static long long g_total_positive_hits_processed = 0;
static bool g_model_loaded_successfully = false;
const int INPUT_DIM_EXPECTED = 8; 

// --- Helpers para extração de features (count_words_in_string, etc. como antes) ---
static int count_words_in_string(const std::string& str) {
    if (str.empty()) return 0;
    std::istringstream iss(str);
    return static_cast<int>(std::distance(std::istream_iterator<std::string>(iss), std::istream_iterator<std::string>()));
}

static float average_word_len_in_string(const std::string& str) {
    if (str.empty()) return 0.0f;
    std::istringstream iss(str);
    std::vector<std::string> words(std::istream_iterator<std::string>{iss}, std::istream_iterator<std::string>());
    if (words.empty()) return 0.0f;
    float total_len = 0;
    for (const auto& word : words) {
        total_len += static_cast<float>(word.length());
    }
    return total_len / static_cast<float>(words.size());
}

static float unique_chars_ratio_in_string(const std::string& str) {
    if (str.empty()) return 0.0f;
    std::set<char> unique_chars(str.begin(), str.end());
    return static_cast<float>(unique_chars.size()) / static_cast<float>(str.length());
}

static float get_bitcoin_addr_type_proxy(const std::string& addr) {
    if (addr.empty()) return 0.0f; 
    if (addr.rfind("1", 0) == 0) return 1.0f;
    if (addr.rfind("3", 0) == 0) return 2.0f;
    if (addr.rfind("bc1", 0) == 0) { 
        if (addr.length() < 45) return 3.1f; 
        return 3.2f; 
    }
    return 5.0f; 
}

// --- Extração de Features Principal (Agora pública via ml_engine.h) ---
// Removido 'static' e nomeado conforme ml_engine.h
std::vector<float> ml_extract_features_for_data(
    const std::string &priv_hex,
    const std::string &wif,
    const std::string &addr1_p2pkh_comp,    
    const std::string &addr2_p2pkh_uncomp,  
    const std::string &seed_phrase,
    const std::string &base64_data) {

    std::vector<float> features;
    features.push_back(static_cast<float>(priv_hex.length()));      
    features.push_back(!wif.empty() ? 1.0f : 0.0f);                 
    features.push_back(get_bitcoin_addr_type_proxy(addr1_p2pkh_comp)); 
    features.push_back(!addr2_p2pkh_uncomp.empty() ? 1.0f : 0.0f);  
    features.push_back(static_cast<float>(count_words_in_string(seed_phrase))); 
    features.push_back(average_word_len_in_string(seed_phrase));    
    features.push_back(static_cast<float>(base64_data.length()));  
    features.push_back(unique_chars_ratio_in_string(base64_data));  
    
    if (features.size() != INPUT_DIM_EXPECTED) {
        features.resize(INPUT_DIM_EXPECTED, 0.0f);
    }
    return features;
}

// --- Carregamento de Hits Iniciais ---
static void load_initial_hits_from_semicolon_csv(const std::string &initial_hits_path) {
    if (initial_hits_path.empty()) { /* ... (como antes) ... */ return; }
    std::ifstream file(initial_hits_path);
    if (!file.is_open()) { /* ... (como antes) ... */ return; }
    std::cout << "[ML] Carregando hits iniciais de: " << initial_hits_path << std::endl;
    std::string line; int count = 0; int line_num = 0;
    while (std::getline(file, line)) {
        line_num++; std::stringstream ss(line);
        std::string f[6]; // Array para os 6 campos
        if (std::getline(ss, f[0], ';') && std::getline(ss, f[1], ';') &&
            std::getline(ss, f[2], ';') && std::getline(ss, f[3], ';') &&
            std::getline(ss, f[4], ';') && std::getline(ss, f[5])) { // Lê o resto para o último campo
            for(int i=0; i<6; ++i) { // Trim simples
                f[i].erase(0, f[i].find_first_not_of(" \t\n\r\f\v"));
                f[i].erase(f[i].find_last_not_of(" \t\n\r\f\v") + 1);
            }
            g_positive_hits_buffer.push_back(ml_extract_features_for_data(f[0], f[1], f[2], f[3], f[4], f[5]));
            count++;
        }
    }
    if (count > 0) {
        std::cout << "[ML] Carregados " << count << " padrões de '" << initial_hits_path 
                  << "'. Buffer de hits positivos: " << g_positive_hits_buffer.size() << std::endl;
        g_current_search_focus = "Analisando " + std::to_string(g_positive_hits_buffer.size()) + " hits pré-carregados de " + initial_hits_path;
    } else { /* ... (como antes) ... */ }
    file.close();
}

// --- Funções da Interface ---
void ml_init(const std::string &model_path, const std::string &initial_hits_semicolon_csv_path) {
    srand(time(0)); 
    try {
        g_model = torch::jit::load(model_path);
        g_model.eval(); 
        g_model_loaded_successfully = true;
        std::cout << "[ML] Modelo PyTorch carregado: " << model_path << std::endl;
        load_initial_hits_from_semicolon_csv(initial_hits_semicolon_csv_path);
    } catch (const c10::Error &e) {
        std::cerr << "[ML] Falha ao carregar modelo: " << e.what() << std::endl;
        g_model_loaded_successfully = false;
    }
}

float ml_score_key_data(const std::string &priv_hex,
                        const std::string &wif,
                        const std::string &addr1_p2pkh_comp,
                        const std::string &addr2_p2pkh_uncomp,
                        const std::string &seed_phrase,
                        const std::string &base64_data) {
    if (!g_model_loaded_successfully) return 0.5f; 
    std::lock_guard<std::mutex> lock(g_mutex);
    
    // Usa a função agora pública para extrair features
    auto features = ml_extract_features_for_data(priv_hex, wif, addr1_p2pkh_comp, addr2_p2pkh_uncomp, seed_phrase, base64_data);
    if (features.size() != INPUT_DIM_EXPECTED) {
        return 0.5f;
    }
    try {
        torch::Tensor input_tensor = torch::from_blob(features.data(), {1, static_cast<long>(features.size())}, torch::kFloat32);
        at::Tensor output_tensor = g_model.forward({input_tensor}).toTensor();
        return output_tensor.item<float>(); 
    } catch (const c10::Error &e) {
        std::cerr << "[ML] Erro (ml_score_key_data): " << e.what() << std::endl;
        return 0.5f; 
    }
}

void ml_learn_from_hit(const std::string &priv_hex,
                       const std::string &wif,
                       const std::string &addr1_p2pkh_comp,
                       const std::string &addr2_p2pkh_uncomp,
                       const std::string &seed_phrase,
                       const std::string &base64_data) {
    if (!g_model_loaded_successfully) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    
    // Usa a função agora pública para extrair features
    auto features = ml_extract_features_for_data(priv_hex, wif, addr1_p2pkh_comp, addr2_p2pkh_uncomp, seed_phrase, base64_data);
    
    if (features.size() == INPUT_DIM_EXPECTED) {
        g_positive_hits_buffer.push_back(features); // Adiciona ao buffer de hits POSITIVOS
        std::cout << "[ML] Hit positivo adicionado ao buffer. Tamanho: " 
                  << g_positive_hits_buffer.size() << std::endl;
    } else { /* ... (log de erro como antes) ... */ }
}

void ml_periodic_update() {
    if (!g_model_loaded_successfully) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    std::cout << "[ML] === ATUALIZAÇÃO PERIÓDICA DA IA ===" << std::endl;

    if (!g_positive_hits_buffer.empty()) {
        size_t new_hits_count = g_positive_hits_buffer.size();
        g_total_positive_hits_processed += new_hits_count; // Atualiza contador de hits positivos
        
        // ... (lógica de atualização de g_current_search_focus como antes, usando g_positive_hits_buffer e g_total_positive_hits_processed) ...
        std::vector<float> last_hit_features = g_positive_hits_buffer.back();
        std::stringstream focus_ss;
        focus_ss << "Foco IA: " << new_hits_count << " hit(s) positivos recentes. "
                 << "Total positivos: " << g_total_positive_hits_processed << ". "
                 << "Ex. último: PrivLen(" << last_hit_features[0] << ") SeedWords(" << last_hit_features[4] << ")";
        g_current_search_focus = focus_ss.str();
        std::cout << "[ML] FOCO ATUAL: " << g_current_search_focus << std::endl;
        
        ml_save_state(); // Salva os HITS POSITIVOS do buffer
        
        g_positive_hits_buffer.clear(); 
        std::cout << "[ML] Buffer de hits positivos limpo." << std::endl;
    } else {
        std::cout << "[ML] Nenhum novo hit positivo no buffer." << std::endl;
    }
    std::cout << "[ML] Foco informativo: " << g_current_search_focus << std::endl;
    std::cout << "[ML] === FIM DA ATUALIZAÇÃO ===" << std::endl;
}

// Salva APENAS HITS POSITIVOS do buffer da IA
void ml_save_state(const std::string &state_path /* "models/positive_hits_features.csv" */ ) {
    if (g_positive_hits_buffer.empty()) return;
    // O lock já deve ser mantido pela ml_periodic_update

    std::ofstream file(state_path, std::ios::app); 
    if (!file.is_open()) { /* ... (erro como antes) ... */ return; }

    file.seekp(0, std::ios::end);
    bool write_header = (file.tellp() == 0);
    
    if (write_header) {
        file << "priv_hex_len,wif_present,addr1_type,addr2_present,seed_phrase_word_count,seed_phrase_avg_len_word,base64_data_len,base64_data_unique_chars_ratio,target_score\n";
    }

    std::cout << "[ML] Salvando " << g_positive_hits_buffer.size() << " features de HITS POSITIVOS para " << state_path << std::endl;
    for (const auto &features_vec : g_positive_hits_buffer) {
        for (size_t i = 0; i < features_vec.size(); ++i) {
            file << features_vec[i] << ",";
        }
        file << "1.0\n"; // Score alvo de 1.0 para hits positivos
    }
    file.close();
}

// Lógica placeholder para sugestão de range (IA "ditando")
AISearchSuggestion ml_get_next_search_suggestion() {
    std::lock_guard<std::mutex> lock(g_mutex);
    AISearchSuggestion suggestion;
    suggestion.use_suggestion = false;
    suggestion.priority_score = 0.0f;
    suggestion.reasoning = "Lógica de sugestão da IA ainda não implementada ou sem dados suficientes.";

    if (!g_model_loaded_successfully) { /* ... (retorna sugestão vazia como antes) ... */ return suggestion; }

    // Lógica de EXEMPLO (MUITO SIMPLES):
    // Se houver hits recentes, ou se o modelo pontuar bem um candidato aleatório.
    // Esta parte precisa de MUITO mais inteligência para ser útil.
    int num_candidates = 3; 
    float best_score = -0.1f; // Inicia abaixo de 0 para garantir que qualquer score positivo seja melhor
    std::string best_candidate_hex_priv = "";

    for (int i = 0; i < num_candidates; ++i) {
        std::stringstream temp_key_ss;
        // Gera um hex aleatório de 64 chars para simular uma chave privada
        for (int k = 0; k < 64; ++k) { temp_key_ss << std::hex << (rand() % 16); }
        std::string random_priv_hex = temp_key_ss.str();
        
        // Pontua esta chave (outros campos vazios, o modelo precisa lidar com isso)
        float score = ml_score_key_data(random_priv_hex, "", "", "", "", "");
        if (score > best_score) {
            best_score = score;
            best_candidate_hex_priv = random_priv_hex;
        }
    }

    if (best_score > 0.65) { // Limiar arbitrário
        suggestion.base_key_hex = best_candidate_hex_priv;
        suggestion.priority_score = best_score;
        suggestion.use_suggestion = true;
        suggestion.reasoning = "Modelo pontuou chave candidata (" + best_candidate_hex_priv.substr(0,10) + "...) com score " + std::to_string(best_score);
        std::cout << "[ML] Sugestão de IA: Explorar a partir de " << suggestion.base_key_hex.substr(0,10) << "... (Score: " << suggestion.priority_score << ")" << std::endl;
    } else {
        suggestion.reasoning = "Modelo não encontrou candidato aleatório promissor (melhor score: " + std::to_string(best_score) + "). Keyhunt deve usar lógica padrão.";
    }
    
    if(suggestion.use_suggestion){
        g_current_search_focus = "IA SUGERE: " + suggestion.reasoning;
    } else {
         g_current_search_focus = "IA: " + suggestion.reasoning;
    }
    return suggestion;
}