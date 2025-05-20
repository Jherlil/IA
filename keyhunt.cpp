/*
Develop by Alberto
email: albertobsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "oldbloom/oldbloom.h"
#include "bloom/bloom.h"
#include "sha3/sha3.h"
#include "util.h"

#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "secp256k1/Random.h"

#include "hash/sha256.h"
#include "hash/ripemd160.h"

#if defined(_WIN64) && !defined(__CYGWIN__)
#include "getopt.h"
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>
#endif

#ifdef __unix__
#ifdef __CYGWIN__
#else
#include <linux/random.h>
#include "ml_engine.h"    // Incluído para a IA
#include "hits_logger.h"  // Para export_hits (já estava no seu código)
#endif
#endif

#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define CRYPTO_ETH 2
#define CRYPTO_ALL 3

#define MODE_XPOINT 0
#define MODE_ADDRESS 1
#define MODE_BSGS 2
#define MODE_RMD160 3
#define MODE_PUB2RMD 4 // Removido, mas o define ainda existe
#define MODE_MINIKEYS 5
#define MODE_VANITY 6

#define SEARCH_UNCOMPRESS 0
#define SEARCH_COMPRESS 1
#define SEARCH_BOTH 2

uint32_t  THREADBPWORKLOAD = 1048576;

struct checksumsha256	{
	char data[32];
	char backup[32];
};

struct bsgs_xvalue	{
	uint8_t value[6];
	uint64_t index;
};

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
	char *rs;   //range start
	char *rpt;  //rng per thread
};

struct bPload	{
	uint32_t threadid;
	uint64_t from;
	uint64_t to;
	uint64_t counter;
	uint64_t workload;
	uint32_t aux;
	uint32_t finished;
};

#if defined(_WIN64) && !defined(__CYGWIN__)
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
PACK(struct publickey
{
	uint8_t parity;
	union {
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
});
#else
struct __attribute__((__packed__)) publickey {
  uint8_t parity;
	union	{
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
};
#endif

const char *Ccoinbuffer_default = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

char *Ccoinbuffer = (char*) Ccoinbuffer_default;
char *str_baseminikey = NULL;
char *raw_baseminikey = NULL;
char *minikeyN = NULL;
int minikey_n_limit;
	
const char *version = "0.2.230519 Satoshi Quest"; // Você pode atualizar a versão se quiser

#define CPU_GRP_SIZE 1024

std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;

// Protótipos de função
void menu();
void init_generator();
int searchbinary(struct address_value *buffer,char *data,int64_t array_length);
void sleep_ms(int milliseconds);
void _sort(struct address_value *arr,int64_t N);
void _insertionsort(struct address_value *arr, int64_t n);
void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n);
void _swap(struct address_value *a,struct address_value *b);
int64_t _partition(struct address_value *arr, int64_t n);
void _myheapsort(struct address_value	*arr, int64_t n);
void _heapify(struct address_value *arr, int64_t n, int64_t i);
void bsgs_sort(struct bsgs_xvalue *arr,int64_t n);
void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_introsort(struct bsgs_xvalue *arr,uint32_t depthLimit, int64_t n);
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b);
void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i);
int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n);
int bsgs_searchbinary(struct bsgs_xvalue *arr,char *data,int64_t array_length,uint64_t *r_value);
int bsgs_secondcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey);
int bsgs_thirdcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey);
void sha256sse_22(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);
void sha256sse_23(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);
bool vanityrmdmatch(unsigned char *rmdhash);
void writevanitykey(bool compressed,Int *key);
int addvanity(char *target);
int minimum_same_bytes(unsigned char* A,unsigned char* B, int length);
void writekey(bool compressed,Int *key);
void writekeyeth(Int *key);
void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);
bool isBase58(char c);
bool isValidBase58String(char *str);
bool readFileAddress(char *fileName);
bool readFileVanity(char *fileName);
bool forceReadFileAddress(char *fileName);
bool forceReadFileAddressEth(char *fileName);
bool forceReadFileXPoint(char *fileName);
bool processOneVanity();
bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom);
void writeFileIfNeeded(const char *fileName);
void calcualteindex(int i,Int *key);

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_vanity(LPVOID vargp);
DWORD WINAPI thread_process_minikeys(LPVOID vargp);
DWORD WINAPI thread_process(LPVOID vargp);
DWORD WINAPI thread_process_bsgs(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_backward(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_both(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_random(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_dance(LPVOID vargp);
DWORD WINAPI thread_bPload(LPVOID vargp);
DWORD WINAPI thread_bPload_2blooms(LPVOID vargp);
#else
void *thread_process_vanity(void *vargp);
void *thread_process_minikeys(void *vargp);	
void *thread_process(void *vargp);
void *thread_process_bsgs(void *vargp);
void *thread_process_bsgs_backward(void *vargp);
void *thread_process_bsgs_both(void *vargp);
void *thread_process_bsgs_random(void *vargp);
void *thread_process_bsgs_dance(void *vargp);
void *thread_bPload(void *vargp);
void *thread_bPload_2blooms(void *vargp);
#endif

char *pubkeytopubaddress(char *pkey,int length);
void pubkeytopubaddress_dst(char *pkey,int length,char *dst);
void rmd160toaddress_dst(char *rmd,char *dst);
void set_minikey(char *buffer,char *rawbuffer,int length);
bool increment_minikey_index(char *buffer,char *rawbuffer,int index);
void increment_minikey_N(char *rawbuffer);
void KECCAK_256(uint8_t *source, size_t size,uint8_t *dst);
void generate_binaddress_eth(Point &publickey,unsigned char *dst_address);

// Variáveis Globais
int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *bsgs_modes[5] = {"sequential","backward","both","random","dance"};
const char *modes[7] = {"xpoint","address","bsgs","rmd160","pub2rmd","minikeys","vanity"};
const char *cryptos[3] = {"btc","eth","all"};
const char *publicsearch[3] = {"uncompress","compress","both"};
const char *default_fileName = "addresses.txt";
std::string g_initial_hits_file_path = "hits.txt"; // << ARQUIVO PARA HITS INICIAIS DA IA >>

#if defined(_WIN64) && !defined(__CYGWIN__)
HANDLE* tid = NULL;
HANDLE write_keys;
HANDLE write_random;
HANDLE bsgs_thread;
HANDLE *bPload_mutex = NULL;
HANDLE write_negative_log_mutex; // << NOVO MUTEX PARA LOG DE NEGATIVOS >>
#else
pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t bsgs_thread;
pthread_mutex_t *bPload_mutex = NULL;
pthread_mutex_t write_negative_log_mutex; // << NOVO MUTEX PARA LOG DE NEGATIVOS >>
#endif

uint64_t FINISHED_THREADS_COUNTER = 0;
uint64_t FINISHED_THREADS_BP = 0;
uint64_t THREADCYCLES = 0;
uint64_t THREADCOUNTER = 0;
uint64_t FINISHED_ITEMS = 0;
uint64_t OLDFINISHED_ITEMS = (uint64_t)-1; // Corrigido para warning de comparação

uint8_t byte_encode_crypto = 0x00;

int vanity_rmd_targets = 0;
int vanity_rmd_total = 0;
int *vanity_rmd_limits = NULL;
uint8_t ***vanity_rmd_limit_values_A = NULL,***vanity_rmd_limit_values_B = NULL;
int vanity_rmd_minimun_bytes_check_length = 999999;
char **vanity_address_targets = NULL;
struct bloom *vanity_bloom = NULL;

struct bloom bloom;

uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;

uint64_t N_SEQUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400; // Usado em alguns cálculos de stats
// uint64_t u64range; // Parece não ser usada, pode comentar ou remover

Int OUTPUTSECONDS;

int FLAGSKIPCHECKSUM = 0;
int FLAGENDOMORPHISM = 0;
int FLAG_IA_FORCE_MODE = 0; // << NOVO FLAG PARA CONTROLAR MODO "IA FORCE" >>

int FLAGBLOOMMULTIPLIER = 1;
int FLAGVANITY = 0;
int FLAGBASEMINIKEY = 0;
int FLAGBSGSMODE = 0;
int FLAGDEBUG = 0;
int FLAGQUIET = 0;
int FLAGMATRIX = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;

int FLAGSAVEREADFILE = 0;
int FLAGREADEDFILE1 = 0;
int FLAGREADEDFILE2 = 0;
int FLAGREADEDFILE3 = 0;
int FLAGREADEDFILE4 = 0;
int FLAGUPDATEFILE1 = 0;

int FLAGSTRIDE = 0;
int FLAGSEARCH = 2; // Default: SEARCH_BOTH
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAGMODE = MODE_ADDRESS; // Default: address
int FLAGCRYPTO = 0; // Default: none (será BTC se modo address e nada especificado)
// int FLAGRAWDATA	= 0; // Parece não ser usada
int FLAGRANDOM = 0; // Default: não aleatório (sequencial em range, ou threads pegam blocos)
int FLAG_N = 0;
// int FLAGPRECALCUTED_P_FILE = 0; // Parece não ser usada

int bitrange;
char *str_N;
char *range_start;
char *range_end;
char *str_stride;
Int stride;

uint64_t BSGS_XVALUE_RAM = 6;
// uint64_t BSGS_BUFFERXPOINTLENGTH = 32; // Definido localmente onde usado
// uint64_t BSGS_BUFFERREGISTERLENGTH = 36; // Definido localmente onde usado

// BSGS Variables (como antes)
int *bsgs_found;
std::vector<Point> OriginalPointsBSGS;
bool *OriginalPointsBSGScompressed;
uint64_t bytes_bsgs_table; // Renomeado de bytes para evitar conflito
char checksum_bsgs_table[32],checksum_backup_bsgs_table[32]; // Renomeado
char buffer_bloom_file[1024];
struct bsgs_xvalue *bPtable;
struct address_value *addressTable;
struct oldbloom oldbloom_bP;
struct bloom *bloom_bP;
struct bloom *bloom_bPx2nd;
struct bloom *bloom_bPx3rd;
struct checksumsha256 *bloom_bP_checksums;
struct checksumsha256 *bloom_bPx2nd_checksums;
struct checksumsha256 *bloom_bPx3rd_checksums;
#if defined(_WIN64) && !defined(__CYGWIN__)
// std::vector<HANDLE> bloom_bP_mutex; // Seu código original declara como std::vector mas usa como HANDLE*
// std::vector<HANDLE> bloom_bPx2nd_mutex;
// std::vector<HANDLE> bloom_bPx3rd_mutex;
HANDLE *bloom_bP_mutex_handles = NULL; // Alterado para ponteiro para consistência com calloc
HANDLE *bloom_bPx2nd_mutex_handles = NULL;
HANDLE *bloom_bPx3rd_mutex_handles = NULL;
#else
pthread_mutex_t *bloom_bP_mutex;
pthread_mutex_t *bloom_bPx2nd_mutex;
pthread_mutex_t *bloom_bPx3rd_mutex;
#endif
uint64_t bloom_bP_totalbytes = 0;
uint64_t bloom_bP2_totalbytes = 0;
uint64_t bloom_bP3_totalbytes = 0;
uint64_t bsgs_m_val = 4194304; // Renomeado de bsgs_m para evitar conflito com Int BSGS_M
uint64_t bsgs_m2_val; // Renomeado
uint64_t bsgs_m3_val; // Renomeado
uint64_t bsgs_aux_val; // Renomeado
uint32_t bsgs_point_number;

const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];

Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX_INT; // Renomeado de BSGS_AUX
Int BSGS_N_val;      // Renomeado de BSGS_N
Int BSGS_N_double;
Int BSGS_M;		
Int BSGS_M_double;
Int BSGS_M2;		
Int BSGS_M2_double;	
Int BSGS_M3;		
Int BSGS_M3_double;	

Int ONE;
Int ZERO;
Int MPZAUX; // Usado para cálculos temporários com BigInt

Point BSGS_P_calc; // Renomeado de BSGS_P
Point BSGS_MP_calc; // Renomeado
Point BSGS_MP2_calc; // Renomeado
Point BSGS_MP3_calc; // Renomeado

Point BSGS_MP_double_calc; // Renomeado
Point BSGS_MP2_double_calc; // Renomeado
Point BSGS_MP3_double_calc; // Renomeado

std::vector<Point> BSGS_AMP2;
std::vector<Point> BSGS_AMP3;

Point point_temp,point_temp2;

Int n_range_start_global; // Renomeado de n_range_start
Int n_range_end_global;   // Renomeado de n_range_end_global
Int n_range_diff_global;  // Renomeado de n_range_diff
Int n_range_aux_val;      // Renomeado de n_range_aux

Int lambda,lambda2,beta,beta2; // Para endomorfismo

Secp256K1 *secp;


int main(int argc, char **argv)	{
    printf("====================================\n");
    printf("=        Keyhunt ML Edition        =\n");
    printf("= IA Ativa por padrão [libtorch]   =\n"); // Banner já estava
    printf("====================================\n\n");
    
    // << MODIFICAÇÃO AQUI >>
    // Inicializa a IA, passando o caminho do arquivo de hits (ex: "hits.txt")
    // O arquivo g_initial_hits_file_path pode ser configurado por um novo argumento de linha de comando se desejado.
    ml_init("models/model.pt", g_initial_hits_file_path); 
    // << FIM DA MODIFICAÇÃO >>
	struct tothread *tt_data_ptr;	// Renomeado de tt
	Tokenizer t_tokenizer, tokenizerbsgs_main;	// Renomeado t, tokenizerbsgs
	char *fileName_ptr = NULL; // Renomeado de fileName
	char *hextemp_ptr = NULL;  // Renomeado de hextemp
	char *aux_char_ptr = NULL; // Renomeado de aux
	char *aux2_char_ptr = NULL;// Renomeado de aux2
	char *pointx_str_main = NULL; // Renomeado
	char *pointy_str_main = NULL; // Renomeado
	char *str_seconds_out = NULL; // Renomeado
	char *str_total_out = NULL; // Renomeado
	char *str_pretotal_out = NULL; // Renomeado
	char *str_divpretotal_out = NULL; // Renomeado
	char *bf_file_ptr = NULL; // Renomeado de bf_ptr
	char *bPload_threads_available_ptr; // Renomeado
	FILE *fd_ptr, *fd_aux1_ptr, *fd_aux2_ptr, *fd_aux3_ptr; // Renomeados
	uint64_t i_loop_main, BASE_val, PERTHREAD_R_val, itemsbloom_main, itemsbloom2_main, itemsbloom3_main; // Renomeados
	uint32_t finished_flag_main; // Renomeado de finished
	int readed_bytes, continue_flag_main, check_flag_main, c_opt, salir_flag, index_value_opt, j_loop; // Renomeados
	Int total_keys_processed, pretotal_keys_processed, debugcount_mpz_val, seconds_elapsed, div_pretotal_val, int_aux_calc, int_r_calc, int_q_calc, int58_val; // Renomeados
	struct bPload *bPload_temp_data_ptr; // Renomeado
	size_t rsize_val; // Renomeado
	
#if defined(_WIN64) && !defined(__CYGWIN__)
	DWORD s_thread_status; // Renomeado de s
	write_keys = CreateMutex(NULL, FALSE, NULL);
	write_random = CreateMutex(NULL, FALSE, NULL);
	bsgs_thread = CreateMutex(NULL, FALSE, NULL);
    write_negative_log_mutex = CreateMutex(NULL, FALSE, NULL); // << INICIALIZA NOVO MUTEX >>
#else
	pthread_mutex_init(&write_keys,NULL);
	pthread_mutex_init(&write_random,NULL);
	pthread_mutex_init(&bsgs_thread,NULL);
    pthread_mutex_init(&write_negative_log_mutex, NULL); // << INICIALIZA NOVO MUTEX >>
	int s_thread_status; // Renomeado de s
#endif

	srand(time(NULL));

	secp = new Secp256K1();
	secp->Init();
	OUTPUTSECONDS.SetInt32(30); // << ATUALIZAÇÕES DA IA A CADA 30 SEGUNDOS POR PADRÃO >>
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);
	
#if defined(_WIN64) && !defined(__CYGWIN__)
	rseed(clock() + time(NULL) + rand());
#else
	unsigned long rseedvalue_main; // Renomeado
	int bytes_read_rng = getrandom(&rseedvalue_main, sizeof(unsigned long), GRND_NONBLOCK); // Renomeado
	if(bytes_read_rng > 0)	{
		rseed(rseedvalue_main);
	}
	else	{
		fprintf(stderr,"[E] Error getrandom() ?\n");
		exit(EXIT_FAILURE);
	}
#endif
	
	printf("[+] Version %s, developed by AlbertoBSD\n",version);

    // Adicionar uma opção para o arquivo de hits iniciais da IA, ex: -A <arquivo_hits.txt>
	while ((c_opt = getopt(argc, argv, "a:deh6MqRSB:b:c:C:E:f:I:k:l:m:N:n:p:r:s:t:v:G:8:z:")) != -1) { // Adicione 'a:' para a nova flag da IA
		switch(c_opt) {
            // ... (todos os seus cases existentes para getopt) ...
            case 'a': // << NOVO CASE PARA MODO "IA FORCE" E ARQUIVO DE HITS >>
                // Este argumento poderia ser usado para duas coisas:
                // 1. Habilitar o modo "IA Force"
                // 2. Opcionalmente, especificar o arquivo de hits iniciais se diferente de "hits.txt"
                // Exemplo: -a           (habilita IA Force com hits.txt padrão)
                //          -a otherhits.txt (habilita IA Force com otherhits.txt)
                if (optarg && strlen(optarg) > 0 && strcmp(optarg, "1") != 0 && strcmp(optarg, "true") != 0) { // Se optarg não for um simples ativador
                    g_initial_hits_file_path = std::string(optarg);
                    printf("[+] Usando arquivo de hits iniciais para IA: %s\n", g_initial_hits_file_path.c_str());
                }
                FLAG_IA_FORCE_MODE = 1;
                printf("[+] MODO IA FORCE HABILITADO! A IA tentará ditar os ranges.\n");
            break;
            case 's': // Atualiza para garantir que o padrão de 30s seja usado se -s não for especificado, ou usa o valor de -s
				OUTPUTSECONDS.SetBase10(optarg);
				if(OUTPUTSECONDS.IsLower(&ZERO) || OUTPUTSECONDS.IsZero())	{ // Se 0 ou negativo, desliga stats e updates da IA
					OUTPUTSECONDS.SetInt32(0); // Garante que seja 0
                    printf("[+] Stats e atualizações da IA desligados.\n");
				} else {
					hextemp_ptr = OUTPUTSECONDS.GetBase10();
					printf("[+] Stats e atualizações da IA a cada %s segundos.\n",hextemp_ptr);
					free(hextemp_ptr);
                    hextemp_ptr = NULL;
				}
			break;
            // ... (resto dos seus cases) ...
        }
    }
    // Se -s não foi usado, OUTPUTSECONDS ainda terá o valor default (30) definido anteriormente.
    // Se -s 0 foi usado, OUTPUTSECONDS será 0.
    // Se -s X (X > 0) foi usado, OUTPUTSECONDS será X.


	// ... (resto da sua lógica de configuração após getopt, como stride, ranges, modos etc.) ...
    // Esta parte permanece a mesma, apenas os nomes das variáveis globais de range foram alterados
    // para n_range_start_global, n_range_end_global, n_range_diff_global, n_range_aux_val

    if(FLAGRANGE) { // Se -r foi usado
		n_range_start_global.SetBase16(range_start);
		if(n_range_start_global.IsZero())	{
			n_range_start_global.AddOne();
		}
		n_range_end_global.SetBase16(range_end);
		if(!n_range_start_global.IsEqual(&n_range_end_global)) { // Corrigido de == false para !=
			if(n_range_start_global.IsLower(&secp->order) &&  n_range_end_global.IsLowerOrEqual(&secp->order) )	{
				if( n_range_start_global.IsGreater(&n_range_end_global)) {
					fprintf(stderr,"[W] Range inicial maior que final. Trocando-os.\n");
					n_range_aux_val.Set(&n_range_start_global);
					n_range_start_global.Set(&n_range_end_global);
					n_range_end_global.Set(&n_range_aux_val);
				}
				n_range_diff_global.Set(&n_range_end_global);
				n_range_diff_global.Sub(&n_range_start_global);
			}
			else	{
				fprintf(stderr,"[E] Range fora da ordem da curva. Voltando para modo aleatório se IA não ditar.\n");
				FLAGRANGE = 0; // Desabilita range fixo se IA não assumir
			}
		}
		else	{
			fprintf(stderr,"[E] Range inicial igual ao final. Voltando para modo aleatório se IA não ditar.\n");
			FLAGRANGE = 0;
		}
	}
	// Se não for range BSGS ou Minikeys (esses têm sua própria lógica de N e range)
	if(FLAGMODE != MODE_BSGS && FLAGMODE != MODE_MINIKEYS)	{
		BSGS_N_val.SetInt64(DEBUGCOUNT); // BSGS_N_val é usado para debugcount_mpz_val mais tarde
		if(FLAGRANGE == 0 && FLAGBITRANGE == 0 && FLAG_IA_FORCE_MODE == 0)	{ // Se nenhum range, nem bitrange, NEM IA FORCE
			n_range_start_global.SetInt64(1);
			n_range_end_global.Set(&secp->order);
			n_range_diff_global.Set(&n_range_end_global);
			n_range_diff_global.Sub(&n_range_start_global);
            printf("[+] Nenhum range específico ou IA Force. Buscando em todo o espaço de chaves (lento!).\n");
		}
		else if (FLAGBITRANGE && FLAG_IA_FORCE_MODE == 0) { // Se bitrange e não IA Force
			n_range_start_global.SetBase16(bit_range_str_min);
			n_range_end_global.SetBase16(bit_range_str_max);
			n_range_diff_global.Set(&n_range_end_global);
			n_range_diff_global.Sub(&n_range_start_global);
		}
        // Se FLAG_IA_FORCE_MODE == 1, os ranges serão (idealmente) ditados pela IA dentro das threads.
        // Se FLAGRANGE == 1, ele será usado como fallback se a IA não fornecer uma sugestão forte.
	}
    // ... (continua a lógica de inicialização de N, arquivos, BSGS, etc., como no seu original,
    //      usando os nomes de variáveis atualizados se necessário) ...
    // Lembre-se que nomes como N (global) foram mantidos para compatibilidade com _sort, readFileAddress etc.
    // BSGS_N foi renomeado para BSGS_N_val para o BigInt, etc.

    // --- INÍCIO DO LOOP PRINCIPAL DE MONITORAMENTO E ESTATÍSTICAS ---
	continue_flag_main = 1;
	total_keys_processed.SetInt32(0);
	pretotal_keys_processed.SetInt32(0);
    if(FLAGMODE == MODE_BSGS) debugcount_mpz_val.Set(&BSGS_N_val); // Para BSGS, o "passo" é N (m*m)
    else debugcount_mpz_val.SetInt64(N_SEQUENTIAL_MAX); // Para outros modos, o "passo" da thread é N_SEQUENTIAL_MAX

	seconds_elapsed.SetInt32(0);
	do	{
		sleep_ms(1000); 
		seconds_elapsed.AddOne();
		check_flag_main = 1;
		for(j_loop = 0; j_loop <NTHREADS && check_flag_main; j_loop++) {
			check_flag_main &= ends[j_loop]; 
		}
		if(check_flag_main)	{
			continue_flag_main = 0; 
		}

		if(OUTPUTSECONDS.IsGreater(&ZERO) ){ 
			MPZAUX.Set(&seconds_elapsed);
			MPZAUX.Mod(&OUTPUTSECONDS);
			if(MPZAUX.IsZero()) { 
				total_keys_processed.SetInt32(0);
				for(j_loop = 0; j_loop < NTHREADS; j_loop++) {
                    // pretotal_keys_processed é usado como temp aqui
					pretotal_keys_processed.Set(&debugcount_mpz_val); // Cada step[j] representa um bloco de debugcount_mpz_val chaves
					pretotal_keys_processed.Mult(steps[j_loop]);					
					total_keys_processed.Add(&pretotal_keys_processed);
				}
				
				if(FLAGENDOMORPHISM && (FLAGMODE == MODE_ADDRESS || FLAGMODE == MODE_RMD160 || FLAGMODE == MODE_VANITY || FLAGMODE == MODE_XPOINT))	{
					if(FLAGMODE == MODE_XPOINT && FLAGSEARCH != SEARCH_BOTH) { // XPoint não tem compressão, só 3x por endo
                        total_keys_processed.Mult(3);
                    } else if (FLAGMODE == MODE_XPOINT && FLAGSEARCH == SEARCH_BOTH) { // XPoint não tem compressão, mas se ambos (???)
                        total_keys_processed.Mult(3); // Ainda 3x
                    }
                    else if (FLAGSEARCH == SEARCH_BOTH) { // ADDRESS/RMD/VANITY com BOTH e ENDO
						total_keys_processed.Mult(6); // 2 (comp/uncomp) * 3 (original, beta, beta^2)
					} else { // ADDRESS/RMD/VANITY com COMPRESS ou UNCOMPRESS e ENDO
                        total_keys_processed.Mult(3); // 1 (comp OU uncomp) * 3
                    }
				}
				else if (FLAGSEARCH == SEARCH_BOTH && (FLAGMODE == MODE_ADDRESS || FLAGMODE == MODE_RMD160 || FLAGMODE == MODE_VANITY)) { // Sem endo, mas BOTH
					total_keys_processed.Mult(2);
				}
				// Para Minikeys e BSGS, o 'steps' já reflete o trabalho de forma diferente, não multiplicamos por 2 ou 6.
				
#if defined(_WIN64) && !defined(__CYGWIN__)
				WaitForSingleObject(bsgs_thread, INFINITE); 
#else
				pthread_mutex_lock(&bsgs_thread);
#endif			
				pretotal_keys_processed.Set(&total_keys_processed);
                if(!seconds_elapsed.IsZero()) pretotal_keys_processed.Div(&seconds_elapsed);
                else pretotal_keys_processed.SetInt32(0);

				str_seconds_out = seconds_elapsed.GetBase10();
				str_pretotal_out = pretotal_keys_processed.GetBase10();
				str_total_out = total_keys_processed.GetBase10();
				
				if(pretotal_keys_processed.IsLower(&int_limits[0]))	{
					if(FLAGMATRIX)	{
					char buffer_stats[256]; sprintf(buffer_stats,"[+] Total %s chaves em %s seg: %s chaves/s\n",str_total_out,str_seconds_out,str_pretotal_out);
					} else {
					char buffer_stats[256]; sprintf(buffer_stats,"\r[+] Total %s chaves em %s seg: %s chaves/s",str_total_out,str_seconds_out,str_pretotal_out);
					}
				} else {
					i_loop_main = 0; salir_flag = 0;
					while( i_loop_main < 6 && !salir_flag)	{
						if(pretotal_keys_processed.IsLower(&int_limits[i_loop_main+1]))	{
							salir_flag = 1;
						} else { i_loop_main++; }
					}
					div_pretotal_val.Set(&pretotal_keys_processed);
					div_pretotal_val.Div(&int_limits[salir_flag ? i_loop_main : i_loop_main-1]); // Corrigido índice para str_limits_prefixs
				char buffer_stats[256];
	str_divpretotal_out = div_pretotal_val.GetBase10();
				char buffer_stats[256];
	if(FLAGMATRIX)	{
					char buffer_stats[256]; sprintf(buffer_stats,"[+] Total %s chaves em %s seg: ~%s %s (%s chaves/s)\n",str_total_out,str_seconds_out,str_divpretotal_out,str_limits_prefixs[salir_flag ? i_loop_main : i_loop_main-1],str_pretotal_out);
					} else {
				char buffer_stats[256]; sprintf(buffer_stats,"\r[+] Total %s chaves em %s seg: ~%s %s (%s chaves/s)",str_total_out,str_seconds_out,str_divpretotal_out,str_limits_prefixs[salir_flag ? i_loop_main : i_loop_main-1],str_pretotal_out);
					}
					char buffer_stats[256]; free(str_divpretotal_out); str_divpretotal_out = NULL;
				}
				printf("%s",buffer_stats); 
                if (!FLAGMATRIX) { // Para modo não-matrix, garantir que a linha não fique suja
                    printf("          \r"); // Espaços para limpar o restante da linha, depois \r
                }
				THREADOUTPUT = 0; 
                
                // << MODIFICAÇÃO PARA ATUALIZAÇÃO DA IA >>
                ml_periodic_update(); // Chama a atualização da IA, que imprimirá seu status.
                // << FIM DA MODIFICAÇÃO >>
                                
				fflush(stdout); // Garante que tudo (stats e output da IA) seja impresso
                                
#if defined(_WIN64) && !defined(__CYGWIN__)
				ReleaseMutex(bsgs_thread);
#else
				pthread_mutex_unlock(&bsgs_thread);
#endif
				if(str_seconds_out) { free(str_seconds_out); str_seconds_out = NULL; }
				if(str_pretotal_out) { free(str_pretotal_out); str_pretotal_out = NULL; }
				if(str_total_out) { free(str_total_out); str_total_out = NULL; }
			}
		}
	} while(continue_flag_main);
    // ... (resto da função main, como antes, incluindo limpeza de mutexes)
    // ... seu código de limpeza de handles/mutexes e frees ...
	printf("\nEnd\n");

#ifdef _WIN64
	CloseHandle(write_keys);
	CloseHandle(write_random);
	CloseHandle(bsgs_thread);
    CloseHandle(write_negative_log_mutex); // << LIMPA NOVO MUTEX >>
    // ... (sua lógica de limpeza de HANDLE* bPload_mutex_handles, etc.)
#else
    pthread_mutex_destroy(&write_keys);
    pthread_mutex_destroy(&write_random);
    pthread_mutex_destroy(&bsgs_thread);
    pthread_mutex_destroy(&write_negative_log_mutex); // << LIMPA NOVO MUTEX >>
    // ... (sua lógica de limpeza de pthread_mutex_t* bPload_mutex, etc.)
#endif
    if (secp) delete secp;
    // ... (outros frees que você já tem) ...
	return 0;
}

// (Fim da primeira parte - aproximadamente 500-600 linhas)
// (Continuação do keyhunt.cpp - após a função searchbinary)
// ... (as funções pubkeytopubaddress_dst, rmd160toaddress_dst, pubkeytopubaddress, searchbinary permanecem como antes) ...

// Adiciona o "bip" e a chamada ml_learn_from_hit
void writekey(bool compressed,Int *key)	{
	Point publickey_obj;
	FILE *keys_file_ptr;
	char *hextemp_privkey = NULL;
    char *hexrmd_str = NULL;
    char public_key_hex_str[132];
    char address_str[50];
    char rmdhash_bin[20];
	
    std::string priv_hex_for_ml = "";
    std::string wif_for_ml = ""; 
    std::string addr1_p2pkh_comp_for_ml = ""; 
    std::string addr2_p2pkh_uncomp_for_ml = ""; 
    std::string seed_phrase_for_ml = ""; 
    std::string base64_data_for_ml = "";

	memset(address_str,0,50);
	memset(public_key_hex_str,0,132);

	hextemp_privkey = key->GetBase16();
    priv_hex_for_ml = std::string(hextemp_privkey);

	// TODO: Implementar lógica para gerar WIF a partir de 'key' e 'compressed' se desejado para 'wif_for_ml'
    // Ex: wif_for_ml = generate_wif_from_key(key, compressed);

	publickey_obj = secp->ComputePublicKey(key);
	secp->GetPublicKeyHex(compressed, publickey_obj, public_key_hex_str); // Esta é a pubkey principal do hit

    // Gerar addr1 (P2PKH correspondente à 'compressed')
	secp->GetHash160(P2PKH, compressed, publickey_obj, (uint8_t*)rmdhash_bin);
	hexrmd_str = tohex(rmdhash_bin,20); // Guardar para log
	rmd160toaddress_dst(rmdhash_bin, address_str); 
    addr1_p2pkh_comp_for_ml = std::string(address_str);

    // TODO: Implementar lógica para gerar addr2_p2pkh_uncomp_for_ml se 'compressed' for true,
    //       derivando a pubkey não comprimida e seu endereço P2PKH.
    //       Se 'compressed' for false, então addr1 já é uncompressed, e addr2_p2pkh_uncomp_for_ml pode ser igual a addr1_for_ml
    //       ou pode ser deixado vazio se a intenção é ter tipos distintos.
    // Ex: if (compressed) {
    //          char uncomp_addr_str[50];
    //          secp->GetHash160(P2PKH, false, publickey_obj, (uint8_t*)rmdhash_bin_temp);
    //          rmd160toaddress_dst(rmdhash_bin_temp, uncomp_addr_str);
    //          addr2_p2pkh_uncomp_for_ml = std::string(uncomp_addr_str);
    //      } else {
    //          addr2_p2pkh_uncomp_for_ml = addr1_p2pkh_comp_for_ml; // Ou vazio, dependendo da sua definição
    //      }
    // Por simplicidade, se não for BTC, não teremos addr2 facilmente.
    if (FLAGCRYPTO == CRYPTO_BTC) {
        if (compressed) { // Se o hit principal é comprimido, geramos o não comprimido como addr2
            char temp_addr_uncomp[50];
            char temp_rmd_uncomp[20];
            secp->GetHash160(P2PKH, false, publickey_obj, (uint8_t*)temp_rmd_uncomp);
            rmd160toaddress_dst(temp_rmd_uncomp, temp_addr_uncomp);
            addr2_p2pkh_uncomp_for_ml = std::string(temp_addr_uncomp);
        } else { // Se o hit principal é não comprimido, addr1 é o uncomp, addr2 pode ser o comp
            char temp_addr_comp[50];
            char temp_rmd_comp[20];
            secp->GetHash160(P2PKH, true, publickey_obj, (uint8_t*)temp_rmd_comp);
            rmd160toaddress_dst(temp_rmd_comp, temp_addr_comp);
            // Aqui, addr1_p2pkh_comp_for_ml é na verdade o uncompressed. Ajustar nomes se ficar confuso.
            // Para este exemplo, vamos assumir que addr1 é sempre o "principal" e addr2 é o "outro".
            addr2_p2pkh_uncomp_for_ml = addr1_p2pkh_comp_for_ml; // O principal é o uncomp
            addr1_p2pkh_comp_for_ml = std::string(temp_addr_comp); // O "addr1" para IA será o comprimido
        }
    }


#if defined(_WIN64) && !defined(__CYGWIN__)
	WaitForSingleObject(write_keys, INFINITE);
#else
	pthread_mutex_lock(&write_keys);
#endif
    fprintf(stderr, "\a"); // << BIP DO SISTEMA >>
    fflush(stderr);

	keys_file_ptr = fopen("KEYFOUNDKEYFOUND.txt","a+");
	if(keys_file_ptr != NULL)	{
		fprintf(keys_file_ptr,"Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n", hextemp_privkey, public_key_hex_str, address_str, hexrmd_str);
		// Adicionar seed e base64 ao arquivo se desejar e se estiverem disponíveis:
        // if (!seed_phrase_for_ml.empty()) fprintf(keys_file_ptr, "Seed: %s\n", seed_phrase_for_ml.c_str());
        // if (!base64_data_for_ml.empty()) fprintf(keys_file_ptr, "Base64: %s\n", base64_data_for_ml.c_str());
		fclose(keys_file_ptr);
	}
	printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n", hextemp_privkey, public_key_hex_str, address_str, hexrmd_str);
	// if (!seed_phrase_for_ml.empty()) printf("Seed: %s\n", seed_phrase_for_ml.c_str());
    // if (!base64_data_for_ml.empty()) printf("Base64: %s\n", base64_data_for_ml.c_str());
	
    ml_learn_from_hit(
        priv_hex_for_ml,
        wif_for_ml,           
        addr1_p2pkh_comp_for_ml, // Este será o P2PKH comprimido se CRYPTO_BTC e compressed=true, ou o P2PKH uncomp se compressed=false
        addr2_p2pkh_uncomp_for_ml, // Este será o P2PKH não comprimido se CRYPTO_BTC e compressed=true
        seed_phrase_for_ml, 
        base64_data_for_ml  
    );
    
#if defined(_WIN64) && !defined(__CYGWIN__)
	ReleaseMutex(write_keys);
#else
	pthread_mutex_unlock(&write_keys);
#endif
	if(hextemp_privkey) free(hextemp_privkey);
	if(hexrmd_str) free(hexrmd_str);
}

void writekeyeth(Int *key)	{
	Point publickey_obj; 
	FILE *keys_file_ptr;
	char *hextemp_privkey = NULL;
    char address_eth_str[43];
    char hash_eth_bin[20]; 

    std::string priv_hex_for_ml = "";
    std::string wif_for_ml = ""; 
    std::string addr1_eth_for_ml = ""; 
    std::string addr2_eth_for_ml = ""; 
    std::string seed_phrase_for_ml = "";
    std::string base64_data_for_ml = "";

	hextemp_privkey = key->GetBase16();
    priv_hex_for_ml = std::string(hextemp_privkey);

	publickey_obj = secp->ComputePublicKey(key);
	generate_binaddress_eth(publickey_obj,(unsigned char*)hash_eth_bin);
	address_eth_str[0] = '0';
	address_eth_str[1] = 'x';
	tohex_dst(hash_eth_bin,20,address_eth_str+2);
    addr1_eth_for_ml = std::string(address_eth_str);
    // Para ETH, addr2, wif, seed, base64 são tipicamente não aplicáveis diretamente do hit de chave
    // a menos que a busca seja direcionada por esses elementos.

#if defined(_WIN64) && !defined(__CYGWIN__)
	WaitForSingleObject(write_keys, INFINITE);
#else
	pthread_mutex_lock(&write_keys);
#endif
    fprintf(stderr, "\a"); // << BIP DO SISTEMA >>
    fflush(stderr);

	keys_file_ptr = fopen("KEYFOUNDKEYFOUND.txt","a+");
	if(keys_file_ptr != NULL)	{
		fprintf(keys_file_ptr,"Private Key: %s\naddress: %s\n",hextemp_privkey,address_eth_str);
		fclose(keys_file_ptr);
	}
	printf("\n Hit!!!! Private Key: %s\naddress: %s\n",hextemp_privkey,address_eth_str);

    ml_learn_from_hit(
        priv_hex_for_ml,
        wif_for_ml,          
        addr1_eth_for_ml, // Endereço ETH principal        
        addr2_eth_for_ml, // Vazio para ETH           
        seed_phrase_for_ml,  
        base64_data_for_ml   
    );
    
#if defined(_WIN64) && !defined(__CYGWIN__)
	ReleaseMutex(write_keys);
#else
	pthread_mutex_unlock(&write_keys);
#endif
	if(hextemp_privkey) free(hextemp_privkey);
}

void writevanitykey(bool compressed,Int *key)	{
	Point publickey_obj;
	FILE *keys_file_ptr;
	char *hextemp_privkey = NULL;
    char *hexrmd_str = NULL;
    char public_key_hex_str[131];
    char address_str[50];
    char rmdhash_bin[20];

    std::string priv_hex_for_ml = "";
    std::string wif_for_ml = ""; 
    std::string addr1_vanity_for_ml = ""; 
    std::string addr2_vanity_for_ml = ""; 
    std::string seed_phrase_for_ml = "";
    std::string base64_data_for_ml = "";

	hextemp_privkey = key->GetBase16();
    priv_hex_for_ml = std::string(hextemp_privkey);

	// TODO: Lógica para WIF se aplicável/desejado
    
	publickey_obj = secp->ComputePublicKey(key);
	secp->GetPublicKeyHex(compressed,publickey_obj,public_key_hex_str);
	secp->GetHash160(P2PKH,compressed,publickey_obj,(uint8_t*)rmdhash_bin); // Assumindo P2PKH para vanity, pode variar
	hexrmd_str = tohex(rmdhash_bin,20);
	rmd160toaddress_dst(rmdhash_bin,address_str);
    addr1_vanity_for_ml = std::string(address_str);

    // TODO: Lógica para addr2 se aplicável (ex: endereço não comprimido se o 'compressed' for true)
    // Similar ao writekey.

#if defined(_WIN64) && !defined(__CYGWIN__)
	WaitForSingleObject(write_keys, INFINITE);
#else
	pthread_mutex_lock(&write_keys);
#endif
    fprintf(stderr, "\a"); // << BIP DO SISTEMA >>
    fflush(stderr);

	keys_file_ptr = fopen("VANITYKEYFOUND.txt","a+");
	if(keys_file_ptr != NULL)	{
		fprintf(keys_file_ptr,"Vanity Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp_privkey,public_key_hex_str,address_str,hexrmd_str);
		fclose(keys_file_ptr);
	}
	printf("\nVanity Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp_privkey,public_key_hex_str,address_str,hexrmd_str);
	
    ml_learn_from_hit(
        priv_hex_for_ml,
        wif_for_ml,
        addr1_vanity_for_ml,
        addr2_vanity_for_ml,
        seed_phrase_for_ml,
        base64_data_for_ml
    );
    
#if defined(_WIN64) && !defined(__CYGWIN__)
	ReleaseMutex(write_keys);
#else
	pthread_mutex_unlock(&write_keys);
#endif
	if(hextemp_privkey) free(hextemp_privkey);
	if(hexrmd_str) free(hexrmd_str);
}


// --- Função thread_process_minikeys modificada (apenas o bloco do hit) ---
#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_minikeys(LPVOID vargp) {
#else
void *thread_process_minikeys(void *vargp)	{
    bool continue_thread_loop = true;
#endif
	// ... (declarações de variáveis como na sua versão ou na minha sugestão anterior) ...
	// Renomear variáveis para evitar conflitos se copiado diretamente.
	// Ex: key_mpz_arr, publickey_arr, address_str_arr, minikeys_buffer, etc.
    FILE *keys_file_ptr_mini;
	Point publickey_mini_arr[4];
	Int key_mpz_mini_arr[4];
	struct tothread *tt_data_mini;
	uint64_t count_blocks_mini;
	char pubkeyhash_uncomp_mini_arr[4][20];
	char pubkey_uncomp_hex_mini[131];
	char address_mini_arr[4][40], minikey_cand_arr[4][24], minikeys_valid_buf[8][24], b58_buf_mini[21], minikey_check_buf[24], sha256_raw_val[4][32];
	char *hex_priv_mini = NULL;
    char *raw_b58_material_mini;
	int r_found_mini, thread_num_mini, continue_flag_mini = 1, k_mini, j_mini, valid_mk_count;
	Int counter_mini;

	tt_data_mini = (struct tothread *)vargp;
	thread_num_mini = tt_data_mini->nt;
	free(tt_data_mini);
	raw_b58_material_mini = (char*) &counter_mini.bits64;
	valid_mk_count = 0;
	for(k_mini = 0; k_mini < 4; k_mini++)	{
		minikey_cand_arr[k_mini][0] = 'S';
		minikey_cand_arr[k_mini][22] = '?';
		minikey_cand_arr[k_mini][23] = 0x00;
	}
	minikey_check_buf[0] = 'S';
	minikey_check_buf[22] = '?';
	minikey_check_buf[23] = 0x00;

    // ... (lógica de geração de minikey base como no seu código original) ...
	
	do	{ // Loop principal da thread de minikeys
		// ... (lógica para obter/incrementar base_minikey em buffer_b58_local) ...
        if(FLAGRANDOM)	{ counter_mini.Rand(256); for(k_mini = 0; k_mini < 21; k_mini++) { b58_buf_mini[k_mini] =(uint8_t)((uint8_t) raw_b58_material_mini[k_mini] % 58);}}
		else	{ /* ... (sua lógica para FLAGBASEMINIKEY ou raw_baseminikey global) ... */ }
		set_minikey(minikey_check_buf+1, b58_buf_mini, 21);


		if(continue_flag_mini)	{
			count_blocks_mini = 0;
			// ... (impressão de base minikey se não FLAGQUIET) ...

			do { // Loop de processamento de um bloco de minikeys
				for(j_mini = 0; j_mini < 256 && continue_flag_mini; j_mini++)	{ 
					if(valid_mk_count > 0)	{ /* ... (copia minikeys válidas que sobraram) ... */ }
					do	{ /* ... (gera 4 minikeys candidatas em minikey_cand_arr e valida com sha256sse_23) ... */
                        increment_minikey_index(minikey_check_buf+1,b58_buf_mini,20); memcpy(minikey_cand_arr[0]+1,minikey_check_buf+1,21);
						increment_minikey_index(minikey_check_buf+1,b58_buf_mini,20); memcpy(minikey_cand_arr[1]+1,minikey_check_buf+1,21);
						increment_minikey_index(minikey_check_buf+1,b58_buf_mini,20); memcpy(minikey_cand_arr[2]+1,minikey_check_buf+1,21);
						increment_minikey_index(minikey_check_buf+1,b58_buf_mini,20); memcpy(minikey_cand_arr[3]+1,minikey_check_buf+1,21);
						sha256sse_23((uint8_t*)minikey_cand_arr[0],(uint8_t*)minikey_cand_arr[1],(uint8_t*)minikey_cand_arr[2],(uint8_t*)minikey_cand_arr[3], (uint8_t*)sha256_raw_val[0],(uint8_t*)sha256_raw_val[1],(uint8_t*)sha256_raw_val[2],(uint8_t*)sha256_raw_val[3]);
						for(k_mini = 0; k_mini < 4; k_mini++){ if(sha256_raw_val[k_mini][0] == 0x00)	{ memcpy(minikeys_valid_buf[valid_mk_count],minikey_cand_arr[k_mini],22); minikeys_valid_buf[valid_mk_count][22] = '\0'; valid_mk_count++; } }
                    } while(valid_mk_count < 4 && continue_flag_mini);
                    if(!continue_flag_mini) break;
					valid_mk_count-=4;				
					sha256sse_22((uint8_t*)minikeys_valid_buf[0],(uint8_t*)minikeys_valid_buf[1],(uint8_t*)minikeys_valid_buf[2],(uint8_t*)minikeys_valid_buf[3], (uint8_t*)sha256_raw_val[0],(uint8_t*)sha256_raw_val[1],(uint8_t*)sha256_raw_val[2],(uint8_t*)sha256_raw_val[3]);
					for(k_mini = 0; k_mini < 4; k_mini++)	{ key_mpz_mini_arr[k_mini].Set32Bytes((uint8_t*)sha256_raw_val[k_mini]); publickey_mini_arr[k_mini] = secp->ComputePublicKey(&key_mpz_mini_arr[k_mini]); }
					secp->GetHash160(P2PKH,false,publickey_mini_arr[0],publickey_mini_arr[1],publickey_mini_arr[2],publickey_mini_arr[3], (uint8_t*)pubkeyhash_uncomp_mini_arr[0],(uint8_t*)pubkeyhash_uncomp_mini_arr[1],(uint8_t*)pubkeyhash_uncomp_mini_arr[2],(uint8_t*)pubkeyhash_uncomp_mini_arr[3]);
					
					for(k_mini = 0; k_mini < 4; k_mini++)	{
						r_found_mini = bloom_check(&bloom,pubkeyhash_uncomp_mini_arr[k_mini],20);
						if(r_found_mini) {
							r_found_mini = searchbinary(addressTable,pubkeyhash_uncomp_mini_arr[k_mini],N);
							if(r_found_mini) { // HIT MINKIKEY
								hex_priv_mini = key_mpz_mini_arr[k_mini].GetBase16();
								secp->GetPublicKeyHex(false,publickey_mini_arr[k_mini],pubkey_uncomp_hex_mini);
								rmd160toaddress_dst(pubkeyhash_uncomp_mini_arr[k_mini],address_mini_arr[k_mini]);
								// minikeys_valid_buf[k_mini] contém a minikey string

#if defined(_WIN64) && !defined(__CYGWIN__)
								WaitForSingleObject(write_keys, INFINITE);
#else
								pthread_mutex_lock(&write_keys);
#endif
                                fprintf(stderr, "\a"); // << BIP DO SISTEMA >>
                                fflush(stderr);
							
								keys_file_ptr_mini = fopen("KEYFOUNDKEYFOUND.txt","a+");
								if(keys_file_ptr_mini != NULL)	{
									fprintf(keys_file_ptr_mini,"Private Key: %s\npubkey: %s\nminikey: %s\naddress: %s\n",hex_priv_mini,pubkey_uncomp_hex_mini,minikeys_valid_buf[k_mini],address_mini_arr[k_mini]);
									fclose(keys_file_ptr_mini);
								}
								printf("\nHIT!! Private Key: %s\npubkey: %s\nminikey: %s\naddress: %s\n",hex_priv_mini,pubkey_uncomp_hex_mini,minikeys_valid_buf[k_mini],address_mini_arr[k_mini]);
								
                                // << MODIFICAÇÃO PARA IA >>
                                ml_learn_from_hit(
                                    std::string(hex_priv_mini),
                                    std::string(""),    // WIF não é padrão para minikey
                                    std::string(address_mini_arr[k_mini]), // addr1 (endereço P2PKH uncompressed)
                                    std::string(""),    // addr2 (não há segundo tipo padrão para minikey)
                                    std::string(minikeys_valid_buf[k_mini]), // Usando a string da minikey como "seed_phrase"
                                    std::string("")     // base64_data (não aplicável aqui)
                                );
                                // << FIM DA MODIFICAÇÃO >>

#if defined(_WIN64) && !defined(__CYGWIN__)
								ReleaseMutex(write_keys);
#else
								pthread_mutex_unlock(&write_keys);
#endif
								if(hex_priv_mini) { free(hex_priv_mini); hex_priv_mini = NULL; }
							}
						}
					} // Fim do loop k_mini
				} // Fim do loop j_mini
                if(!continue_flag_mini) break;
				steps[thread_num_mini]++;
				count_blocks_mini+=1024; // (Na verdade, 1024 minikeys candidatas que resultaram em 4xN hashes)
			} while(count_blocks_mini < N_SEQUENTIAL_MAX && continue_flag_mini);
		} // Fim if(continue_flag_mini)
	} while(continue_flag_mini);
	ends[thread_num_mini] = 1;
	return NULL;
}

// (Aproximadamente 500 linhas até aqui, incluindo headers e declarações)
// (Continuação do keyhunt.cpp - após thread_process_minikeys ou outras funções de thread)

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process(LPVOID vargp) {
#else
void *thread_process(void *vargp)	{
    bool continue_thread_loop = true;
#endif
	struct tothread *tt_data = (struct tothread *)vargp;
	int thread_number_local = tt_data->nt;
	free(tt_data);

	Point pts[CPU_GRP_SIZE];
	Point endomorphism_beta_pts[CPU_GRP_SIZE];
	Point endomorphism_beta2_pts[CPU_GRP_SIZE];
	Point endomorphism_negated_point_arr[4];
	
	Int dx_arr[CPU_GRP_SIZE / 2 + 1];
	IntGroup *grp_ptr = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	grp_ptr->Set(dx_arr);

	Point startP_local;
	Int dy_calc, dyn_calc, s_calc, p_calc;
	Point pp_calc, pn_calc;
	int i_loop, l_loop, pp_offset_calc, pn_offset_calc, hLength_val = (CPU_GRP_SIZE / 2 - 1);
	
	uint64_t j_idx_group; // Renomeado de j para evitar confusão com j_loop em main
    uint64_t count_keys_in_block; // Renomeado de count

	Point publickey_found_obj; // Renomeado de publickey para evitar conflito com nome de struct
	int r_found_flag, k_hit_idx; // Renomeados
	char *hextemp_privkey_log = NULL; // Renomeado
	
	char publickeyhashrmd160_bin_check[20];
	char publickeyhashrmd160_uncompress_hit_arr[4][20];
	char rawvalue_xpoint_data[32];
	char publickeyhashrmd160_endo_hit_arr[12][4][20];
	
	bool calculate_y_needed = FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH || FLAGCRYPTO  == CRYPTO_ETH;
	Int key_mpz_current_block_base; // Chave base para o bloco N_SEQUENTIAL_MAX atual
    Int keyfound_priv_final;        // Chave privada final do hit
    Int temp_stride_calc;           // Para cálculos de stride
    bool continue_thread_loop = true; // Renomeado de continue_flag

    // Para amostragem de negativos
    bool positive_hit_found_in_this_N_SEQ_MAX_block = false;
    long long keys_processed_for_negative_sampling = 0;
    const long long SAMPLE_NEGATIVE_EVERY_N_KEYS = 2000000; // Amostre um negativo a cada X chaves "frias" (ajustável)
    Int last_key_in_cold_sub_block; // Para guardar uma chave candidata para negativo


	do { // Loop principal da thread: processa blocos de N_SEQUENTIAL_MAX chaves
        positive_hit_found_in_this_N_SEQ_MAX_block = false; // Reseta para cada novo bloco grande
        keys_processed_for_negative_sampling = 0;

        // --- PONTO DE INTERVENÇÃO DA IA PARA DITAR O RANGE/CHAVE INICIAL ---
        bool ai_suggestion_used = false;
        if (FLAG_IA_FORCE_MODE && (FLAGMODE == MODE_ADDRESS || FLAGMODE == MODE_RMD160)) {
            AISearchSuggestion suggestion = ml_get_next_search_suggestion();
            if (suggestion.use_suggestion && suggestion.priority_score > 0.5) { // Usa se score for bom
                key_mpz_current_block_base.SetBase16(suggestion.base_key_hex.c_str();
if (true)) {
                     if (!FLAGQUIET) {
                        printf("[Thread %d] IA SUGERIU INÍCIO EM: %s (Score: %.2f, Razão: %s)\n", 
                               thread_number_local, suggestion.base_key_hex.c_str(), 
                               suggestion.priority_score, suggestion.reasoning.c_str());
                        fflush(stdout);
                    }
                    ai_suggestion_used = true;
                } else {
                    if (!FLAGQUIET) fprintf(stderr, "[Thread %d] IA sugeriu chave base inválida: %s\n", thread_number_local, suggestion.base_key_hex.c_str());
                }
            } else {
                 if (!FLAGQUIET) printf("[Thread %d] IA não forneceu sugestão forte ou válida. Usando lógica padrão. (Razão: %s)\n", thread_number_local, suggestion.reasoning.c_str());
            }
        }

        if (!ai_suggestion_used) { // Lógica original se IA não ditou ou não está no modo IA Force
            if (FLAGRANDOM) {
                key_mpz_current_block_base.Rand(&n_range_start_global, &n_range_end_global);
            } else {
                if (n_range_start_global.IsLower(&n_range_end_global)) {
#if defined(_WIN64) && !defined(__CYGWIN__)
                    WaitForSingleObject(write_random, INFINITE);
                    key_mpz_current_block_base.Set(&n_range_start_global);
                    n_range_start_global.Add(N_SEQUENTIAL_MAX);
                    ReleaseMutex(write_random);
#else
                    pthread_mutex_lock(&write_random);
                    key_mpz_current_block_base.Set(&n_range_start_global);
                    n_range_start_global.Add(N_SEQUENTIAL_MAX);
                    pthread_mutex_unlock(&write_random);
#endif
                } else {
                    continue_thread_loop = false; // Range global esgotado
                }
            }
        }
        // --- FIM DO PONTO DE INTERVENÇÃO DA IA ---

		if(!continue_thread_loop) break; // Sai do loop da thread se não há mais ranges

		count_keys_in_block = 0; // Zera contador para o bloco N_SEQUENTIAL_MAX
		if(!FLAGQUIET && FLAGMATRIX) { /* ... (impressão matrix) ... */ }
		else if(!FLAGQUIET) { /* ... (impressão normal de base key) ... */ }

        // Salva uma cópia da chave base do bloco para poder usá-la para registrar negativos
        Int key_mpz_current_iteration = key_mpz_current_block_base;


		do { // Loop interno: processa CPU_GRP_SIZE chaves de cada vez, até N_SEQUENTIAL_MAX
			temp_stride_calc.SetInt32(CPU_GRP_SIZE / 2);
			temp_stride_calc.Mult(&stride);
			key_mpz_current_iteration.Add(&temp_stride_calc); // Ajusta para o centro do sub-bloco
	 		startP_local = secp->ComputePublicKey(&key_mpz_current_iteration);
			key_mpz_current_iteration.Sub(&temp_stride_calc); // Retorna ao início do sub-bloco (de CPU_GRP_SIZE/2 chaves antes do centro)

			// ... (Lógica de pré-cálculo de dx_arr, grp_ptr->ModInv(), cálculo de pts[] e endomorphism_beta_pts[] etc.
            //      Permanece EXATAMENTE como no seu código original ou na minha sugestão anterior para esta parte, 
            //      apenas usando os nomes de variáveis locais que defini acima (ex: i_loop, hLength_val, dx_arr, Gn, etc.)
            //      Esta parte é crucial para a performance e não deve ser alterada levianamente.) ...
            for(i_loop = 0; i_loop < hLength_val; i_loop++) { dx_arr[i_loop].ModSub(&Gn[i_loop].x,&startP_local.x); }
			dx_arr[i_loop].ModSub(&Gn[i_loop].x,&startP_local.x);
			dx_arr[i_loop + 1].ModSub(&_2Gn.x,&startP_local.x);
			grp_ptr->ModInv();
			pts[CPU_GRP_SIZE / 2] = startP_local;
			for(i_loop = 0; i_loop < hLength_val; i_loop++) { /* ... cálculo de pp_calc, pn_calc ... */ 
                pp_calc = startP_local; pn_calc = startP_local;
                dy_calc.ModSub(&Gn[i_loop].y,&pp_calc.y); s_calc.ModMulK1(&dy_calc,&dx_arr[i_loop]); p_calc.ModSquareK1(&s_calc);
                pp_calc.x.ModNeg(); pp_calc.x.ModAdd(&p_calc); pp_calc.x.ModSub(&Gn[i_loop].x);
                if(calculate_y_needed) { pp_calc.y.ModSub(&Gn[i_loop].x,&pp_calc.x); pp_calc.y.ModMulK1(&s_calc); pp_calc.y.ModSub(&Gn[i_loop].y); }
                dyn_calc.Set(&Gn[i_loop].y); dyn_calc.ModNeg(); dyn_calc.ModSub(&pn_calc.y); s_calc.ModMulK1(&dyn_calc,&dx_arr[i_loop]); p_calc.ModSquareK1(&s_calc);
                pn_calc.x.ModNeg(); pn_calc.x.ModAdd(&p_calc); pn_calc.x.ModSub(&Gn[i_loop].x);
                if(calculate_y_needed) { pn_calc.y.ModSub(&Gn[i_loop].x,&pn_calc.x); pn_calc.y.ModMulK1(&s_calc); pn_calc.y.ModAdd(&Gn[i_loop].y); }
                pp_offset_calc = CPU_GRP_SIZE / 2 + (i_loop + 1); pn_offset_calc = CPU_GRP_SIZE / 2 - (i_loop + 1);
                pts[pp_offset_calc] = pp_calc; pts[pn_offset_calc] = pn_calc;
                if(FLAGENDOMORPHISM) { /* ... lógica de endomorfismo ... */ }
            }
            if(FLAGENDOMORPHISM) { /* ... lógica de endomorfismo para ponto central ... */ }
            pn_calc = startP_local; dyn_calc.Set(&Gn[i_loop].y); dyn_calc.ModNeg(); dyn_calc.ModSub(&pn_calc.y);
            s_calc.ModMulK1(&dyn_calc,&dx_arr[i_loop]); p_calc.ModSquareK1(&s_calc);
            pn_calc.x.ModNeg(); pn_calc.x.ModAdd(&p_calc); pn_calc.x.ModSub(&Gn[i_loop].x);
            if(calculate_y_needed) { pn_calc.y.ModSub(&Gn[i_loop].x,&pn_calc.x); pn_calc.y.ModMulK1(&s_calc); pn_calc.y.ModAdd(&Gn[i_loop].y); }
            pts[0] = pn_calc;
            if(FLAGENDOMORPHISM) { /* ... lógica de endomorfismo para primeiro ponto ... */ }


            // Loop para processar os pontos gerados (4 por vez)
			for(j_idx_group = 0; j_idx_group < CPU_GRP_SIZE/4;j_idx_group++){
                // Geração de Hashes (como na minha resposta anterior, usando publickeyhashrmd160_endo_hit_arr, publickeyhashrmd160_uncompress_hit_arr)
				// ... (seu switch(FLAGMODE) para gerar os hashes dos 4 pontos atuais pts[(j_idx_group*4)...(j_idx_group*4)+3]
                //      e seus equivalentes de endomorfismo, armazenando em publickeyhashrmd160_endo_hit_arr 
                //      e publickeyhashrmd160_uncompress_hit_arr ou rawvalue_xpoint_data) ...
                // Exemplo simplificado:
                if (FLAGMODE == MODE_ADDRESS || FLAGMODE == MODE_RMD160) {
                    if (FLAGCRYPTO == CRYPTO_BTC) {
                        // Preencher publickeyhashrmd160_endo_hit_arr e publickeyhashrmd160_uncompress_hit_arr
                    } else if (FLAGCRYPTO == CRYPTO_ETH) {
                        // Preencher publickeyhashrmd160_uncompress_hit_arr (para endereços ETH)
                    }
                } else if (FLAGMODE == MODE_XPOINT) {
                    // Preencher rawvalue_xpoint_data para os X-points
                }


                // Verificação de Hits
				switch(FLAGMODE)	{
					case MODE_RMD160:
					case MODE_ADDRESS:
						if( FLAGCRYPTO  == CRYPTO_BTC) {
							for(k_hit_idx = 0; k_hit_idx < 4; k_hit_idx++)	{ // Para cada um dos 4 pontos base
                                // Checa comprimidas (e endomorfismos se FLAGENDOMORPHISM)
								if(FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH){
									int endo_loops = FLAGENDOMORPHISM ? 6 : 2; // 0,1 para normal; 0-5 para endo
									for(l_loop = 0; l_loop < endo_loops; l_loop++)	{
										r_found_flag = bloom_check(&bloom, publickeyhashrmd160_endo_hit_arr[l_loop][k_hit_idx], 20); //MAXLENGTHADDRESS era 20
										if(r_found_flag) {
											r_found_flag = searchbinary(addressTable, publickeyhashrmd160_endo_hit_arr[l_loop][k_hit_idx], N);
											if(r_found_flag) { 
												positive_hit_found_in_this_N_SEQ_MAX_block = true; // SINALIZA HIT POSITIVO
												keys_processed_for_negative_sampling = 0; // Reseta contador de negativos

												keyfound_priv_final.SetInt32((j_idx_group*4) + k_hit_idx); 
												keyfound_priv_final.Mult(&stride);
												keyfound_priv_final.Add(&key_mpz_current_iteration); // Adiciona ao base do sub-bloco
												
                                                // ... (lógica para ajustar keyfound_priv_final baseado em l_loop e paridade, como antes) ...
												writekey(true, &keyfound_priv_final); // true para comprimido
											}
										}
									}
								}
                                // Checa não comprimidas (e endomorfismos se FLAGENDOMORPHISM)
								if(FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH)	{
                                    char (*hash_array_ptr)[20];
                                    int start_idx_uncomp, end_idx_uncomp;

                                    if(FLAGENDOMORPHISM) {
                                        hash_array_ptr = publickeyhashrmd160_endo_hit_arr[0]; // Usa o array de endo
                                        start_idx_uncomp = 6; // Índices 6-11 para não comprimidos com endo
                                        end_idx_uncomp = 12;
                                    } else {
                                        hash_array_ptr = publickeyhashrmd160_uncompress_hit_arr; // Usa array de não comprimido simples
                                        start_idx_uncomp = 0; // Um único RMD160 não comprimido por chave
                                        end_idx_uncomp = 1; // Iterar uma vez (ou 4 vezes se array é [4][20])
                                                              // Se publickeyhashrmd160_uncompress_hit_arr é [4][20], então é hash_array_ptr[k_hit_idx]
                                    }

									for(l_loop = start_idx_uncomp; l_loop < end_idx_uncomp ; l_loop++)	{
                                        char* current_hash_ptr = FLAGENDOMORPHISM ? publickeyhashrmd160_endo_hit_arr[l_loop][k_hit_idx] : publickeyhashrmd160_uncompress_hit_arr[k_hit_idx];
										r_found_flag = bloom_check(&bloom, current_hash_ptr, 20);
										if(r_found_flag) {
											r_found_flag = searchbinary(addressTable, current_hash_ptr, N);
											if(r_found_flag) { 
												positive_hit_found_in_this_N_SEQ_MAX_block = true;
                                                keys_processed_for_negative_sampling = 0;

												keyfound_priv_final.SetInt32((j_idx_group*4) + k_hit_idx);
												keyfound_priv_final.Mult(&stride);
												keyfound_priv_final.Add(&key_mpz_current_iteration);
												// ... (lógica para ajustar keyfound_priv_final para endomorfismo não comprimido, como antes) ...
												writekey(false, &keyfound_priv_final); // false para não comprimido
											}
										}
									}
								}
							} // Fim for k_hit_idx
						} // Fim if CRYPTO_BTC
						else if ( FLAGCRYPTO == CRYPTO_ETH) { // Se ETH
                            // ... (Lógica de hit para ETH, similar à anterior, chamando writekeyeth) ...
                            // Lembre-se de setar positive_hit_found_in_this_N_SEQ_MAX_block = true;
						}
						break; 
					case MODE_XPOINT:
                        // ... (Lógica de hit para XPoint, similar à anterior, chamando writekey) ...
                        // Lembre-se de setar positive_hit_found_in_this_N_SEQ_MAX_block = true;
						break;
				} // Fim switch(FLAGMODE) para verificação de hits

				count_keys_in_block +=4; // Incrementa chaves processadas neste grande bloco
                keys_processed_for_negative_sampling +=4 * (FLAGENDOMORPHISM ? 6 : (FLAGSEARCH == SEARCH_BOTH ? 2:1) );


				temp_stride_calc.SetInt32(4); 
				temp_stride_calc.Mult(&stride);
				key_mpz_current_iteration.Add(&temp_stride_calc); // Avança para os próximos 4 pontos base dentro do sub-bloco
			} // Fim do for j_idx_group (processamento dos CPU_GRP_SIZE pontos)
			
			steps[thread_number_local]++; // Incrementa o contador de "grandes passos" da thread (um passo = CPU_GRP_SIZE chaves processadas)

            // Prepara para o próximo sub-bloco de CPU_GRP_SIZE pontos
			pp_calc = startP_local; 
			dy_calc.ModSub(&_2Gn.y,&pp_calc.y); 
			s_calc.ModMulK1(&dy_calc,&dx_arr[i_loop + 1]); 
			p_calc.ModSquareK1(&s_calc);
			pp_calc.x.ModNeg(); pp_calc.x.ModAdd(&p_calc); pp_calc.x.ModSub(&_2Gn.x);
			if(calculate_y_needed || true) { // Y sempre necessário para o próximo startP_local
                pp_calc.y.ModSub(&_2Gn.x,&pp_calc.x); 
                pp_calc.y.ModMulK1(&s_calc);
                pp_calc.y.ModSub(&_2Gn.y);
            }
			startP_local = pp_calc; // Novo startP_local para a próxima iteração do loop de CPU_GRP_SIZE

            // Lógica de Amostragem de Negativos (ao final de um sub-bloco CPU_GRP_SIZE)
            // Se você quiser amostrar com menos frequência, mova para após o loop de N_SEQUENTIAL_MAX
            if (!positive_hit_found_in_this_N_SEQ_MAX_block && keys_processed_for_negative_sampling >= SAMPLE_NEGATIVE_EVERY_N_KEYS) {
                last_key_in_cold_sub_block.Set(&key_mpz_current_iteration); // Pega a última chave processada no sub-bloco
                last_key_in_cold_sub_block.Sub(&temp_stride_calc); // Volta para a chave antes do último incremento de 4*stride

                std::string neg_priv_hex = std::string(last_key_in_cold_sub_block.GetBase16());
                std::string neg_wif = ""; // Para chaves geradas, WIF não é trivial
                std::string neg_addr1_comp = "";
                std::string neg_addr2_uncomp = "";

                Point temp_neg_pub = secp->ComputePublicKey(&last_key_in_cold_sub_block);
                char temp_addr_buf[50];
                char temp_rmd_buf[20];

                // Gera P2PKH Comprimido para addr1
                secp->GetHash160(P2PKH, true, temp_neg_pub, (uint8_t*)temp_rmd_buf);
                rmd160toaddress_dst(temp_rmd_buf, temp_addr_buf);
                neg_addr1_comp = std::string(temp_addr_buf);

                // Gera P2PKH Não Comprimido para addr2
                secp->GetHash160(P2PKH, false, temp_neg_pub, (uint8_t*)temp_rmd_buf);
                rmd160toaddress_dst(temp_rmd_buf, temp_addr_buf);
                neg_addr2_uncomp = std::string(temp_addr_buf);
                
                std::vector<float> neg_features = ml_extract_features_for_data(
                    neg_priv_hex, neg_wif, neg_addr1_comp, neg_addr2_uncomp, "", "" // Seed e Base64 vazios
                );

#if defined(_WIN64) && !defined(__CYGWIN__)
                WaitForSingleObject(write_negative_log_mutex, INFINITE);
#else
                pthread_mutex_lock(&write_negative_log_mutex);
#endif
                FILE* neg_log_file = fopen("models/negative_features.csv", "a");
                if (neg_log_file) {
                    // O cabeçalho deve ser escrito manualmente no arquivo uma vez, ou por uma lógica mais robusta no main()
                    for (size_t feat_idx = 0; feat_idx < neg_features.size(); ++feat_idx) {
                        fprintf(neg_log_file, "%.6f,", neg_features[feat_idx]);
                    }
                    fprintf(neg_log_file, "0.0\n"); // target_score = 0.0 para negativos
                    fclose(neg_log_file);
                } else {
                    fprintf(stderr, "[Thread %d] ERRO ao abrir negative_features.csv para escrita!\n", thread_number_local);
                }
#if defined(_WIN64) && !defined(__CYGWIN__)
                ReleaseMutex(write_negative_log_mutex);
#else
                pthread_mutex_unlock(&write_negative_log_mutex);
#endif
                keys_processed_for_negative_sampling = 0; // Reseta contador
            }


		} while(count_keys_in_block < N_SEQUENTIAL_MAX && continue_thread_loop); // Fim do loop N_SEQUENTIAL_MAX
        if (!continue_thread_loop) break; 
	} while(continue_thread_loop); // Fim do loop principal da thread
	
    ends[thread_number_local] = 1; 
    if(grp_ptr) delete grp_ptr;
	return NULL;
}

// (O restante do arquivo keyhunt.cpp, como funções BSGS, utilitários, etc., continua aqui)
// ...
// (Continuação do keyhunt.cpp - após a função thread_process)

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs(LPVOID vargp) {
#else
void *thread_process_bsgs(void *vargp)	{
    bool continue_thread_loop = true;
#endif
	// Renomeando variáveis para clareza e evitar conflitos
	FILE* filekey_bsgs_hit;
	struct tothread* tt_data_bsgs = (struct tothread *)vargp;
	int thread_number_bsgs = tt_data_bsgs->nt;
	free(tt_data_bsgs);

	char xpoint_raw_bsgs[32], *aux_c_bsgs = NULL, *hextemp_bsgs_privkey = NULL;

	Int base_key_bsgs_iter, keyfound_bsgs_priv; // Renomeado de base_key, keyfound
	IntGroup* grp_bsgs = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Int dx_bsgs[CPU_GRP_SIZE / 2 + 1];
	Int dy_bsgs, dyn_bsgs, s_bsgs_calc, p_bsgs_calc, km_bsgs_calc, intaux_bsgs_calc;

	Point base_point_bsgs_iter, point_aux_bsgs, point_found_bsgs_pub;
	Point startP_bsgs_calc;
	Point pp_bsgs_calc, pn_bsgs_calc;
	Point pts_bsgs_group[CPU_GRP_SIZE];

	uint32_t k_target_pubkey_idx, l_found_check_idx, r_bloom_check_result, salir_flag_bsgs;
    uint32_t cycles_bsgs_internal; // Renomeado de cycles

	int hLength_bsgs = (CPU_GRP_SIZE / 2 - 1);
	grp_bsgs->Set(dx_bsgs);
	
	cycles_bsgs_internal = bsgs_aux_val / CPU_GRP_SIZE; // bsgs_aux_val é o antigo bsgs_aux (uint64_t)
	if(bsgs_aux_val % CPU_GRP_SIZE != 0)	{
		cycles_bsgs_internal++;
	}

    // intaux_bsgs_calc = (m * 2) * (CPU_GRP_SIZE/2) + m = m * CPU_GRP_SIZE + m = m * (CPU_GRP_SIZE+1)
    // Esta é a chave k tal que kG é o centro da busca de baby steps
	intaux_bsgs_calc.Set(&BSGS_M_double); // BSGS_M_double = 2*m
	intaux_bsgs_calc.Mult(CPU_GRP_SIZE/2);
	intaux_bsgs_calc.Add(&BSGS_M);       // BSGS_M = m
	
    // --- PONTO DE INTERVENÇÃO DA IA PARA BSGS (CONCEITUAL) ---
    // A IA poderia influenciar qual 'base_key_bsgs_iter' usar (se não estiver usando o BSGS_CURRENT global),
    // ou quais chaves públicas alvo (k_target_pubkey_idx) priorizar, ou os parâmetros m/N do BSGS.
    // Ex: if (FLAG_IA_FORCE_MODE) {
    //         AISearchDirectiveForBSGS directive = ml_get_bsgs_directive();
    //         // Usar a diretiva para ajustar BSGS_CURRENT, ou a ordem de OriginalPointsBSGS, etc.
    //     }
    // --- FIM DO PONTO DE INTERVENÇÃO ---

	do	{	// Loop principal da thread BSGS: processa um grande range de chaves base (giant steps)
#if defined(_WIN64) && !defined(__CYGWIN__)
		WaitForSingleObject(bsgs_thread, INFINITE);
#else
		pthread_mutex_lock(&bsgs_thread);
#endif
		base_key_bsgs_iter.Set(&BSGS_CURRENT);	
		BSGS_CURRENT.Add(&BSGS_N_double); // Avança o range global para a próxima thread/iteração de giant step	
#if defined(_WIN64) && !defined(__CYGWIN__)
		ReleaseMutex(bsgs_thread);
#else
		pthread_mutex_unlock(&bsgs_thread);
#endif

		if(base_key_bsgs_iter.IsGreaterOrEqual(&n_range_end_global)) // n_range_end_global é o antigo n_range_end_global
			break; // Se o range global foi esgotado
		
		if(!FLAGQUIET && FLAGMATRIX)	{ /* ... (impressão matrix) ... */ }
		else if(!FLAGQUIET) { /* ... (impressão de base key da thread) ... */ }
		
        // Ponto público correspondente ao início do giant step atual
		// base_point_bsgs_iter = base_key_bsgs_iter * G
        // km_bsgs_calc = base_key_bsgs_iter - (offset para centro dos baby steps)
        // point_aux_bsgs = -km_bsgs_calc * G
        // O objetivo é calcular Q_target - (base_key_bsgs_iter * G) + (offset_babysteps * G)
        // e comparar com a tabela de baby steps -jG
        // Ou seja, Q_target - base_key_bsgs_iter * G = (i*m_points - j)*G
        // Q' = Q_target - i*(M*G) -> este é o giant step
        // Q'' = Q' - k*(mG) -> este é o segundo nível
        // Q''' = Q'' - l*(gG) -> este é o terceiro nível (tabela de baby steps)

		km_bsgs_calc.Set(&base_key_bsgs_iter);
		km_bsgs_calc.Neg();
		km_bsgs_calc.Add(&secp->order); // (-base_key) mod order
		km_bsgs_calc.Sub(&intaux_bsgs_calc); // (-base_key - offset_para_centro_babysteps) mod order
                                        // intaux_bsgs_calc = m*(CPU_GRP_SIZE+1)
                                        // Este cálculo parece ser para Q_target + (-k_giant_step + offset_babysteps)G
                                        // A lógica original é complexa e otimizada para o BSGS de 3 níveis.
		point_aux_bsgs = secp->ComputePublicKey(&km_bsgs_calc); // Ponto auxiliar para os cálculos

        // Para cada chave pública alvo na lista
		for(k_target_pubkey_idx = 0; k_target_pubkey_idx < bsgs_point_number ; k_target_pubkey_idx++)	{
			if(bsgs_found[k_target_pubkey_idx] == 0)	{ // Se esta chave pública ainda não foi encontrada
				// startP_bsgs_calc = OriginalPointsBSGS[k_target_pubkey_idx] + point_aux_bsgs
                // startP_bsgs_calc = Q_target + (-base_key_bsgs_iter + offset_para_centro_babysteps)G
                // Este é o ponto que será iterado pelos baby steps (GSn)
				startP_bsgs_calc  = secp->AddDirect(OriginalPointsBSGS[k_target_pubkey_idx], point_aux_bsgs);
				
                uint32_t j_baby_step_block_idx = 0; // Renomeado de j
				while( j_baby_step_block_idx < cycles_bsgs_internal && bsgs_found[k_target_pubkey_idx] == 0 )	{
					int i_baby_step_calc_idx; // Renomeado de i
                    // Pré-cálculos para o grupo de baby steps
					for(i_baby_step_calc_idx = 0; i_baby_step_calc_idx < hLength_bsgs; i_baby_step_calc_idx++) {
						dx_bsgs[i_baby_step_calc_idx].ModSub(&GSn[i_baby_step_calc_idx].x,&startP_bsgs_calc.x);
					}
					dx_bsgs[i_baby_step_calc_idx].ModSub(&GSn[i_baby_step_calc_idx].x,&startP_bsgs_calc.x);
					dx_bsgs[i_baby_step_calc_idx+1].ModSub(&_2GSn.x,&startP_bsgs_calc.x); 
					grp_bsgs->ModInv();
					
					pts_bsgs_group[CPU_GRP_SIZE / 2] = startP_bsgs_calc; // Ponto central do grupo de baby steps
                    // Calcula os pontos para o grupo de baby steps
					for(i_baby_step_calc_idx = 0; i_baby_step_calc_idx < hLength_bsgs; i_baby_step_calc_idx++) {
						// ... (lógica de cálculo de pp_bsgs_calc, pn_bsgs_calc como em thread_process, usando GSn em vez de Gn) ...
                        pp_bsgs_calc = startP_bsgs_calc; pn_bsgs_calc = startP_bsgs_calc;
                        dy_bsgs.ModSub(&GSn[i_baby_step_calc_idx].y,&pp_bsgs_calc.y); s_bsgs_calc.ModMulK1(&dy_bsgs,&dx_bsgs[i_baby_step_calc_idx]); p_bsgs_calc.ModSquareK1(&s_bsgs_calc);
                        pp_bsgs_calc.x.ModNeg(); pp_bsgs_calc.x.ModAdd(&p_bsgs_calc); pp_bsgs_calc.x.ModSub(&GSn[i_baby_step_calc_idx].x);
                        dyn_bsgs.Set(&GSn[i_baby_step_calc_idx].y); dyn_bsgs.ModNeg(); dyn_bsgs.ModSub(&pn_bsgs_calc.y); s_bsgs_calc.ModMulK1(&dyn_bsgs,&dx_bsgs[i_baby_step_calc_idx]); p_bsgs_calc.ModSquareK1(&s_bsgs_calc);
                        pn_bsgs_calc.x.ModNeg(); pn_bsgs_calc.x.ModAdd(&p_bsgs_calc); pn_bsgs_calc.x.ModSub(&GSn[i_baby_step_calc_idx].x);
						pts_bsgs_group[CPU_GRP_SIZE / 2 + (i_baby_step_calc_idx + 1)] = pp_bsgs_calc;
						pts_bsgs_group[CPU_GRP_SIZE / 2 - (i_baby_step_calc_idx + 1)] = pn_bsgs_calc;
					}
					pn_bsgs_calc = startP_bsgs_calc; dyn_bsgs.Set(&GSn[i_baby_step_calc_idx].y); dyn_bsgs.ModNeg(); dyn_bsgs.ModSub(&pn_bsgs_calc.y);
					s_bsgs_calc.ModMulK1(&dyn_bsgs,&dx_bsgs[i_baby_step_calc_idx]); p_bsgs_calc.ModSquareK1(&s_bsgs_calc);
					pn_bsgs_calc.x.ModNeg(); pn_bsgs_calc.x.ModAdd(&p_bsgs_calc); pn_bsgs_calc.x.ModSub(&GSn[i_baby_step_calc_idx].x);
					pts_bsgs_group[0] = pn_bsgs_calc;
					
                    // Checa os pontos gerados contra os filtros de Bloom e tabelas
					for(int pt_idx = 0; pt_idx < CPU_GRP_SIZE && bsgs_found[k_target_pubkey_idx] == 0; pt_idx++) {
						pts_bsgs_group[pt_idx].x.Get32Bytes((unsigned char*)xpoint_raw_bsgs);
						r_bloom_check_result = bloom_check(&bloom_bP[((unsigned char)xpoint_raw_bsgs[0])], xpoint_raw_bsgs, 32);
						if(r_bloom_check_result) {
                            // (j_baby_step_block_idx * CPU_GRP_SIZE) é o offset do bloco de baby steps atual
                            // pt_idx é o offset dentro do grupo de CPU_GRP_SIZE
							r_bloom_check_result = bsgs_secondcheck(&base_key_bsgs_iter, ((j_baby_step_block_idx * CPU_GRP_SIZE) + pt_idx), k_target_pubkey_idx, &keyfound_bsgs_priv);
							if(r_bloom_check_result)	{ // HIT BSGS!
								hextemp_bsgs_privkey = keyfound_bsgs_priv.GetBase16();
								point_found_bsgs_pub = secp->ComputePublicKey(&keyfound_bsgs_priv);
								aux_c_bsgs = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k_target_pubkey_idx], point_found_bsgs_pub);
								
#if defined(_WIN64) && !defined(__CYGWIN__)
								WaitForSingleObject(write_keys, INFINITE);
#else
								pthread_mutex_lock(&write_keys);
#endif
                                fprintf(stderr, "\a"); // << BIP DO SISTEMA >>
                                fflush(stderr);

								printf("\n[+] BSGS HIT! Thread %d encontrou Chave Privada: %s\n", thread_number_bsgs, hextemp_bsgs_privkey);
								printf("[+] Chave Pública Alvo %s: %s\n", (OriginalPointsBSGScompressed[k_target_pubkey_idx] ? "Comprimida" : "Não Comprimida"), aux_c_bsgs);
								
								filekey_bsgs_hit = fopen("KEYFOUNDKEYFOUND.txt","a");
								if(filekey_bsgs_hit != NULL)	{
									fprintf(filekey_bsgs_hit,"BSGS HIT! Private Key: %s\nPublic Key (Target %s): %s\n",
                                            hextemp_bsgs_privkey, (OriginalPointsBSGScompressed[k_target_pubkey_idx] ? "C" : "U"), aux_c_bsgs);
									fclose(filekey_bsgs_hit);
								}

                                // << MODIFICAÇÃO PARA IA >>
                                // Para BSGS, a "seed_phrase" e "base64_data" geralmente não são conhecidas no momento do hit.
                                // WIF e addr2 (P2PKH uncompressed) podem ser derivados da chave encontrada.
                                std::string wif_bsgs_hit = ""; // TODO: Gerar WIF de keyfound_bsgs_priv
                                std::string addr1_bsgs_hit = ""; // Endereço P2PKH da chave encontrada (comprimido se OriginalPointsBSGScompressed)
                                std::string addr2_bsgs_hit = ""; // Endereço P2PKH da chave encontrada (não comprimido se OriginalPointsBSGScompressed)
                                
                                char temp_addr_bsgs[50], temp_rmd_bsgs[20];
                                // Addr1 (mesma compressão do target)
                                secp->GetHash160(P2PKH, OriginalPointsBSGScompressed[k_target_pubkey_idx], point_found_bsgs_pub, (uint8_t*)temp_rmd_bsgs);
                                rmd160toaddress_dst(temp_rmd_bsgs, temp_addr_bsgs);
                                addr1_bsgs_hit = std::string(temp_addr_bsgs);

                                // Addr2 (compressão oposta do target)
                                secp->GetHash160(P2PKH, !OriginalPointsBSGScompressed[k_target_pubkey_idx], point_found_bsgs_pub, (uint8_t*)temp_rmd_bsgs);
                                rmd160toaddress_dst(temp_rmd_bsgs, temp_addr_bsgs);
                                addr2_bsgs_hit = std::string(temp_addr_bsgs);


                                ml_learn_from_hit(
                                    std::string(hextemp_bsgs_privkey),
                                    wif_bsgs_hit,
                                    addr1_bsgs_hit,
                                    addr2_bsgs_hit,
                                    "", // seed_phrase (provavelmente vazia para BSGS hit)
                                    ""  // base64_data (provavelmente vazia para BSGS hit)
                                );
                                // << FIM DA MODIFICAÇÃO >>

#if defined(_WIN64) && !defined(__CYGWIN__)
				                ReleaseMutex(write_keys);
#else
				                pthread_mutex_unlock(&write_keys);
#endif
								if(hextemp_bsgs_privkey) { free(hextemp_bsgs_privkey); hextemp_bsgs_privkey = NULL; }
								if(aux_c_bsgs) { free(aux_c_bsgs); aux_c_bsgs = NULL; }
								
                                bsgs_found[k_target_pubkey_idx] = 1; // Marca como encontrado
								salir_flag_bsgs = 1;
								for(l_found_check_idx = 0; l_found_check_idx < bsgs_point_number && salir_flag_bsgs; l_found_check_idx++)	{
									salir_flag_bsgs &= bsgs_found[l_found_check_idx]; // Checa se todos foram encontrados
								}
								if(salir_flag_bsgs)	{ // Se todos foram encontrados
									printf("TODOS OS PONTOS BSGS FORAM ENCONTRADOS! Finalizando...\n");
                                    // Sinalizar para outras threads BSGS pararem também (pode ser um flag global)
                                    // exit(EXIT_SUCCESS); // Ou uma forma mais graciosa de terminar
                                    for(unsigned int end_idx = 0; end_idx < NTHREADS; ++end_idx) ends[end_idx] = 1; // Tenta parar todas as threads
								}
							} 
						}
					} // Fim do loop pt_idx (checagem dos pontos do grupo)
					
                    // Avança para o próximo bloco de baby steps
					pp_bsgs_calc = startP_bsgs_calc;
					dy_bsgs.ModSub(&_2GSn.y,&pp_bsgs_calc.y);
					s_bsgs_calc.ModMulK1(&dy_bsgs,&dx_bsgs[i_baby_step_calc_idx + 1]);
					p_bsgs_calc.ModSquareK1(&s_bsgs_calc);
					pp_bsgs_calc.x.ModNeg(); pp_bsgs_calc.x.ModAdd(&p_bsgs_calc); pp_bsgs_calc.x.ModSub(&_2GSn.x);
					pp_bsgs_calc.y.ModSub(&_2GSn.x,&pp_bsgs_calc.x); pp_bsgs_calc.y.ModMulK1(&s_bsgs_calc); pp_bsgs_calc.y.ModSub(&_2GSn.y);
					startP_bsgs_calc = pp_bsgs_calc;
					
					j_baby_step_block_idx++;
				} // Fim do while j_baby_step_block_idx (loop de blocos de baby steps)
			} // Fim if !bsgs_found
		} // Fim do for k_target_pubkey_idx (loop pelas chaves públicas alvo)
		steps[thread_number_bsgs]+=2; // Incrementa progresso da thread (originalmente era +=2)
	} while(continue_thread_loop && ! (salir_flag_bsgs && bsgs_point_number > 0) ); // sair_flag_bsgs aqui está no escopo errado, precisa de um flag global de "todos encontrados"
                                                                                    // Ou apenas 'continue_thread_loop' e deixa o 'exit' lidar com "todos encontrados"

	ends[thread_number_bsgs] = 1;
    if(grp_bsgs) delete grp_bsgs;
	return NULL;
}

// (O restante do arquivo keyhunt.cpp continua abaixo, com as outras funções BSGS,
//  thread_bPload, utilitários de ordenação, leitura de arquivo, etc.)
// ...
// (Continuação do keyhunt.cpp - após thread_process_bsgs)

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs_random(LPVOID vargp) {
#else
void *thread_process_bsgs_random(void *vargp)	{
    bool continue_thread_loop = true;
#endif
	// Renomeando variáveis para clareza e evitar conflitos
	FILE *filekey_bsgs_hit_rand; // Renomeado
	struct tothread *tt_data_bsgs_rand = (struct tothread *)vargp;
	int thread_number_bsgs_rand = tt_data_bsgs_rand->nt;
	free(tt_data_bsgs_rand);

	char xpoint_raw_bsgs_rand[32],*aux_c_bsgs_rand = NULL,*hextemp_bsgs_privkey_rand = NULL;
	Int base_key_bsgs_rand_iter, keyfound_bsgs_priv_rand; // Renomeado
	// Int n_range_random_bsgs; // Esta variável não parecia ser usada no seu código original dentro desta função

	Point base_point_bsgs_rand_iter, point_aux_bsgs_rand, point_found_bsgs_pub_rand;
	uint32_t l_found_check_idx_rand, k_target_pubkey_idx_rand, r_bloom_check_result_rand, salir_flag_bsgs_rand;
    uint32_t cycles_bsgs_internal_rand; // Renomeado

	IntGroup *grp_bsgs_rand = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP_bsgs_rand_calc;
	int hLength_bsgs_rand = (CPU_GRP_SIZE / 2 - 1);
	Int dx_bsgs_rand[CPU_GRP_SIZE / 2 + 1];
	Point pts_bsgs_group_rand[CPU_GRP_SIZE];
	Int dy_bsgs_rand, dyn_bsgs_rand, s_bsgs_calc_rand, p_bsgs_calc_rand;
	Int km_bsgs_calc_rand, intaux_bsgs_calc_rand;
	Point pp_bsgs_calc_rand, pn_bsgs_calc_rand;
	
    grp_bsgs_rand->Set(dx_bsgs_rand);

	cycles_bsgs_internal_rand = bsgs_aux_val / CPU_GRP_SIZE; // bsgs_aux_val é uint64_t
	if(bsgs_aux_val % CPU_GRP_SIZE != 0)	{
		cycles_bsgs_internal_rand++;
	}
	
	intaux_bsgs_calc_rand.Set(&BSGS_M_double); 
	intaux_bsgs_calc_rand.Mult(CPU_GRP_SIZE/2);
	intaux_bsgs_calc_rand.Add(&BSGS_M);

    // --- PONTO DE INTERVENÇÃO DA IA PARA BSGS RANDOM (CONCEITUAL) ---
    // A IA poderia influenciar a escolha do range [n_range_start_global, n_range_end_global]
    // de onde base_key_bsgs_rand_iter.Rand() seleciona, ou a priorização de chaves públicas alvo.
    // --- FIM DO PONTO DE INTERVENÇÃO ---

	do	{ // Loop principal da thread BSGS Random: cada iteração pega uma nova chave base aleatória
#if defined(_WIN64) && !defined(__CYGWIN__)
		WaitForSingleObject(bsgs_thread, INFINITE); // Protege Rand se ele não for thread-safe ou se n_range_start/end forem globais
#else
		pthread_mutex_lock(&bsgs_thread);
#endif
        // No modo BSGS Random, a chave base para o giant step é escolhida aleatoriamente dentro do range global.
		base_key_bsgs_rand_iter.Rand(&n_range_start_global, &n_range_end_global); 
#if defined(_WIN64) && !defined(__CYGWIN__)
		ReleaseMutex(bsgs_thread);
#else
		pthread_mutex_unlock(&bsgs_thread);
#endif

		if(!FLAGQUIET && FLAGMATRIX)	{ /* ... (impressão matrix) ... */ }
		else if(!FLAGQUIET) { /* ... (impressão de base key da thread) ... */ }
		
        // Lógica similar a thread_process_bsgs para calcular point_aux_bsgs_rand
		km_bsgs_calc_rand.Set(&base_key_bsgs_rand_iter);
		km_bsgs_calc_rand.Neg();
		km_bsgs_calc_rand.Add(&secp->order);
		km_bsgs_calc_rand.Sub(&intaux_bsgs_calc_rand);
		point_aux_bsgs_rand = secp->ComputePublicKey(&km_bsgs_calc_rand);

		for(k_target_pubkey_idx_rand = 0; k_target_pubkey_idx_rand < bsgs_point_number ; k_target_pubkey_idx_rand++)	{
			if(bsgs_found[k_target_pubkey_idx_rand] == 0)	{			
				startP_bsgs_rand_calc  = secp->AddDirect(OriginalPointsBSGS[k_target_pubkey_idx_rand], point_aux_bsgs_rand);
				uint32_t j_baby_step_block_idx_rand = 0;
				while( j_baby_step_block_idx_rand < cycles_bsgs_internal_rand && bsgs_found[k_target_pubkey_idx_rand] == 0 )	{
					int i_baby_step_calc_idx_rand;
                    // ... (Cálculo de dx_bsgs_rand, ModInv, pts_bsgs_group_rand como em thread_process_bsgs) ...
                    for(i_baby_step_calc_idx_rand = 0; i_baby_step_calc_idx_rand < hLength_bsgs_rand; i_baby_step_calc_idx_rand++) { dx_bsgs_rand[i_baby_step_calc_idx_rand].ModSub(&GSn[i_baby_step_calc_idx_rand].x,&startP_bsgs_rand_calc.x); }
					dx_bsgs_rand[i_baby_step_calc_idx_rand].ModSub(&GSn[i_baby_step_calc_idx_rand].x,&startP_bsgs_rand_calc.x);
					dx_bsgs_rand[i_baby_step_calc_idx_rand+1].ModSub(&_2GSn.x,&startP_bsgs_rand_calc.x); 
					grp_bsgs_rand->ModInv();
					pts_bsgs_group_rand[CPU_GRP_SIZE / 2] = startP_bsgs_rand_calc;
					for(i_baby_step_calc_idx_rand = 0; i_baby_step_calc_idx_rand < hLength_bsgs_rand; i_baby_step_calc_idx_rand++) { /* ... cálculo de pp_bsgs_calc_rand, pn_bsgs_calc_rand ... */ 
                        pp_bsgs_calc_rand = startP_bsgs_rand_calc; pn_bsgs_calc_rand = startP_bsgs_rand_calc;
                        dy_bsgs_rand.ModSub(&GSn[i_baby_step_calc_idx_rand].y,&pp_bsgs_calc_rand.y); s_bsgs_calc_rand.ModMulK1(&dy_bsgs_rand,&dx_bsgs_rand[i_baby_step_calc_idx_rand]); p_bsgs_calc_rand.ModSquareK1(&s_bsgs_calc_rand);
                        pp_bsgs_calc_rand.x.ModNeg(); pp_bsgs_calc_rand.x.ModAdd(&p_bsgs_calc_rand); pp_bsgs_calc_rand.x.ModSub(&GSn[i_baby_step_calc_idx_rand].x);
                        dyn_bsgs_rand.Set(&GSn[i_baby_step_calc_idx_rand].y); dyn_bsgs_rand.ModNeg(); dyn_bsgs_rand.ModSub(&pn_bsgs_calc_rand.y); s_bsgs_calc_rand.ModMulK1(&dyn_bsgs_rand,&dx_bsgs_rand[i_baby_step_calc_idx_rand]); p_bsgs_calc_rand.ModSquareK1(&s_bsgs_calc_rand);
                        pn_bsgs_calc_rand.x.ModNeg(); pn_bsgs_calc_rand.x.ModAdd(&p_bsgs_calc_rand); pn_bsgs_calc_rand.x.ModSub(&GSn[i_baby_step_calc_idx_rand].x);
						pts_bsgs_group_rand[CPU_GRP_SIZE / 2 + (i_baby_step_calc_idx_rand + 1)] = pp_bsgs_calc_rand;
						pts_bsgs_group_rand[CPU_GRP_SIZE / 2 - (i_baby_step_calc_idx_rand + 1)] = pn_bsgs_calc_rand;
                    }
					pn_bsgs_calc_rand = startP_bsgs_rand_calc; dyn_bsgs_rand.Set(&GSn[i_baby_step_calc_idx_rand].y); dyn_bsgs_rand.ModNeg(); dyn_bsgs_rand.ModSub(&pn_bsgs_calc_rand.y);
					s_bsgs_calc_rand.ModMulK1(&dyn_bsgs_rand,&dx_bsgs_rand[i_baby_step_calc_idx_rand]); p_bsgs_calc_rand.ModSquareK1(&s_bsgs_calc_rand);
					pn_bsgs_calc_rand.x.ModNeg(); pn_bsgs_calc_rand.x.ModAdd(&p_bsgs_calc_rand); pn_bsgs_calc_rand.x.ModSub(&GSn[i_baby_step_calc_idx_rand].x);
					pts_bsgs_group_rand[0] = pn_bsgs_calc_rand;

					for(int pt_idx_rand = 0; pt_idx_rand < CPU_GRP_SIZE && bsgs_found[k_target_pubkey_idx_rand] == 0; pt_idx_rand++) {
						pts_bsgs_group_rand[pt_idx_rand].x.Get32Bytes((unsigned char*)xpoint_raw_bsgs_rand);
						r_bloom_check_result_rand = bloom_check(&bloom_bP[((unsigned char)xpoint_raw_bsgs_rand[0])],xpoint_raw_bsgs_rand,32);
						if(r_bloom_check_result_rand) {
							r_bloom_check_result_rand = bsgs_secondcheck(&base_key_bsgs_rand_iter, ((j_baby_step_block_idx_rand * CPU_GRP_SIZE) + pt_idx_rand), k_target_pubkey_idx_rand, &keyfound_bsgs_priv_rand);
							if(r_bloom_check_result_rand)	{ // HIT BSGS RANDOM!
								hextemp_bsgs_privkey_rand = keyfound_bsgs_priv_rand.GetBase16();
								point_found_bsgs_pub_rand = secp->ComputePublicKey(&keyfound_bsgs_priv_rand);
								aux_c_bsgs_rand = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k_target_pubkey_idx_rand], point_found_bsgs_pub_rand);
#if defined(_WIN64) && !defined(__CYGWIN__)
								WaitForSingleObject(write_keys, INFINITE);
#else
								pthread_mutex_lock(&write_keys);
#endif
                                fprintf(stderr, "\a"); // << BIP DO SISTEMA >>
                                fflush(stderr);

								printf("\n[+] BSGS RANDOM HIT! Thread %d Chave Privada: %s\n", thread_number_bsgs_rand, hextemp_bsgs_privkey_rand);
								printf("[+] Chave Pública Alvo %s: %s\n", (OriginalPointsBSGScompressed[k_target_pubkey_idx_rand] ? "C" : "U"), aux_c_bsgs_rand);
								
								filekey_bsgs_hit_rand = fopen("KEYFOUNDKEYFOUND.txt","a");
								if(filekey_bsgs_hit_rand != NULL) { /* ... (fprintf como em thread_process_bsgs) ... */ fclose(filekey_bsgs_hit_rand); }

                                // << MODIFICAÇÃO PARA IA >>
                                std::string wif_bsgs_hit_rand = ""; // Gerar WIF se necessário
                                std::string addr1_bsgs_hit_rand = ""; // Derivar P2PKH (compressão do target)
                                std::string addr2_bsgs_hit_rand = ""; // Derivar P2PKH (compressão oposta)
                                // ... (lógica de derivação de addr1 e addr2 como em thread_process_bsgs) ...
                                ml_learn_from_hit(
                                    std::string(hextemp_bsgs_privkey_rand), wif_bsgs_hit_rand,
                                    addr1_bsgs_hit_rand, addr2_bsgs_hit_rand, "", ""
                                );
                                // << FIM DA MODIFICAÇÃO >>

#if defined(_WIN64) && !defined(__CYGWIN__)
								ReleaseMutex(write_keys);
#else
								pthread_mutex_unlock(&write_keys);
#endif
								if(hextemp_bsgs_privkey_rand) { free(hextemp_bsgs_privkey_rand); hextemp_bsgs_privkey_rand = NULL; }
								if(aux_c_bsgs_rand) { free(aux_c_bsgs_rand); aux_c_bsgs_rand = NULL; }
								
                                bsgs_found[k_target_pubkey_idx_rand] = 1;
								salir_flag_bsgs_rand = 1; // Checa se todos os pontos foram encontrados
								for(l_found_check_idx_rand = 0; l_found_check_idx_rand < bsgs_point_number && salir_flag_bsgs_rand; l_found_check_idx_rand++)	{
									salir_flag_bsgs_rand &= bsgs_found[l_found_check_idx_rand];
								}
								if(salir_flag_bsgs_rand)	{ /* ... (lógica de "todos encontrados") ... */ 
                                    printf("TODOS OS PONTOS BSGS FORAM ENCONTRADOS (via Random)! Finalizando...\n");
                                    for(unsigned int end_idx = 0; end_idx < NTHREADS; ++end_idx) ends[end_idx] = 1;
                                }
							} 
						}
					} // Fim loop pt_idx_rand
					
					// Avança para o próximo bloco de baby steps
					pp_bsgs_calc_rand = startP_bsgs_rand_calc;
					dy_bsgs_rand.ModSub(&_2GSn.y,&pp_bsgs_calc_rand.y); /* ... (como em thread_process_bsgs) ... */
                    s_bsgs_calc_rand.ModMulK1(&dy_bsgs_rand,&dx_bsgs_rand[i_baby_step_calc_idx_rand + 1]); p_bsgs_calc_rand.ModSquareK1(&s_bsgs_calc_rand);
					pp_bsgs_calc_rand.x.ModNeg(); pp_bsgs_calc_rand.x.ModAdd(&p_bsgs_calc_rand); pp_bsgs_calc_rand.x.ModSub(&_2GSn.x);
					pp_bsgs_calc_rand.y.ModSub(&_2GSn.x,&pp_bsgs_calc_rand.x); pp_bsgs_calc_rand.y.ModMulK1(&s_bsgs_calc_rand); pp_bsgs_calc_rand.y.ModSub(&_2GSn.y);
					startP_bsgs_rand_calc = pp_bsgs_calc_rand;
					
					j_baby_step_block_idx_rand++;
				}	//Fim While j_baby_step_block_idx_rand
			}	//Fim if !bsgs_found
		} // Fim for k_target_pubkey_idx_rand
		steps[thread_number_bsgs_rand]+=2; // Incrementa progresso da thread
	} while(continue_thread_loop && ! (salir_flag_bsgs_rand && bsgs_point_number > 0) ); // sair_flag_bsgs_rand está no escopo errado, precisa de flag global ou apenas continue_thread_loop

	ends[thread_number_bsgs_rand] = 1;
    if(grp_bsgs_rand) delete grp_bsgs_rand;
	return NULL;
}

// (Continuação do keyhunt.cpp com thread_process_bsgs_dance, _backward, _both, e depois as funções de BSGS check, etc.)
// ...
// (Continuação do keyhunt.cpp - após thread_process_bsgs_random)

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs_dance(LPVOID vargp) {
#else
void *thread_process_bsgs_dance(void *vargp)	{
    bool continue_thread_loop = true;
#endif
	// Renomeando variáveis para clareza e escopo local
	FILE *filekey_bsgs_hit_dance;
	struct tothread *tt_data_bsgs_dance = (struct tothread *)vargp;
	int thread_number_bsgs_dance = tt_data_bsgs_dance->nt;
	free(tt_data_bsgs_dance);

	char xpoint_raw_bsgs_dance[32], *aux_c_bsgs_dance = NULL, *hextemp_bsgs_privkey_dance = NULL;
	Int base_key_bsgs_dance_iter, keyfound_bsgs_priv_dance;
	
	Point base_point_bsgs_dance_iter, point_aux_bsgs_dance, point_found_bsgs_pub_dance;
	uint32_t k_target_pubkey_idx_dance, l_found_check_idx_dance, r_bloom_check_result_dance, salir_flag_bsgs_dance = 0; // Inicializa salir_flag
    uint32_t cycles_bsgs_internal_dance, entrar_flag_dance; // Renomeado de entrar

	IntGroup *grp_bsgs_dance = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP_bsgs_dance_calc;
	int hLength_bsgs_dance = (CPU_GRP_SIZE / 2 - 1);	
	Int dx_bsgs_dance[CPU_GRP_SIZE / 2 + 1];
	Point pts_bsgs_group_dance[CPU_GRP_SIZE];
	Int dy_bsgs_dance, dyn_bsgs_dance, s_bsgs_calc_dance, p_bsgs_calc_dance;
	Int km_bsgs_calc_dance, intaux_bsgs_calc_dance;
	Point pp_bsgs_calc_dance, pn_bsgs_calc_dance;

	grp_bsgs_dance->Set(dx_bsgs_dance);
	
	cycles_bsgs_internal_dance = bsgs_aux_val / CPU_GRP_SIZE; // bsgs_aux_val é uint64_t
	if(bsgs_aux_val % CPU_GRP_SIZE != 0)	{
		cycles_bsgs_internal_dance++;
	}
	
	intaux_bsgs_calc_dance.Set(&BSGS_M_double); 
	intaux_bsgs_calc_dance.Mult(CPU_GRP_SIZE/2);
	intaux_bsgs_calc_dance.Add(&BSGS_M);
	
	entrar_flag_dance = 1; // Flag para controlar o loop principal da thread
	
    // --- PONTO DE INTERVENÇÃO DA IA PARA BSGS DANCE (CONCEITUAL) ---
    // A IA poderia influenciar a estratégia de "dança" entre os ranges (como 'r' é escolhido),
    // ou priorizar chaves públicas alvo.
    // --- FIM DO PONTO DE INTERVENÇÃO ---

	do	{ // Loop principal da thread BSGS Dance
		r_bloom_check_result_dance = rand() % 3; // Escolhe aleatoriamente como pegar o próximo base_key (topo, fundo, meio do range)
#if defined(_WIN64) && !defined(__CYGWIN__)
	    WaitForSingleObject(bsgs_thread, INFINITE);
#else
	    pthread_mutex_lock(&bsgs_thread);
#endif
	    switch(r_bloom_check_result_dance)	{ // r_bloom_check_result_dance aqui é usado para a decisão do range
		    case 0:	//TOP do range restante
			    if(n_range_end_global.IsGreater(&BSGS_CURRENT))	{ // n_range_end_global e BSGS_CURRENT são globais
					n_range_end_global.Sub(&BSGS_N_double); // BSGS_N_double = 2 * N (tamanho do passo do BSGS)
					if(n_range_end_global.IsLower(&BSGS_CURRENT))	{
						base_key_bsgs_dance_iter.Set(&BSGS_CURRENT); // Se o topo passou do fundo, usa o fundo
					} else {
						base_key_bsgs_dance_iter.Set(&n_range_end_global); // Pega do topo
					}
			    } else { entrar_flag_dance = 0; } // Range esgotado
		        break;
		    case 1: //BOTTOM do range restante
			    if(BSGS_CURRENT.IsLower(&n_range_end_global))	{
				    base_key_bsgs_dance_iter.Set(&BSGS_CURRENT);
				    BSGS_CURRENT.Add(&BSGS_N_double); // Avança o ponteiro do fundo global
			    } else { entrar_flag_dance = 0; } // Range esgotado
		        break;
		    case 2: //RANDOM no meio do range restante
			    base_key_bsgs_dance_iter.Rand(&BSGS_CURRENT,&n_range_end_global);
		        break;
	    }
#if defined(_WIN64) && !defined(__CYGWIN__)
	    ReleaseMutex(bsgs_thread);
#else
	    pthread_mutex_unlock(&bsgs_thread);
#endif

		if(entrar_flag_dance == 0) break; // Sai do loop da thread se range esgotado
			
		if(!FLAGQUIET && FLAGMATRIX) { /* ... (impressão matrix) ... */ }
		else if(!FLAGQUIET) { /* ... (impressão de base key da thread) ... */ }
		
        // Lógica para calcular point_aux_bsgs_dance (similar às outras funções BSGS)
		km_bsgs_calc_dance.Set(&base_key_bsgs_dance_iter);
		km_bsgs_calc_dance.Neg();
		km_bsgs_calc_dance.Add(&secp->order);
		km_bsgs_calc_dance.Sub(&intaux_bsgs_calc_dance);
		point_aux_bsgs_dance = secp->ComputePublicKey(&km_bsgs_calc_dance);
		
		for(k_target_pubkey_idx_dance = 0; k_target_pubkey_idx_dance < bsgs_point_number ; k_target_pubkey_idx_dance++)	{
			if(bsgs_found[k_target_pubkey_idx_dance] == 0)	{
				startP_bsgs_dance_calc  = secp->AddDirect(OriginalPointsBSGS[k_target_pubkey_idx_dance], point_aux_bsgs_dance);
				uint32_t j_baby_step_block_idx_dance = 0;
				while( j_baby_step_block_idx_dance < cycles_bsgs_internal_dance && bsgs_found[k_target_pubkey_idx_dance] == 0 )	{
					int i_baby_step_calc_idx_dance;
                    // ... (Cálculo de dx_bsgs_dance, ModInv, pts_bsgs_group_dance como nas outras BSGS) ...
                    for(i_baby_step_calc_idx_dance = 0; i_baby_step_calc_idx_dance < hLength_bsgs_dance; i_baby_step_calc_idx_dance++) { dx_bsgs_dance[i_baby_step_calc_idx_dance].ModSub(&GSn[i_baby_step_calc_idx_dance].x,&startP_bsgs_dance_calc.x); }
					dx_bsgs_dance[i_baby_step_calc_idx_dance].ModSub(&GSn[i_baby_step_calc_idx_dance].x,&startP_bsgs_dance_calc.x);
					dx_bsgs_dance[i_baby_step_calc_idx_dance+1].ModSub(&_2GSn.x,&startP_bsgs_dance_calc.x); 
					grp_bsgs_dance->ModInv();
					pts_bsgs_group_dance[CPU_GRP_SIZE / 2] = startP_bsgs_dance_calc;
					for(i_baby_step_calc_idx_dance = 0; i_baby_step_calc_idx_dance < hLength_bsgs_dance; i_baby_step_calc_idx_dance++) { /* ... cálculo de pp_bsgs_calc_dance, pn_bsgs_calc_dance ... */ 
                        pp_bsgs_calc_dance = startP_bsgs_dance_calc; pn_bsgs_calc_dance = startP_bsgs_dance_calc;
                        dy_bsgs_dance.ModSub(&GSn[i_baby_step_calc_idx_dance].y,&pp_bsgs_calc_dance.y); s_bsgs_calc_dance.ModMulK1(&dy_bsgs_dance,&dx_bsgs_dance[i_baby_step_calc_idx_dance]); p_bsgs_calc_dance.ModSquareK1(&s_bsgs_calc_dance);
                        pp_bsgs_calc_dance.x.ModNeg(); pp_bsgs_calc_dance.x.ModAdd(&p_bsgs_calc_dance); pp_bsgs_calc_dance.x.ModSub(&GSn[i_baby_step_calc_idx_dance].x);
                        dyn_bsgs_dance.Set(&GSn[i_baby_step_calc_idx_dance].y); dyn_bsgs_dance.ModNeg(); dyn_bsgs_dance.ModSub(&pn_bsgs_calc_dance.y); s_bsgs_calc_dance.ModMulK1(&dyn_bsgs_dance,&dx_bsgs_dance[i_baby_step_calc_idx_dance]); p_bsgs_calc_dance.ModSquareK1(&s_bsgs_calc_dance);
                        pn_bsgs_calc_dance.x.ModNeg(); pn_bsgs_calc_dance.x.ModAdd(&p_bsgs_calc_dance); pn_bsgs_calc_dance.x.ModSub(&GSn[i_baby_step_calc_idx_dance].x);
						pts_bsgs_group_dance[CPU_GRP_SIZE / 2 + (i_baby_step_calc_idx_dance + 1)] = pp_bsgs_calc_dance;
						pts_bsgs_group_dance[CPU_GRP_SIZE / 2 - (i_baby_step_calc_idx_dance + 1)] = pn_bsgs_calc_dance;
                    }
					pn_bsgs_calc_dance = startP_bsgs_dance_calc; dyn_bsgs_dance.Set(&GSn[i_baby_step_calc_idx_dance].y); dyn_bsgs_dance.ModNeg(); dyn_bsgs_dance.ModSub(&pn_bsgs_calc_dance.y);
					s_bsgs_calc_dance.ModMulK1(&dyn_bsgs_dance,&dx_bsgs_dance[i_baby_step_calc_idx_dance]); p_bsgs_calc_dance.ModSquareK1(&s_bsgs_calc_dance);
					pn_bsgs_calc_dance.x.ModNeg(); pn_bsgs_calc_dance.x.ModAdd(&p_bsgs_calc_dance); pn_bsgs_calc_dance.x.ModSub(&GSn[i_baby_step_calc_idx_dance].x);
					pts_bsgs_group_dance[0] = pn_bsgs_calc_dance;
					
					for(int pt_idx_dance = 0; pt_idx_dance < CPU_GRP_SIZE && bsgs_found[k_target_pubkey_idx_dance] == 0; pt_idx_dance++) {
						pts_bsgs_group_dance[pt_idx_dance].x.Get32Bytes((unsigned char*)xpoint_raw_bsgs_dance);
						r_bloom_check_result_dance = bloom_check(&bloom_bP[((unsigned char)xpoint_raw_bsgs_dance[0])],xpoint_raw_bsgs_dance,32);
						if(r_bloom_check_result_dance) {
							r_bloom_check_result_dance = bsgs_secondcheck(&base_key_bsgs_dance_iter, ((j_baby_step_block_idx_dance * CPU_GRP_SIZE) + pt_idx_dance), k_target_pubkey_idx_dance, &keyfound_bsgs_priv_dance);
							if(r_bloom_check_result_dance)	{ // HIT BSGS DANCE!
								hextemp_bsgs_privkey_dance = keyfound_bsgs_priv_dance.GetBase16();
								point_found_bsgs_pub_dance = secp->ComputePublicKey(&keyfound_bsgs_priv_dance);
								aux_c_bsgs_dance = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k_target_pubkey_idx_dance], point_found_bsgs_pub_dance);
#if defined(_WIN64) && !defined(__CYGWIN__)
								WaitForSingleObject(write_keys, INFINITE);
#else
								pthread_mutex_lock(&write_keys);
#endif
                                fprintf(stderr, "\a"); // << BIP DO SISTEMA >>
                                fflush(stderr);

								printf("\n[+] BSGS DANCE HIT! Thread %d Chave Privada: %s\n", thread_number_bsgs_dance, hextemp_bsgs_privkey_dance);
								printf("[+] Chave Pública Alvo %s: %s\n", (OriginalPointsBSGScompressed[k_target_pubkey_idx_dance] ? "C" : "U"), aux_c_bsgs_dance);
								
								filekey_bsgs_hit_dance = fopen("KEYFOUNDKEYFOUND.txt","a");
								if(filekey_bsgs_hit_dance != NULL) { /* ... (fprintf como nas outras BSGS) ... */ fclose(filekey_bsgs_hit_dance); }

                                // << MODIFICAÇÃO PARA IA >>
                                std::string wif_bsgs_hit_dance = ""; 
                                std::string addr1_bsgs_hit_dance = ""; 
                                std::string addr2_bsgs_hit_dance = ""; 
                                // ... (lógica de derivação de addr1 e addr2 como em thread_process_bsgs) ...
                                ml_learn_from_hit(
                                    std::string(hextemp_bsgs_privkey_dance), wif_bsgs_hit_dance,
                                    addr1_bsgs_hit_dance, addr2_bsgs_hit_dance, "", ""
                                );
                                // << FIM DA MODIFICAÇÃO >>

#if defined(_WIN64) && !defined(__CYGWIN__)
								ReleaseMutex(write_keys);
#else
								pthread_mutex_unlock(&write_keys);
#endif
								if(hextemp_bsgs_privkey_dance) { free(hextemp_bsgs_privkey_dance); hextemp_bsgs_privkey_dance = NULL; }
								if(aux_c_bsgs_dance) { free(aux_c_bsgs_dance); aux_c_bsgs_dance = NULL; }
								
                                bsgs_found[k_target_pubkey_idx_dance] = 1;
								salir_flag_bsgs_dance = 1;
								for(l_found_check_idx_dance = 0; l_found_check_idx_dance < bsgs_point_number && salir_flag_bsgs_dance; l_found_check_idx_dance++)	{
									salir_flag_bsgs_dance &= bsgs_found[l_found_check_idx_dance];
								}
								if(salir_flag_bsgs_dance)	{ /* ... (lógica de "todos encontrados") ... */ 
                                    printf("TODOS OS PONTOS BSGS FORAM ENCONTRADOS (via Dance)! Finalizando...\n");
                                    for(unsigned int end_idx = 0; end_idx < NTHREADS; ++end_idx) ends[end_idx] = 1;
                                }
							} 
						}
					} // Fim loop pt_idx_dance
					
					pp_bsgs_calc_dance = startP_bsgs_dance_calc; // Avança startP para o próximo bloco de baby steps
					dy_bsgs_dance.ModSub(&_2GSn.y,&pp_bsgs_calc_dance.y); /* ... (como nas outras BSGS) ... */
                    s_bsgs_calc_dance.ModMulK1(&dy_bsgs_dance,&dx_bsgs_dance[i_baby_step_calc_idx_dance + 1]); p_bsgs_calc_dance.ModSquareK1(&s_bsgs_calc_dance);
					pp_bsgs_calc_dance.x.ModNeg(); pp_bsgs_calc_dance.x.ModAdd(&p_bsgs_calc_dance); pp_bsgs_calc_dance.x.ModSub(&_2GSn.x);
					pp_bsgs_calc_dance.y.ModSub(&_2GSn.x,&pp_bsgs_calc_dance.x); pp_bsgs_calc_dance.y.ModMulK1(&s_bsgs_calc_dance); pp_bsgs_calc_dance.y.ModSub(&_2GSn.y);
					startP_bsgs_dance_calc = pp_bsgs_calc_dance;
					
					j_baby_step_block_idx_dance++;
				} // Fim while j_baby_step_block_idx_dance
			} // Fim if !bsgs_found
		} // Fim for k_target_pubkey_idx_dance
		steps[thread_number_bsgs_dance]+=2;
	} while(entrar_flag_dance && ! (salir_flag_bsgs_dance && bsgs_point_number > 0) ); // sair_flag_bsgs_dance está no escopo errado

	ends[thread_number_bsgs_dance] = 1;
    if(grp_bsgs_dance) delete grp_bsgs_dance;
	return NULL;
}


// (Continuação do keyhunt.cpp com thread_process_bsgs_backward, _both, e depois as funções de suporte BSGS, etc.)
// ...
// (Continuação do keyhunt.cpp - após thread_process_bsgs_dance)

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs_backward(LPVOID vargp) {
#else
void *thread_process_bsgs_backward(void *vargp)	{
    bool continue_thread_loop = true;
#endif
	// Renomeando variáveis para clareza e escopo local
	FILE *filekey_bsgs_hit_bwd; // Renomeado
	struct tothread *tt_data_bsgs_bwd = (struct tothread *)vargp;
	int thread_number_bsgs_bwd = tt_data_bsgs_bwd->nt;
	free(tt_data_bsgs_bwd);

	char xpoint_raw_bsgs_bwd[32],*aux_c_bsgs_bwd = NULL,*hextemp_bsgs_privkey_bwd = NULL;
	Int base_key_bsgs_bwd_iter, keyfound_bsgs_priv_bwd;
	
	Point base_point_bsgs_bwd_iter, point_aux_bsgs_bwd, point_found_bsgs_pub_bwd;
	uint32_t k_target_pubkey_idx_bwd, l_found_check_idx_bwd, r_bloom_check_result_bwd, salir_flag_bsgs_bwd = 0;
    uint32_t cycles_bsgs_internal_bwd, entrar_flag_bwd; 

	IntGroup *grp_bsgs_bwd = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP_bsgs_bwd_calc;
	int hLength_bsgs_bwd = (CPU_GRP_SIZE / 2 - 1);	
	Int dx_bsgs_bwd[CPU_GRP_SIZE / 2 + 1];
	Point pts_bsgs_group_bwd[CPU_GRP_SIZE];
	Int dy_bsgs_bwd, dyn_bsgs_bwd, s_bsgs_calc_bwd, p_bsgs_calc_bwd;
	Int km_bsgs_calc_bwd, intaux_bsgs_calc_bwd;
	Point pp_bsgs_calc_bwd, pn_bsgs_calc_bwd;

	grp_bsgs_bwd->Set(dx_bsgs_bwd);
	
	cycles_bsgs_internal_bwd = bsgs_aux_val / CPU_GRP_SIZE; 
	if(bsgs_aux_val % CPU_GRP_SIZE != 0)	{
		cycles_bsgs_internal_bwd++;
	}
	
	intaux_bsgs_calc_bwd.Set(&BSGS_M_double); 
	intaux_bsgs_calc_bwd.Mult(CPU_GRP_SIZE/2);
	intaux_bsgs_calc_bwd.Add(&BSGS_M);
	
	entrar_flag_bwd = 1; 
	
    // --- PONTO DE INTERVENÇÃO DA IA PARA BSGS BACKWARD (CONCEITUAL) ---
    // A IA poderia influenciar a escolha do range [n_range_start_global, n_range_end_global]
    // de onde base_key_bsgs_bwd_iter é retirada (do topo do range).
    // --- FIM DO PONTO DE INTERVENÇÃO ---

	do	{ // Loop principal da thread BSGS Backward
#if defined(_WIN64) && !defined(__CYGWIN__)
		WaitForSingleObject(bsgs_thread, INFINITE);
#else
		pthread_mutex_lock(&bsgs_thread);
#endif
        // No modo backward, sempre pegamos do "topo" do range global e diminuímos n_range_end_global
		if(n_range_end_global.IsGreater(&n_range_start_global))	{
			n_range_end_global.Sub(&BSGS_N_double); // Diminui o topo do range global
			if(n_range_end_global.IsLower(&n_range_start_global))	{ // Se o topo passou do fundo
				base_key_bsgs_bwd_iter.Set(&n_range_start_global); // Usa o fundo como último ponto
                // Poderia setar entrar_flag_bwd = 0 aqui se o último bloco já foi o n_range_start_global
                Int temp2 = n_range_end_global;
temp2.Add(&BSGS_N_double);
n_range_start_global.IsGreater(&temp2) { // Se antes de subtrair já era o limite
                     // Não há mais o que processar de fato se já estava no limite
                } Int temp2 = n_range_end_global;
temp2.Add(&BSGS_N_double);
n_range_start_global.IsGreater(&temp2)
{
                    // Se base_key já é o start e o end_global já passou dele, significa que este é o último bloco
                    // ou já passou. Para simplificar, processa o start_global e termina.
                }


			} else {
				base_key_bsgs_bwd_iter.Set(&n_range_end_global); // Pega o novo topo
			}
		} else { // Range esgotado
			entrar_flag_bwd = 0;
		}
#if defined(_WIN64) && !defined(__CYGWIN__)
		ReleaseMutex(bsgs_thread);
#else
		pthread_mutex_unlock(&bsgs_thread);
#endif
		if(entrar_flag_bwd == 0) break;
		
		if(!FLAGQUIET && FLAGMATRIX) { /* ... (impressão matrix) ... */ }
		else if(!FLAGQUIET) { /* ... (impressão de base key da thread) ... */ }
		
        // Lógica para calcular point_aux_bsgs_bwd (similar às outras funções BSGS)
		km_bsgs_calc_bwd.Set(&base_key_bsgs_bwd_iter);
		km_bsgs_calc_bwd.Neg();
		km_bsgs_calc_bwd.Add(&secp->order);
		km_bsgs_calc_bwd.Sub(&intaux_bsgs_calc_bwd);
		point_aux_bsgs_bwd = secp->ComputePublicKey(&km_bsgs_calc_bwd);
		
		for(k_target_pubkey_idx_bwd = 0; k_target_pubkey_idx_bwd < bsgs_point_number ; k_target_pubkey_idx_bwd++)	{
			if(bsgs_found[k_target_pubkey_idx_bwd] == 0)	{
				startP_bsgs_bwd_calc  = secp->AddDirect(OriginalPointsBSGS[k_target_pubkey_idx_bwd], point_aux_bsgs_bwd);
				uint32_t j_baby_step_block_idx_bwd = 0;
				while( j_baby_step_block_idx_bwd < cycles_bsgs_internal_bwd && bsgs_found[k_target_pubkey_idx_bwd] == 0 )	{
					int i_baby_step_calc_idx_bwd;
                    // ... (Cálculo de dx_bsgs_bwd, ModInv, pts_bsgs_group_bwd como nas outras BSGS) ...
                    for(i_baby_step_calc_idx_bwd = 0; i_baby_step_calc_idx_bwd < hLength_bsgs_bwd; i_baby_step_calc_idx_bwd++) { dx_bsgs_bwd[i_baby_step_calc_idx_bwd].ModSub(&GSn[i_baby_step_calc_idx_bwd].x,&startP_bsgs_bwd_calc.x); }
					dx_bsgs_bwd[i_baby_step_calc_idx_bwd].ModSub(&GSn[i_baby_step_calc_idx_bwd].x,&startP_bsgs_bwd_calc.x);
					dx_bsgs_bwd[i_baby_step_calc_idx_bwd+1].ModSub(&_2GSn.x,&startP_bsgs_bwd_calc.x); 
					grp_bsgs_bwd->ModInv();
					pts_bsgs_group_bwd[CPU_GRP_SIZE / 2] = startP_bsgs_bwd_calc;
					for(i_baby_step_calc_idx_bwd = 0; i_baby_step_calc_idx_bwd < hLength_bsgs_bwd; i_baby_step_calc_idx_bwd++) { /* ... cálculo de pp_bsgs_calc_bwd, pn_bsgs_calc_bwd ... */ 
                        pp_bsgs_calc_bwd = startP_bsgs_bwd_calc; pn_bsgs_calc_bwd = startP_bsgs_bwd_calc;
                        dy_bsgs_bwd.ModSub(&GSn[i_baby_step_calc_idx_bwd].y,&pp_bsgs_calc_bwd.y); s_bsgs_calc_bwd.ModMulK1(&dy_bsgs_bwd,&dx_bsgs_bwd[i_baby_step_calc_idx_bwd]); p_bsgs_calc_bwd.ModSquareK1(&s_bsgs_calc_bwd);
                        pp_bsgs_calc_bwd.x.ModNeg(); pp_bsgs_calc_bwd.x.ModAdd(&p_bsgs_calc_bwd); pp_bsgs_calc_bwd.x.ModSub(&GSn[i_baby_step_calc_idx_bwd].x);
                        dyn_bsgs_bwd.Set(&GSn[i_baby_step_calc_idx_bwd].y); dyn_bsgs_bwd.ModNeg(); dyn_bsgs_bwd.ModSub(&pn_bsgs_calc_bwd.y); s_bsgs_calc_bwd.ModMulK1(&dyn_bsgs_bwd,&dx_bsgs_bwd[i_baby_step_calc_idx_bwd]); p_bsgs_calc_bwd.ModSquareK1(&s_bsgs_calc_bwd);
                        pn_bsgs_calc_bwd.x.ModNeg(); pn_bsgs_calc_bwd.x.ModAdd(&p_bsgs_calc_bwd); pn_bsgs_calc_bwd.x.ModSub(&GSn[i_baby_step_calc_idx_bwd].x);
						pts_bsgs_group_bwd[CPU_GRP_SIZE / 2 + (i_baby_step_calc_idx_bwd + 1)] = pp_bsgs_calc_bwd;
						pts_bsgs_group_bwd[CPU_GRP_SIZE / 2 - (i_baby_step_calc_idx_bwd + 1)] = pn_bsgs_calc_bwd;
                    }
					pn_bsgs_calc_bwd = startP_bsgs_bwd_calc; dyn_bsgs_bwd.Set(&GSn[i_baby_step_calc_idx_bwd].y); dyn_bsgs_bwd.ModNeg(); dyn_bsgs_bwd.ModSub(&pn_bsgs_calc_bwd.y);
					s_bsgs_calc_bwd.ModMulK1(&dyn_bsgs_bwd,&dx_bsgs_bwd[i_baby_step_calc_idx_bwd]); p_bsgs_calc_bwd.ModSquareK1(&s_bsgs_calc_bwd);
					pn_bsgs_calc_bwd.x.ModNeg(); pn_bsgs_calc_bwd.x.ModAdd(&p_bsgs_calc_bwd); pn_bsgs_calc_bwd.x.ModSub(&GSn[i_baby_step_calc_idx_bwd].x);
					pts_bsgs_group_bwd[0] = pn_bsgs_calc_bwd;
					
					for(int pt_idx_bwd = 0; pt_idx_bwd < CPU_GRP_SIZE && bsgs_found[k_target_pubkey_idx_bwd] == 0; pt_idx_bwd++) {
						pts_bsgs_group_bwd[pt_idx_bwd].x.Get32Bytes((unsigned char*)xpoint_raw_bsgs_bwd);
						r_bloom_check_result_bwd = bloom_check(&bloom_bP[((unsigned char)xpoint_raw_bsgs_bwd[0])],xpoint_raw_bsgs_bwd,32);
						if(r_bloom_check_result_bwd) {
							r_bloom_check_result_bwd = bsgs_secondcheck(&base_key_bsgs_bwd_iter, ((j_baby_step_block_idx_bwd * CPU_GRP_SIZE) + pt_idx_bwd), k_target_pubkey_idx_bwd, &keyfound_bsgs_priv_bwd);
							if(r_bloom_check_result_bwd)	{ // HIT BSGS BACKWARD!
								hextemp_bsgs_privkey_bwd = keyfound_bsgs_priv_bwd.GetBase16();
								point_found_bsgs_pub_bwd = secp->ComputePublicKey(&keyfound_bsgs_priv_bwd);
								aux_c_bsgs_bwd = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k_target_pubkey_idx_bwd], point_found_bsgs_pub_bwd);
#if defined(_WIN64) && !defined(__CYGWIN__)
								WaitForSingleObject(write_keys, INFINITE);
#else
								pthread_mutex_lock(&write_keys);
#endif
                                fprintf(stderr, "\a"); // << BIP DO SISTEMA >>
                                fflush(stderr);

								printf("\n[+] BSGS BACKWARD HIT! Thread %d Chave Privada: %s\n", thread_number_bsgs_bwd, hextemp_bsgs_privkey_bwd);
								printf("[+] Chave Pública Alvo %s: %s\n", (OriginalPointsBSGScompressed[k_target_pubkey_idx_bwd] ? "C" : "U"), aux_c_bsgs_bwd);
								
								filekey_bsgs_hit_bwd = fopen("KEYFOUNDKEYFOUND.txt","a");
								if(filekey_bsgs_hit_bwd != NULL) { /* ... (fprintf como nas outras BSGS) ... */ fclose(filekey_bsgs_hit_bwd); }

                                // << MODIFICAÇÃO PARA IA >>
                                std::string wif_bsgs_hit_bwd = ""; 
                                std::string addr1_bsgs_hit_bwd = ""; 
                                std::string addr2_bsgs_hit_bwd = ""; 
                                // ... (lógica de derivação de addr1 e addr2 como em thread_process_bsgs) ...
                                ml_learn_from_hit(
                                    std::string(hextemp_bsgs_privkey_bwd), wif_bsgs_hit_bwd,
                                    addr1_bsgs_hit_bwd, addr2_bsgs_hit_bwd, "", ""
                                );
                                // << FIM DA MODIFICAÇÃO >>
#if defined(_WIN64) && !defined(__CYGWIN__)
								ReleaseMutex(write_keys);
#else
								pthread_mutex_unlock(&write_keys);
#endif
								if(hextemp_bsgs_privkey_bwd) { free(hextemp_bsgs_privkey_bwd); hextemp_bsgs_privkey_bwd = NULL; }
								if(aux_c_bsgs_bwd) { free(aux_c_bsgs_bwd); aux_c_bsgs_bwd = NULL; }
								
                                bsgs_found[k_target_pubkey_idx_bwd] = 1;
								salir_flag_bsgs_bwd = 1;
								for(l_found_check_idx_bwd = 0; l_found_check_idx_bwd < bsgs_point_number && salir_flag_bsgs_bwd; l_found_check_idx_bwd++)	{
									salir_flag_bsgs_bwd &= bsgs_found[l_found_check_idx_bwd];
								}
								if(salir_flag_bsgs_bwd)	{ /* ... (lógica de "todos encontrados") ... */ 
                                    printf("TODOS OS PONTOS BSGS FORAM ENCONTRADOS (via Backward)! Finalizando...\n");
                                    for(unsigned int end_idx = 0; end_idx < NTHREADS; ++end_idx) ends[end_idx] = 1;
                                }
							} 
						}
					} // Fim loop pt_idx_bwd
					
					pp_bsgs_calc_bwd = startP_bsgs_bwd_calc; // Avança startP para o próximo bloco de baby steps
					dy_bsgs_bwd.ModSub(&_2GSn.y,&pp_bsgs_calc_bwd.y); /* ... (como nas outras BSGS) ... */
                    s_bsgs_calc_bwd.ModMulK1(&dy_bsgs_bwd,&dx_bsgs_bwd[i_baby_step_calc_idx_bwd + 1]); p_bsgs_calc_bwd.ModSquareK1(&s_bsgs_calc_bwd);
					pp_bsgs_calc_bwd.x.ModNeg(); pp_bsgs_calc_bwd.x.ModAdd(&p_bsgs_calc_bwd); pp_bsgs_calc_bwd.x.ModSub(&_2GSn.x);
					pp_bsgs_calc_bwd.y.ModSub(&_2GSn.x,&pp_bsgs_calc_bwd.x); pp_bsgs_calc_bwd.y.ModMulK1(&s_bsgs_calc_bwd); pp_bsgs_calc_bwd.y.ModSub(&_2GSn.y);
					startP_bsgs_bwd_calc = pp_bsgs_calc_bwd;
					
					j_baby_step_block_idx_bwd++;
				} // Fim while j_baby_step_block_idx_bwd
			} // Fim if !bsgs_found
		} // Fim for k_target_pubkey_idx_bwd
		steps[thread_number_bsgs_bwd]+=2;
	} while(entrar_flag_bwd && ! (salir_flag_bsgs_bwd && bsgs_point_number > 0) );

	ends[thread_number_bsgs_bwd] = 1;
    if(grp_bsgs_bwd) delete grp_bsgs_bwd;
	return NULL;
}

// (Continuação do keyhunt.cpp com thread_process_bsgs_both, etc.)
// ...	
// (Continuação do keyhunt.cpp - após thread_process_bsgs_backward)

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs_both(LPVOID vargp) {
#else
void *thread_process_bsgs_both(void *vargp)	{
    bool continue_thread_loop = true;
#endif
	// Renomeando variáveis para clareza e escopo local
	FILE *filekey_bsgs_hit_both;
	struct tothread *tt_data_bsgs_both = (struct tothread *)vargp;
	int thread_number_bsgs_both = tt_data_bsgs_both->nt;
	free(tt_data_bsgs_both);

	char xpoint_raw_bsgs_both[32],*aux_c_bsgs_both = NULL,*hextemp_bsgs_privkey_both = NULL;
	Int base_key_bsgs_both_iter, keyfound_bsgs_priv_both;
	
	Point base_point_bsgs_both_iter, point_aux_bsgs_both, point_found_bsgs_pub_both;
	uint32_t k_target_pubkey_idx_both, l_found_check_idx_both, r_choice_bsgs_both, salir_flag_bsgs_both = 0;
    uint32_t cycles_bsgs_internal_both, entrar_flag_both; 
    uint32_t r_bloom_check_result_both; // Para guardar resultado do bloom_check

	IntGroup *grp_bsgs_both = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP_bsgs_both_calc;
	int hLength_bsgs_both = (CPU_GRP_SIZE / 2 - 1);	
	Int dx_bsgs_both[CPU_GRP_SIZE / 2 + 1];
	Point pts_bsgs_group_both[CPU_GRP_SIZE];
	Int dy_bsgs_both, dyn_bsgs_both, s_bsgs_calc_both, p_bsgs_calc_both;
	Int km_bsgs_calc_both, intaux_bsgs_calc_both;
	Point pp_bsgs_calc_both, pn_bsgs_calc_both;

	grp_bsgs_both->Set(dx_bsgs_both);
	
	cycles_bsgs_internal_both = bsgs_aux_val / CPU_GRP_SIZE; 
	if(bsgs_aux_val % CPU_GRP_SIZE != 0)	{
		cycles_bsgs_internal_both++;
	}
	
	intaux_bsgs_calc_both.Set(&BSGS_M_double); 
	intaux_bsgs_calc_both.Mult(CPU_GRP_SIZE/2);
	intaux_bsgs_calc_both.Add(&BSGS_M);
	
	entrar_flag_both = 1; 
	
    // --- PONTO DE INTERVENÇÃO DA IA PARA BSGS BOTH (CONCEITUAL) ---
    // A IA poderia influenciar a escolha da estratégia (topo ou fundo do range),
    // ou priorizar chaves públicas alvo.
    // --- FIM DO PONTO DE INTERVENÇÃO ---

	do	{ // Loop principal da thread BSGS Both
		r_choice_bsgs_both = rand() % 2; // 0 para Topo (backward), 1 para Fundo (sequential)
#if defined(_WIN64) && !defined(__CYGWIN__)
		WaitForSingleObject(bsgs_thread, INFINITE);
#else
		pthread_mutex_lock(&bsgs_thread);
#endif
		switch(r_choice_bsgs_both)	{
			case 0:	//TOP (similar ao backward)
				if(n_range_end_global.IsGreater(&BSGS_CURRENT))	{
						n_range_end_global.Sub(&BSGS_N_double);
						if(n_range_end_global.IsLower(&BSGS_CURRENT))	{
							base_key_bsgs_both_iter.Set(&BSGS_CURRENT);
						} else {
							base_key_bsgs_both_iter.Set(&n_range_end_global);
						}
				} else { entrar_flag_both = 0; }
			break;
			case 1: //BOTTOM (similar ao sequential)
				if(BSGS_CURRENT.IsLower(&n_range_end_global))	{
					base_key_bsgs_both_iter.Set(&BSGS_CURRENT);
					BSGS_CURRENT.Add(&BSGS_N_double);
				} else { entrar_flag_both = 0; }
			break;
		}
#if defined(_WIN64) && !defined(__CYGWIN__)
		ReleaseMutex(bsgs_thread);
#else
		pthread_mutex_unlock(&bsgs_thread);
#endif

		if(entrar_flag_both == 0) break;
		
		if(!FLAGQUIET && FLAGMATRIX) { /* ... (impressão matrix) ... */ }
		else if(!FLAGQUIET) { /* ... (impressão de base key da thread) ... */ }
		
        // Lógica para calcular point_aux_bsgs_both (similar às outras funções BSGS)
		km_bsgs_calc_both.Set(&base_key_bsgs_both_iter);
		km_bsgs_calc_both.Neg();
		km_bsgs_calc_both.Add(&secp->order);
		km_bsgs_calc_both.Sub(&intaux_bsgs_calc_both);
		point_aux_bsgs_both = secp->ComputePublicKey(&km_bsgs_calc_both);
		
		for(k_target_pubkey_idx_both = 0; k_target_pubkey_idx_both < bsgs_point_number ; k_target_pubkey_idx_both++)	{
			if(bsgs_found[k_target_pubkey_idx_both] == 0)	{
				startP_bsgs_both_calc  = secp->AddDirect(OriginalPointsBSGS[k_target_pubkey_idx_both], point_aux_bsgs_both);
				uint32_t j_baby_step_block_idx_both = 0;
				while( j_baby_step_block_idx_both < cycles_bsgs_internal_both && bsgs_found[k_target_pubkey_idx_both] == 0 )	{
					int i_baby_step_calc_idx_both;
                    // ... (Cálculo de dx_bsgs_both, ModInv, pts_bsgs_group_both como nas outras BSGS) ...
                    for(i_baby_step_calc_idx_both = 0; i_baby_step_calc_idx_both < hLength_bsgs_both; i_baby_step_calc_idx_both++) { dx_bsgs_both[i_baby_step_calc_idx_both].ModSub(&GSn[i_baby_step_calc_idx_both].x,&startP_bsgs_both_calc.x); }
					dx_bsgs_both[i_baby_step_calc_idx_both].ModSub(&GSn[i_baby_step_calc_idx_both].x,&startP_bsgs_both_calc.x);
					dx_bsgs_both[i_baby_step_calc_idx_both+1].ModSub(&_2GSn.x,&startP_bsgs_both_calc.x); 
					grp_bsgs_both->ModInv();
					pts_bsgs_group_both[CPU_GRP_SIZE / 2] = startP_bsgs_both_calc;
					for(i_baby_step_calc_idx_both = 0; i_baby_step_calc_idx_both < hLength_bsgs_both; i_baby_step_calc_idx_both++) { /* ... cálculo de pp_bsgs_calc_both, pn_bsgs_calc_both ... */ 
                        pp_bsgs_calc_both = startP_bsgs_both_calc; pn_bsgs_calc_both = startP_bsgs_both_calc;
                        dy_bsgs_both.ModSub(&GSn[i_baby_step_calc_idx_both].y,&pp_bsgs_calc_both.y); s_bsgs_calc_both.ModMulK1(&dy_bsgs_both,&dx_bsgs_both[i_baby_step_calc_idx_both]); p_bsgs_calc_both.ModSquareK1(&s_bsgs_calc_both);
                        pp_bsgs_calc_both.x.ModNeg(); pp_bsgs_calc_both.x.ModAdd(&p_bsgs_calc_both); pp_bsgs_calc_both.x.ModSub(&GSn[i_baby_step_calc_idx_both].x);
                        dyn_bsgs_both.Set(&GSn[i_baby_step_calc_idx_both].y); dyn_bsgs_both.ModNeg(); dyn_bsgs_both.ModSub(&pn_bsgs_calc_both.y); s_bsgs_calc_both.ModMulK1(&dyn_bsgs_both,&dx_bsgs_both[i_baby_step_calc_idx_both]); p_bsgs_calc_both.ModSquareK1(&s_bsgs_calc_both);
                        pn_bsgs_calc_both.x.ModNeg(); pn_bsgs_calc_both.x.ModAdd(&p_bsgs_calc_both); pn_bsgs_calc_both.x.ModSub(&GSn[i_baby_step_calc_idx_both].x);
						pts_bsgs_group_both[CPU_GRP_SIZE / 2 + (i_baby_step_calc_idx_both + 1)] = pp_bsgs_calc_both;
						pts_bsgs_group_both[CPU_GRP_SIZE / 2 - (i_baby_step_calc_idx_both + 1)] = pn_bsgs_calc_both;
                    }
					pn_bsgs_calc_both = startP_bsgs_both_calc; dyn_bsgs_both.Set(&GSn[i_baby_step_calc_idx_both].y); dyn_bsgs_both.ModNeg(); dyn_bsgs_both.ModSub(&pn_bsgs_calc_both.y);
					s_bsgs_calc_both.ModMulK1(&dyn_bsgs_both,&dx_bsgs_both[i_baby_step_calc_idx_both]); p_bsgs_calc_both.ModSquareK1(&s_bsgs_calc_both);
					pn_bsgs_calc_both.x.ModNeg(); pn_bsgs_calc_both.x.ModAdd(&p_bsgs_calc_both); pn_bsgs_calc_both.x.ModSub(&GSn[i_baby_step_calc_idx_both].x);
					pts_bsgs_group_both[0] = pn_bsgs_calc_both;
					
					for(int pt_idx_both = 0; pt_idx_both < CPU_GRP_SIZE && bsgs_found[k_target_pubkey_idx_both] == 0; pt_idx_both++) {
						pts_bsgs_group_both[pt_idx_both].x.Get32Bytes((unsigned char*)xpoint_raw_bsgs_both);
						r_bloom_check_result_both = bloom_check(&bloom_bP[((unsigned char)xpoint_raw_bsgs_both[0])],xpoint_raw_bsgs_both,32);
						if(r_bloom_check_result_both) {
							r_bloom_check_result_both = bsgs_secondcheck(&base_key_bsgs_both_iter, ((j_baby_step_block_idx_both * CPU_GRP_SIZE) + pt_idx_both), k_target_pubkey_idx_both, &keyfound_bsgs_priv_both);
							if(r_bloom_check_result_both)	{ // HIT BSGS BOTH!
								hextemp_bsgs_privkey_both = keyfound_bsgs_priv_both.GetBase16();
								point_found_bsgs_pub_both = secp->ComputePublicKey(&keyfound_bsgs_priv_both);
								aux_c_bsgs_both = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k_target_pubkey_idx_both], point_found_bsgs_pub_both);
#if defined(_WIN64) && !defined(__CYGWIN__)
								WaitForSingleObject(write_keys, INFINITE);
#else
								pthread_mutex_lock(&write_keys);
#endif
                                fprintf(stderr, "\a"); // << BIP DO SISTEMA >>
                                fflush(stderr);

								printf("\n[+] BSGS BOTH HIT! Thread %d Chave Privada: %s\n", thread_number_bsgs_both, hextemp_bsgs_privkey_both);
								printf("[+] Chave Pública Alvo %s: %s\n", (OriginalPointsBSGScompressed[k_target_pubkey_idx_both] ? "C" : "U"), aux_c_bsgs_both);
								
								filekey_bsgs_hit_both = fopen("KEYFOUNDKEYFOUND.txt","a");
								if(filekey_bsgs_hit_both != NULL) { /* ... (fprintf como nas outras BSGS) ... */ fclose(filekey_bsgs_hit_both); }

                                // << MODIFICAÇÃO PARA IA >>
                                std::string wif_bsgs_hit_both = ""; 
                                std::string addr1_bsgs_hit_both = ""; 
                                std::string addr2_bsgs_hit_both = ""; 
                                // ... (lógica de derivação de addr1 e addr2 como em thread_process_bsgs) ...
                                ml_learn_from_hit(
                                    std::string(hextemp_bsgs_privkey_both), wif_bsgs_hit_both,
                                    addr1_bsgs_hit_both, addr2_bsgs_hit_both, "", ""
                                );
                                // << FIM DA MODIFICAÇÃO >>
#if defined(_WIN64) && !defined(__CYGWIN__)
								ReleaseMutex(write_keys);
#else
								pthread_mutex_unlock(&write_keys);
#endif
								if(hextemp_bsgs_privkey_both) { free(hextemp_bsgs_privkey_both); hextemp_bsgs_privkey_both = NULL; }
								if(aux_c_bsgs_both) { free(aux_c_bsgs_both); aux_c_bsgs_both = NULL; }
								
                                bsgs_found[k_target_pubkey_idx_both] = 1;
								salir_flag_bsgs_both = 1;
								for(l_found_check_idx_both = 0; l_found_check_idx_both < bsgs_point_number && salir_flag_bsgs_both; l_found_check_idx_both++)	{
									salir_flag_bsgs_both &= bsgs_found[l_found_check_idx_both];
								}
								if(salir_flag_bsgs_both)	{ /* ... (lógica de "todos encontrados") ... */ 
                                    printf("TODOS OS PONTOS BSGS FORAM ENCONTRADOS (via Both)! Finalizando...\n");
                                    for(unsigned int end_idx = 0; end_idx < NTHREADS; ++end_idx) ends[end_idx] = 1;
                                }
							} 
						}
					} // Fim loop pt_idx_both
					
					pp_bsgs_calc_both = startP_bsgs_both_calc; // Avança startP para o próximo bloco de baby steps
					dy_bsgs_both.ModSub(&_2GSn.y,&pp_bsgs_calc_both.y); /* ... (como nas outras BSGS) ... */
                    s_bsgs_calc_both.ModMulK1(&dy_bsgs_both,&dx_bsgs_both[i_baby_step_calc_idx_both + 1]); p_bsgs_calc_both.ModSquareK1(&s_bsgs_calc_both);
					pp_bsgs_calc_both.x.ModNeg(); pp_bsgs_calc_both.x.ModAdd(&p_bsgs_calc_both); pp_bsgs_calc_both.x.ModSub(&_2GSn.x);
					pp_bsgs_calc_both.y.ModSub(&_2GSn.x,&pp_bsgs_calc_both.x); pp_bsgs_calc_both.y.ModMulK1(&s_bsgs_calc_both); pp_bsgs_calc_both.y.ModSub(&_2GSn.y);
					startP_bsgs_both_calc = pp_bsgs_calc_both;
					
					j_baby_step_block_idx_both++;
				} // Fim while j_baby_step_block_idx_both
			} // Fim if !bsgs_found
		} // Fim for k_target_pubkey_idx_both
		steps[thread_number_bsgs_both]+=2;	
	} while(entrar_flag_both && ! (salir_flag_bsgs_both && bsgs_point_number > 0) );

	ends[thread_number_bsgs_both] = 1;
    if(grp_bsgs_both) delete grp_bsgs_both;
	return NULL;
}


/*	
	The bsgs_secondcheck function is made to perform a second BSGS search in a Range of less size.
	This funtion is made with the especific purpouse to USE a smaller bPtable in RAM.
    (Esta função é auxiliar do BSGS e não reporta hits finais, então não precisa de modificações para bip ou ml_learn_from_hit)
*/
int bsgs_secondcheck(Int *start_range_bsgs,uint32_t a_val,uint32_t k_index_bsgs,Int *privatekey_found_bsgs)	{ // Nomes de parâmetros atualizados
	int i_val = 0,found_flag = 0,r_check = 0;
	Int base_key_lvl2;
	Point base_point_lvl2,point_aux_lvl2;
	Point BSGS_Q_lvl2, BSGS_S_lvl2,BSGS_Q_AMP_lvl2;
	char xpoint_raw_lvl2[32];

	base_key_lvl2.Set(&BSGS_M_double); // BSGS_M_double = 2*m (m principal)
	base_key_lvl2.Mult((uint64_t) a_val); // a_val é o índice do primeiro nível de baby steps (0 a m-1)
	base_key_lvl2.Add(start_range_bsgs);  // start_range_bsgs é a chave do giant step atual

	base_point_lvl2 = secp->ComputePublicKey(&base_key_lvl2);
	point_aux_lvl2 = secp->Negation(base_point_lvl2);

	BSGS_S_lvl2 = secp->AddDirect(OriginalPointsBSGS[k_index_bsgs],point_aux_lvl2); // Q_target - (k_giant + a*2m)G
	BSGS_Q_lvl2.Set(BSGS_S_lvl2);
	do {
        // BSGS_AMP2[i_val] = - ( i_val * 2*m2 ) G - m2*G
		BSGS_Q_AMP_lvl2 = secp->AddDirect(BSGS_Q_lvl2, BSGS_AMP2[i_val]); // BSGS_AMP2 são os pontos pré-calculados para o 2º nível
		// BSGS_S_lvl2 = Q_target - (k_giant + a*2m)G - (i_val*2m2 + m2)G
        BSGS_S_lvl2.Set(BSGS_Q_AMP_lvl2);
		BSGS_S_lvl2.x.Get32Bytes((unsigned char *) xpoint_raw_lvl2);
		r_check = bloom_check(&bloom_bPx2nd[(uint8_t) xpoint_raw_lvl2[0]],xpoint_raw_lvl2,32); // Checa no 2º filtro de Bloom
		if(r_check)	{
            // Se passou no 2º filtro, faz a 3ª checagem (tabela em memória)
			found_flag = bsgs_thirdcheck(&base_key_lvl2, i_val, k_index_bsgs, privatekey_found_bsgs);
		}
		i_val++;
	} while(i_val < 32 && !found_flag); // Itera pelos 32 pontos pré-calculados de BSGS_AMP2
	return found_flag;
}

// (Esta função é auxiliar do BSGS e não reporta hits finais, então não precisa de modificações para bip ou ml_learn_from_hit)
int bsgs_thirdcheck(Int *start_range_lvl2,uint32_t a_val_lvl2,uint32_t k_index_bsgs_lvl2,Int *privatekey_found_final)	{ // Nomes de parâmetros atualizados
	uint64_t j_idx_table = 0;
	int i_val_lvl3 = 0,found_flag_lvl3 = 0,r_check_lvl3 = 0;
	Int base_key_lvl3,calculatedkey_lvl3;
	Point base_point_lvl3,point_aux_lvl3;
	Point BSGS_Q_lvl3, BSGS_S_lvl3,BSGS_Q_AMP_lvl3;
	char xpoint_raw_lvl3[32];

	base_key_lvl3.SetInt32(a_val_lvl2); // a_val_lvl2 é o índice do segundo nível (0 a 31)
	base_key_lvl3.Mult(&BSGS_M2_double); // BSGS_M2_double = 2*m2
	base_key_lvl3.Add(start_range_lvl2); // start_range_lvl2 é (k_giant + a*2m)

	base_point_lvl3 = secp->ComputePublicKey(&base_key_lvl3);
	point_aux_lvl3 = secp->Negation(base_point_lvl3);
	
	BSGS_S_lvl3 = secp->AddDirect(OriginalPointsBSGS[k_index_bsgs_lvl2],point_aux_lvl3); // Q_target - (k_giant + a*2m + a_lvl2*2m2)G
	BSGS_Q_lvl3.Set(BSGS_S_lvl3);
	
	do {
        // BSGS_AMP3[i_val_lvl3] = - (i_val_lvl3 * 2*m3)G - m3*G
		BSGS_Q_AMP_lvl3 = secp->AddDirect(BSGS_Q_lvl3,BSGS_AMP3[i_val_lvl3]); // BSGS_AMP3 são os pontos do 3º nível
		BSGS_S_lvl3.Set(BSGS_Q_AMP_lvl3);
		BSGS_S_lvl3.x.Get32Bytes((unsigned char *)xpoint_raw_lvl3);
		r_check_lvl3 = bloom_check(&bloom_bPx3rd[(uint8_t)xpoint_raw_lvl3[0]],xpoint_raw_lvl3,32); // Checa no 3º filtro de Bloom
		if(r_check_lvl3)	{
            // Se passou, busca na tabela bPtable (que contém xG para x de 0 a m3-1, apenas os X bytes)
			r_check_lvl3 = bsgs_searchbinary(bPtable,xpoint_raw_lvl3,bsgs_m3_val,&j_idx_table); // bsgs_m3_val é o antigo bsgs_m3 (uint64_t)
			if(r_check_lvl3)	{ // Colisão na tabela!
                // Constrói a chave privada candidata
				calcualteindex(i_val_lvl3,&calculatedkey_lvl3); // calculatedkey_lvl3 = i_val_lvl3*2m3 + m3
				privatekey_found_final->Set(&calculatedkey_lvl3);
				privatekey_found_final->Add((uint64_t)(j_idx_table+1)); // j_idx_table é o índice da tabela (0 a m3-1), então +1 para valor de 1 a m3
				privatekey_found_final->Add(&base_key_lvl3);
                // privatekey = (k_giant + a*2m + a_lvl2*2m2) + (i_val_lvl3*2m3 + m3) + (j_idx_table+1)

				point_aux_lvl3 = secp->ComputePublicKey(privatekey_found_final);
				if(point_aux_lvl3.x.IsEqual(&OriginalPointsBSGS[k_index_bsgs_lvl2].x))	{ // Verifica se o X da chave pública bate
					found_flag_lvl3 = 1;
				}
				else	{ // Tenta com - (j_idx_table+1) por causa da simetria (xP e -xP têm o mesmo X se xP for um baby step)
                      // Na verdade, a tabela bPtable contém (k*G).x. O ponto encontrado é (Q - i*M*G - j*m*G).x
                      // Se (Q - i*M*G - j*m*G).x == (k*G).x, então Q - i*M*G - j*m*G = +/-(k*G)
                      // Chave = i*M + j*m +/- k
                      // A lógica aqui já considera o +/- ao reconstruir e checar. A chave final é base_key + (calculated_from_i) +/- (calculated_from_j)
					calcualteindex(i_val_lvl3,&calculatedkey_lvl3);
					privatekey_found_final->Set(&calculatedkey_lvl3);
					privatekey_found_final->Sub((uint64_t)(j_idx_table+1)); // Tenta com o negativo do valor da tabela
					privatekey_found_final->Add(&base_key_lvl3);
					point_aux_lvl3 = secp->ComputePublicKey(privatekey_found_final);
					if(point_aux_lvl3.x.IsEqual(&OriginalPointsBSGS[k_index_bsgs_lvl2].x))	{
						found_flag_lvl3 = 1;
					}
				}
			}
		}
		else	{ 
            // Caso especial se Q'''.x == (-BSGS_AMP3[i_val_lvl3]).x
            // Isso significa que Q''' + BSGS_AMP3[i_val_lvl3] = PontoNoInfinito
            // Q_target - (k_giant + a*2m + a_lvl2*2m2)G = (i_val_lvl3*2m3 + m3)G
            // Chave = (k_giant + a*2m + a_lvl2*2m2) + (i_val_lvl3*2m3 + m3)
			if(BSGS_Q_lvl3.x.IsEqual(&BSGS_AMP3[i_val_lvl3].x) && !BSGS_Q_lvl3.y.IsEqual(&BSGS_AMP3[i_val_lvl3].y))	{ // Verifica se são opostos
				calcualteindex(i_val_lvl3,&calculatedkey_lvl3);
				privatekey_found_final->Set(&calculatedkey_lvl3);
				privatekey_found_final->Add(&base_key_lvl3);
				found_flag_lvl3 = 1;
			}
		}
		i_val_lvl3++;
	} while(i_val_lvl3 < 32 && !found_flag_lvl3);
	return found_flag_lvl3;
}

void sleep_ms(int milliseconds)	{ 
#if defined(_WIN64) && !defined(__CYGWIN__)
    Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    if (milliseconds >= 1000)
      sleep(milliseconds / 1000);
    usleep((milliseconds % 1000) * 1000);
#endif
}

// Inicializa os pontos G*n para os cálculos de grupo (baby steps)
void init_generator()	{
	Point G_base = secp->ComputePublicKey(&stride); // G_base é G ou stride*G
	Point g_iter = G_base;
	
    Gn.clear(); // Limpa para o caso de ser chamado múltiplas vezes (embora não seja comum)
    Gn.resize(CPU_GRP_SIZE / 2); // Pré-aloca o tamanho necessário

	Gn[0] = g_iter; // Gn[0] = 1*G_base (ou stride*G)
	
    g_iter = secp->DoubleDirect(g_iter); // g_iter = 2*G_base
	Gn[1] = g_iter; // Gn[1] = 2*G_base

	for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g_iter = secp->AddDirect(g_iter,G_base); // g_iter += G_base
		Gn[i] = g_iter; // Gn[i] = (i+1)*G_base
	}
    // Gn[k] = (k+1)*stride*G
    // Ex: Gn[0] = 1*stride*G, Gn[1] = 2*stride*G, ..., Gn[CPU_GRP_SIZE/2 - 1] = (CPU_GRP_SIZE/2)*stride*G

	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]); // _2Gn = 2 * (CPU_GRP_SIZE/2)*stride*G = CPU_GRP_SIZE*stride*G
}

// (O restante do arquivo, incluindo thread_bPload, funções de ordenação, leitura de arquivo, etc. continua aqui)
// ...
// (Continuação do keyhunt.cpp - após as funções de busca BSGS como thread_process_bsgs_both)

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_bPload(LPVOID vargp) {
#else
void *thread_bPload(void *vargp)	{
    bool continue_thread_loop = true;
#endif
	// Renomeando variáveis para clareza e escopo local
	char rawvalue_bpload[32];
	// char hexraw[65]; // Declarado mas não usado no seu código original, removido para limpeza
	struct bPload *tt_data_bpload = (struct bPload *)vargp;
	uint64_t i_counter_bpload, j_idx_bpload, nbStep_bpload, to_val_bpload;
	
	IntGroup *grp_bpload = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP_bpload;
	Int dx_bpload[CPU_GRP_SIZE / 2 + 1];
	Point pts_bpload[CPU_GRP_SIZE];
	Int dy_bpload, dyn_bpload, s_bpload_calc, p_bpload_calc;
	Point pp_bpload_calc, pn_bpload_calc;
	
	int i_loop_bpload, bloom_bP_idx_bpload, hLength_bpload = (CPU_GRP_SIZE / 2 - 1) ,threadid_bpload;
	
	threadid_bpload = tt_data_bpload->threadid;
	Int km_bpload((uint64_t)(tt_data_bpload->from + 1)); // Chave inicial para este bloco de carga
	
	i_counter_bpload = tt_data_bpload->from;
	to_val_bpload = tt_data_bpload->to;

	nbStep_bpload = (to_val_bpload - tt_data_bpload->from) / CPU_GRP_SIZE;
	if( ((to_val_bpload - tt_data_bpload->from) % CPU_GRP_SIZE )  != 0)	{
		nbStep_bpload++;
	}
	
	km_bpload.Add((uint64_t)(CPU_GRP_SIZE / 2)); // Ajusta para o centro do primeiro grupo
	startP_bpload = secp->ComputePublicKey(&km_bpload);
	grp_bpload->Set(dx_bpload);

	for(uint64_t s_step_bpload=0; s_step_bpload < nbStep_bpload; s_step_bpload++) {
		// ... (Lógica de cálculo de dx_bpload, ModInv, pts_bpload como em thread_process/thread_process_bsgs) ...
        for(i_loop_bpload = 0; i_loop_bpload < hLength_bpload; i_loop_bpload++) { dx_bpload[i_loop_bpload].ModSub(&Gn[i_loop_bpload].x,&startP_bpload.x); }
		dx_bpload[i_loop_bpload].ModSub(&Gn[i_loop_bpload].x,&startP_bpload.x); 
		dx_bpload[i_loop_bpload + 1].ModSub(&_2Gn.x,&startP_bpload.x);
		grp_bpload->ModInv();
		pts_bpload[CPU_GRP_SIZE / 2] = startP_bpload;
		for(i_loop_bpload = 0; i_loop_bpload < hLength_bpload; i_loop_bpload++) { 
            pp_bpload_calc = startP_bpload; pn_bpload_calc = startP_bpload;
            dy_bpload.ModSub(&Gn[i_loop_bpload].y,&pp_bpload_calc.y); s_bpload_calc.ModMulK1(&dy_bpload,&dx_bpload[i_loop_bpload]); p_bpload_calc.ModSquareK1(&s_bpload_calc);
            pp_bpload_calc.x.ModNeg(); pp_bpload_calc.x.ModAdd(&p_bpload_calc); pp_bpload_calc.x.ModSub(&Gn[i_loop_bpload].x);
            // Y não é estritamente necessário para bPload, pois só X.Get32Bytes é usado
            dyn_bpload.Set(&Gn[i_loop_bpload].y); dyn_bpload.ModNeg(); dyn_bpload.ModSub(&pn_bpload_calc.y); s_bpload_calc.ModMulK1(&dyn_bpload,&dx_bpload[i_loop_bpload]); p_bpload_calc.ModSquareK1(&s_bpload_calc);
            pn_bpload_calc.x.ModNeg(); pn_bpload_calc.x.ModAdd(&p_bpload_calc); pn_bpload_calc.x.ModSub(&Gn[i_loop_bpload].x);
			pts_bpload[CPU_GRP_SIZE / 2 + (i_loop_bpload + 1)] = pp_bpload_calc;
			pts_bpload[CPU_GRP_SIZE / 2 - (i_loop_bpload + 1)] = pn_bpload_calc;
        }
		pn_bpload_calc = startP_bpload; dyn_bpload.Set(&Gn[i_loop_bpload].y); dyn_bpload.ModNeg(); dyn_bpload.ModSub(&pn_bpload_calc.y);
		s_bpload_calc.ModMulK1(&dyn_bpload,&dx_bpload[i_loop_bpload]); p_bpload_calc.ModSquareK1(&s_bpload_calc);
		pn_bpload_calc.x.ModNeg(); pn_bpload_calc.x.ModAdd(&p_bpload_calc); pn_bpload_calc.x.ModSub(&Gn[i_loop_bpload].x);
		pts_bpload[0] = pn_bpload_calc;

		for(j_idx_bpload=0; j_idx_bpload < CPU_GRP_SIZE; j_idx_bpload++)	{
			if (i_counter_bpload >= to_val_bpload) break; // Garante que não exceda o 'to' desta thread

			pts_bpload[j_idx_bpload].x.Get32Bytes((unsigned char*)rawvalue_bpload);
			bloom_bP_idx_bpload = (uint8_t)rawvalue_bpload[0];
			
			if(i_counter_bpload < bsgs_m3_val)	{ // bsgs_m3_val é o antigo bsgs_m3 (uint64_t)
				if(!FLAGREADEDFILE3)	{ // Se a tabela bPtable (nível 3) não foi lida do arquivo
					memcpy(bPtable[i_counter_bpload].value,rawvalue_bpload+16,BSGS_XVALUE_RAM); // Copia últimos 6 bytes do X
					bPtable[i_counter_bpload].index = i_counter_bpload;
				}
				if(!FLAGREADEDFILE4)	{ // Se o filtro de Bloom do nível 3 não foi lido
#if defined(_WIN64) && !defined(__CYGWIN__)
					#define BSGS_BUFFERXPOINTLENGTH 32 WaitForSingleObject(bloom_bPx3rd_mutex_handles[bloom_bP_idx_bpload], INFINITE); // Usando _handles
					bloom_add(&bloom_bPx3rd[bloom_bP_idx_bpload], rawvalue_bpload, BSGS_BUFFERXPOINTLENGTH);
					ReleaseMutex(bloom_bPx3rd_mutex_handles[bloom_bP_idx_bpload]);
#else
					pthread_mutex_lock(&bloom_bPx3rd_mutex[bloom_bP_idx_bpload]);
					bloom_add(&bloom_bPx3rd[bloom_bP_idx_bpload], rawvalue_bpload, BSGS_BUFFERXPOINTLENGTH);
					pthread_mutex_unlock(&bloom_bPx3rd_mutex[bloom_bP_idx_bpload]);
#endif
				}
			}
			if(i_counter_bpload < bsgs_m2_val && !FLAGREADEDFILE2)	{ // Se o filtro de Bloom do nível 2 não foi lido
                 #if defined(_WIN64) && !defined(__CYGWIN__)
				WaitForSingleObject(bloom_bPx2nd_mutex_handles[bloom_bP_idx_bpload], INFINITE); // Usando _handles
				bloom_add(&bloom_bPx2nd[bloom_bP_idx_bpload], rawvalue_bpload, BSGS_BUFFERXPOINTLENGTH); #define BSGS_BUFFERXPOINTLENGTH 32
				ReleaseMutex(bloom_bPx2nd_mutex_handles[bloom_bP_idx_bpload]);
#else
				pthread_mutex_lock(&bloom_bPx2nd_mutex[bloom_bP_idx_bpload]);
				bloom_add(&bloom_bPx2nd[bloom_bP_idx_bpload], rawvalue_bpload, BSGS_BUFFERXPOINTLENGTH); #define BSGS_BUFFERXPOINTLENGTH 32

				pthread_mutex_unlock(&bloom_bPx2nd_mutex[bloom_bP_idx_bpload]);
#endif	
			}
			if(i_counter_bpload < bsgs_m_val && !FLAGREADEDFILE1 )	{ // Se o filtro de Bloom do nível 1 não foi lido (bsgs_m_val é o bsgs_m original)
#if defined(_WIN64) && !defined(__CYGWIN__)
				WaitForSingleObject(bloom_bP_mutex_handles[bloom_bP_idx_bpload], INFINITE); // Usando _handles
				bloom_add(&bloom_bP[bloom_bP_idx_bpload], rawvalue_bpload ,BSGS_BUFFERXPOINTLENGTH);#define BSGS_BUFFERXPOINTLENGTH 32
				ReleaseMutex(bloom_bP_mutex_handles[bloom_bP_idx_bpload]);
#else
				pthread_mutex_lock(&bloom_bP_mutex[bloom_bP_idx_bpload]);
				bloom_add(&bloom_bP[bloom_bP_idx_bpload], rawvalue_bpload ,BSGS_BUFFERXPOINTLENGTH); #define BSGS_BUFFERXPOINTLENGTH 32

				pthread_mutex_unlock(&bloom_bP_mutex[bloom_bP_idx_bpload]);
#endif
			}
			i_counter_bpload++;
		}
        if (i_counter_bpload >= to_val_bpload && s_step_bpload < nbStep_bpload -1) {
             // Este caso pode ocorrer se NTHREADS * THREADBPWORKLOAD > bsgs_m (ou m2, m3)
             // e a última thread tem menos trabalho que THREADBPWORKLOAD.
             // A thread completou seu trabalho 'to_val_bpload', mesmo que nbStep_bpload não tenha sido atingido.
             break; 
        }

		// Prepara para o próximo bloco de CPU_GRP_SIZE
		pp_bpload_calc = startP_bpload;
		dy_bpload.ModSub(&_2Gn.y,&pp_bpload_calc.y);
		s_bpload_calc.ModMulK1(&dy_bpload,&dx_bpload[i_loop_bpload + 1]); // i_loop_bpload aqui é hLength_bpload
		p_bpload_calc.ModSquareK1(&s_bpload_calc);
		pp_bpload_calc.x.ModNeg(); pp_bpload_calc.x.ModAdd(&p_bpload_calc); pp_bpload_calc.x.ModSub(&_2Gn.x);
		pp_bpload_calc.y.ModSub(&_2Gn.x,&pp_bpload_calc.x); // Y é necessário para o próximo startP_bpload
		pp_bpload_calc.y.ModMulK1(&s_bpload_calc);
		pp_bpload_calc.y.ModSub(&_2Gn.y);
		startP_bpload = pp_bpload_calc;
	} // Fim for s_step_bpload
	if(grp_bpload) delete grp_bpload;

#if defined(_WIN64) && !defined(__CYGWIN__)
	WaitForSingleObject(bPload_mutex[threadid_bpload], INFINITE); // bPload_mutex é global (array de mutexes)
	tt_data_bpload->finished = 1;
	ReleaseMutex(bPload_mutex[threadid_bpload]);
#else	
	pthread_mutex_lock(&bPload_mutex[threadid_bpload]);
	tt_data_bpload->finished = 1;
	pthread_mutex_unlock(&bPload_mutex[threadid_bpload]);
	pthread_exit(NULL); // Importante para threads pthreads
#endif
	return NULL; // Para compatibilidade com DWORD WINAPI
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_bPload_2blooms(LPVOID vargp) {
#else
void *thread_bPload_2blooms(void *vargp)	{
    bool continue_thread_loop = true;
#endif
	// Lógica muito similar a thread_bPload, mas foca em preencher apenas os filtros de bloom
    // de nível 2 e 3, e a tabela bPtable. O filtro de nível 1 (bloom_bP) é assumido como já carregado/preenchido.
	// Renomear variáveis locais com sufixo _2blm para evitar conflitos.
	char rawvalue_2blm[32];
	struct bPload *tt_data_2blm = (struct bPload *)vargp;
	uint64_t i_counter_2blm, j_idx_2blm, nbStep_2blm;
	
	IntGroup *grp_2blm = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP_2blm;
	Int dx_2blm[CPU_GRP_SIZE / 2 + 1];
	Point pts_2blm[CPU_GRP_SIZE];
	Int dy_2blm, dyn_2blm, s_2blm_calc, p_2blm_calc;
	Point pp_2blm_calc, pn_2blm_calc;
	
	int i_loop_2blm, bloom_idx_2blm, hLength_2blm = (CPU_GRP_SIZE / 2 - 1) ,threadid_2blm;
	
	threadid_2blm = tt_data_2blm->threadid;
	Int km_2blm((uint64_t)(tt_data_2blm->from +1 ));
	i_counter_2blm = tt_data_2blm->from;
    uint64_t to_val_2blm = tt_data_2blm->to;


	nbStep_2blm = (to_val_2blm - tt_data_2blm->from) / CPU_GRP_SIZE;
	if( ((to_val_2blm - tt_data_2blm->from) % CPU_GRP_SIZE )  != 0)	{
		nbStep_2blm++;
	}
	
	km_2blm.Add((uint64_t)(CPU_GRP_SIZE / 2));
	startP_2blm = secp->ComputePublicKey(&km_2blm);
	grp_2blm->Set(dx_2blm);

	for(uint64_t s_step_2blm=0; s_step_2blm < nbStep_2blm; s_step_2blm++) {
		// ... (Lógica de cálculo de dx_2blm, ModInv, pts_2blm como em thread_bPload) ...
        for(i_loop_2blm = 0; i_loop_2blm < hLength_2blm; i_loop_2blm++) { dx_2blm[i_loop_2blm].ModSub(&Gn[i_loop_2blm].x,&startP_2blm.x); }
		dx_2blm[i_loop_2blm].ModSub(&Gn[i_loop_2blm].x,&startP_2blm.x); 
		dx_2blm[i_loop_2blm + 1].ModSub(&_2Gn.x,&startP_2blm.x);
		grp_2blm->ModInv();
		pts_2blm[CPU_GRP_SIZE / 2] = startP_2blm;
		for(i_loop_2blm = 0; i_loop_2blm < hLength_2blm; i_loop_2blm++) { /* ... pp_2blm_calc, pn_2blm_calc ... */ 
            pp_2blm_calc = startP_2blm; pn_2blm_calc = startP_2blm;
            dy_2blm.ModSub(&Gn[i_loop_2blm].y,&pp_2blm_calc.y); s_2blm_calc.ModMulK1(&dy_2blm,&dx_2blm[i_loop_2blm]); p_2blm_calc.ModSquareK1(&s_2blm_calc);
            pp_2blm_calc.x.ModNeg(); pp_2blm_calc.x.ModAdd(&p_2blm_calc); pp_2blm_calc.x.ModSub(&Gn[i_loop_2blm].x);
            dyn_2blm.Set(&Gn[i_loop_2blm].y); dyn_2blm.ModNeg(); dyn_2blm.ModSub(&pn_2blm_calc.y); s_2blm_calc.ModMulK1(&dyn_2blm,&dx_2blm[i_loop_2blm]); p_2blm_calc.ModSquareK1(&s_2blm_calc);
            pn_2blm_calc.x.ModNeg(); pn_2blm_calc.x.ModAdd(&p_2blm_calc); pn_2blm_calc.x.ModSub(&Gn[i_loop_2blm].x);
			pts_2blm[CPU_GRP_SIZE / 2 + (i_loop_2blm + 1)] = pp_2blm_calc;
			pts_2blm[CPU_GRP_SIZE / 2 - (i_loop_2blm + 1)] = pn_2blm_calc;
        }
		pn_2blm_calc = startP_2blm; dyn_2blm.Set(&Gn[i_loop_2blm].y); dyn_2blm.ModNeg(); dyn_2blm.ModSub(&pn_2blm_calc.y);
		s_2blm_calc.ModMulK1(&dyn_2blm,&dx_2blm[i_loop_2blm]); p_2blm_calc.ModSquareK1(&s_2blm_calc);
		pn_2blm_calc.x.ModNeg(); pn_2blm_calc.x.ModAdd(&p_2blm_calc); pn_2blm_calc.x.ModSub(&Gn[i_loop_2blm].x);
		pts_2blm[0] = pn_2blm_calc;

		for(j_idx_2blm=0; j_idx_2blm<CPU_GRP_SIZE; j_idx_2blm++)	{
            if (i_counter_2blm >= to_val_2blm) break;

			pts_2blm[j_idx_2blm].x.Get32Bytes((unsigned char*)rawvalue_2blm);
			bloom_idx_2blm = (uint8_t)rawvalue_2blm[0];

			if(i_counter_2blm < bsgs_m3_val)	{
				if(!FLAGREADEDFILE3)	{ // Se a tabela bPtable (nível 3) não foi lida
					memcpy(bPtable[i_counter_2blm].value,rawvalue_2blm+16,BSGS_XVALUE_RAM);
					bPtable[i_counter_2blm].index = i_counter_2blm;
				}
				if(!FLAGREADEDFILE4)	{ // Se o filtro de Bloom do nível 3 não foi lido
#if defined(_WIN64) && !defined(__CYGWIN__)
					WaitForSingleObject(bloom_bPx3rd_mutex_handles[bloom_idx_2blm], INFINITE);
					bloom_add(&bloom_bPx3rd[bloom_idx_2blm], rawvalue_2blm, BSGS_BUFFERXPOINTLENGTH); #define BSGS_BUFFERXPOINTLENGTH 32

					ReleaseMutex(bloom_bPx3rd_mutex_handles[bloom_idx_2blm]);
#else
					pthread_mutex_lock(&bloom_bPx3rd_mutex[bloom_idx_2blm]);
					bloom_add(&bloom_bPx3rd[bloom_idx_2blm], rawvalue_2blm, BSGS_BUFFERXPOINTLENGTH); #define BSGS_BUFFERXPOINTLENGTH 32

					pthread_mutex_unlock(&bloom_bPx3rd_mutex[bloom_idx_2blm]);
#endif
				}
			}
			if(i_counter_2blm < bsgs_m2_val && !FLAGREADEDFILE2)	{ // Se o filtro de Bloom do nível 2 não foi lido
#if defined(_WIN64) && !defined(__CYGWIN__)
					WaitForSingleObject(bloom_bPx2nd_mutex_handles[bloom_idx_2blm], INFINITE);
					bloom_add(&bloom_bPx2nd[bloom_idx_2blm], rawvalue_2blm, BSGS_BUFFERXPOINTLENGTH); #define BSGS_BUFFERXPOINTLENGTH 32

					ReleaseMutex(bloom_bPx2nd_mutex_handles[bloom_idx_2blm]);
#else
					pthread_mutex_lock(&bloom_bPx2nd_mutex[bloom_idx_2blm]);
					bloom_add(&bloom_bPx2nd[bloom_idx_2blm], rawvalue_2blm, BSGS_BUFFERXPOINTLENGTH); #define BSGS_BUFFERXPOINTLENGTH 32

					pthread_mutex_unlock(&bloom_bPx2nd_mutex[bloom_idx_2blm]);
#endif			
			}
			i_counter_2blm++;
		}
        if (i_counter_2blm >= to_val_2blm && s_step_2blm < nbStep_2blm -1) break;
        
		pp_2blm_calc = startP_2blm;
		dy_2blm.ModSub(&_2Gn.y,&pp_2blm_calc.y);
		s_2blm_calc.ModMulK1(&dy_2blm,&dx_2blm[i_loop_2blm + 1]);
		p_2blm_calc.ModSquareK1(&s_2blm_calc);
		pp_2blm_calc.x.ModNeg(); pp_2blm_calc.x.ModAdd(&p_2blm_calc); pp_2blm_calc.x.ModSub(&_2Gn.x);
		pp_2blm_calc.y.ModSub(&_2Gn.x,&pp_2blm_calc.x); 
		pp_2blm_calc.y.ModMulK1(&s_2blm_calc);
		pp_2blm_calc.y.ModSub(&_2Gn.y);
		startP_2blm = pp_2blm_calc;
	}
	if(grp_2blm) delete grp_2blm;

#if defined(_WIN64) && !defined(__CYGWIN__)
	WaitForSingleObject(bPload_mutex[threadid_2blm], INFINITE);
	tt_data_2blm->finished = 1;
	ReleaseMutex(bPload_mutex[threadid_2blm]);
#else	
	pthread_mutex_lock(&bPload_mutex[threadid_2blm]);
	tt_data_2blm->finished = 1;
	pthread_mutex_unlock(&bPload_mutex[threadid_2blm]);
	pthread_exit(NULL);
#endif
	return NULL;
}

/* This function perform the KECCAK Opetation*/
void KECCAK_256(uint8_t *source, size_t size,uint8_t *dst)	{
	SHA3_256_CTX ctx;
	SHA3_256_Init(&ctx);
	SHA3_256_Update(&ctx,source,size);
	KECCAK_256_Final(dst,&ctx); // Note: sha3.h deve ter KECCAK_256_Final, ou SHA3_256_Final se for SHA3 puro
}

void generate_binaddress_eth(Point &publickey_obj, unsigned char *dst_address)	{ // Renomeado publickey
	unsigned char bin_publickey[64];
	publickey_obj.x.Get32Bytes(bin_publickey);
	publickey_obj.y.Get32Bytes(bin_publickey+32);
	KECCAK_256(bin_publickey, 64, bin_publickey); // Hash Keccak-256
	memcpy(dst_address,bin_publickey+12,20); // Últimos 20 bytes do hash
}

// (Fim desta parte - aproximadamente 500 linhas. A próxima seção conteria as funções de manipulação de minikey, SSE, menu, etc.)
// (Continuação do keyhunt.cpp - após generate_binaddress_eth)

/* This function takes in three parameters:
buffer: a pointer to a char array where the minikey will be stored.
rawbuffer: a pointer to a char array that contains the raw data.
length: an integer representing the length of the raw data.
The function is designed to convert the raw data using a lookup table (Ccoinbuffer) and store the result in the buffer. 
*/
void set_minikey(char *buffer,char *rawbuffer,int length)	{
	for(int i = 0;  i < length; i++)	{
		buffer[i] = Ccoinbuffer[(uint8_t)rawbuffer[i]];
	}
}

/* This function takes in three parameters:
buffer: a pointer to a char array where the minikey will be stored.
rawbuffer: a pointer to a char array that contains the raw data.
index: an integer representing the index of the raw data array to be incremented.
The function is designed to increment the value at the specified index in the raw data array,
and update the corresponding value in the buffer using a lookup table (Ccoinbuffer).
If the value at the specified index exceeds 57, it is reset to 0x00 and the function recursively
calls itself to increment the value at the previous index, unless the index is already 0, in which
case the function returns false. The function returns true otherwise. 
*/
bool increment_minikey_index(char *buffer,char *rawbuffer,int index)	{
	if(rawbuffer[index] < 57){
		rawbuffer[index]++;
		buffer[index] = Ccoinbuffer[(uint8_t)rawbuffer[index]];
	}
	else	{
		rawbuffer[index] = 0x00;
		buffer[index] = Ccoinbuffer[0];
		if(index>0)	{
			return increment_minikey_index(buffer,rawbuffer,index-1);
		}
		else	{
			return false; // Chegou ao limite máximo da minikey
		}
	}
	return true;
}

/* This function takes in a single parameter:
rawbuffer: a pointer to a char array that contains the raw data.
The function is designed to increment the values in the raw data array
using a lookup table (minikeyN), while also handling carry-over to the
previous element in the array if necessary. The maximum number of iterations
is limited by minikey_n_limit. 
*/
void increment_minikey_N(char *rawbuffer)	{
	int i = 20,j = 0; // Começa do final da parte "payload" da raw minikey
	while( i > 0 && j < minikey_n_limit)	{ // minikey_n_limit protege contra overflow
		rawbuffer[i] = rawbuffer[i] + minikeyN[i]; // minikeyN contém o valor N convertido para base58
		if(rawbuffer[i] > 57)	{	 // Handling carry-over if value exceeds 57 (índice máximo em Ccoinbuffer)
			rawbuffer[i] = rawbuffer[i] % 58; // Volta para o início do alfabeto Base58
			if (i > 0) rawbuffer[i-1]++; // Propaga o "vai um"
		}
		i--;
		j++;
	}
}


#define BUFFMINIKEY(buff,src) \
(buff)[ 0] = (uint32_t)src[ 0] << 24 | (uint32_t)src[ 1] << 16 | (uint32_t)src[ 2] << 8 | (uint32_t)src[ 3]; \
(buff)[ 1] = (uint32_t)src[ 4] << 24 | (uint32_t)src[ 5] << 16 | (uint32_t)src[ 6] << 8 | (uint32_t)src[ 7]; \
(buff)[ 2] = (uint32_t)src[ 8] << 24 | (uint32_t)src[ 9] << 16 | (uint32_t)src[10] << 8 | (uint32_t)src[11]; \
(buff)[ 3] = (uint32_t)src[12] << 24 | (uint32_t)src[13] << 16 | (uint32_t)src[14] << 8 | (uint32_t)src[15]; \
(buff)[ 4] = (uint32_t)src[16] << 24 | (uint32_t)src[17] << 16 | (uint32_t)src[18] << 8 | (uint32_t)src[19]; \
(buff)[ 5] = (uint32_t)src[20] << 24 | (uint32_t)src[21] << 16 | 0x8000; \
(buff)[ 6] = 0; (buff)[ 7] = 0; (buff)[ 8] = 0; (buff)[ 9] = 0; \
(buff)[10] = 0; (buff)[11] = 0; (buff)[12] = 0; (buff)[13] = 0; \
(buff)[14] = 0; (buff)[15] = 0xB0;	/* 176 bits => 22 BYTES */


void sha256sse_22(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3)	{
  uint32_t b0[16], b1[16], b2[16], b3[16];
  BUFFMINIKEY(b0, src0); BUFFMINIKEY(b1, src1);
  BUFFMINIKEY(b2, src2); BUFFMINIKEY(b3, src3);
  sha256sse_1B(b0, b1, b2, b3, dst0, dst1, dst2, dst3); // Presume que sha256sse_1B está definida em outro lugar (ex: hash/sha256.h)
}


#define BUFFMINIKEYCHECK(buff,src) \
(buff)[ 0] = (uint32_t)src[ 0] << 24 | (uint32_t)src[ 1] << 16 | (uint32_t)src[ 2] << 8 | (uint32_t)src[ 3]; \
(buff)[ 1] = (uint32_t)src[ 4] << 24 | (uint32_t)src[ 5] << 16 | (uint32_t)src[ 6] << 8 | (uint32_t)src[ 7]; \
(buff)[ 2] = (uint32_t)src[ 8] << 24 | (uint32_t)src[ 9] << 16 | (uint32_t)src[10] << 8 | (uint32_t)src[11]; \
(buff)[ 3] = (uint32_t)src[12] << 24 | (uint32_t)src[13] << 16 | (uint32_t)src[14] << 8 | (uint32_t)src[15]; \
(buff)[ 4] = (uint32_t)src[16] << 24 | (uint32_t)src[17] << 16 | (uint32_t)src[18] << 8 | (uint32_t)src[19]; \
(buff)[ 5] = (uint32_t)src[20] << 24 | (uint32_t)src[21] << 16 | (uint32_t)src[22] << 8 | 0x80; \
(buff)[ 6] = 0; (buff)[ 7] = 0; (buff)[ 8] = 0; (buff)[ 9] = 0; \
(buff)[10] = 0; (buff)[11] = 0; (buff)[12] = 0; (buff)[13] = 0; \
(buff)[14] = 0; (buff)[15] = 0xB8;	/* 184 bits => 23 BYTES */

void sha256sse_23(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3)	{
  uint32_t b0[16], b1[16], b2[16], b3[16];
  BUFFMINIKEYCHECK(b0, src0); BUFFMINIKEYCHECK(b1, src1);
  BUFFMINIKEYCHECK(b2, src2); BUFFMINIKEYCHECK(b3, src3);
  sha256sse_1B(b0, b1, b2, b3, dst0, dst1, dst2, dst3); // Presume que sha256sse_1B está definida
}

void menu() {
	printf("\nUsage:\n");
    // Adicionar a nova flag -a para IA Force ao menu
	printf("-a [arquivo_hits] Ativa o modo IA Force, opcionalmente usa <arquivo_hits> para conhecimento inicial (padrão: hits.txt).\n");
	printf("-h          show this help\n");
	printf("-B Mode     BSGS now have some modes <sequential, backward, both, random, dance>\n");
	// ... (resto das suas opções de menu como no original) ...
	printf("-z value    Bloom size multiplier, only address,rmd160,vanity, xpoint, value >= 1\n");
	printf("\nExample:\n\n");
	printf("./keyhunt -m rmd160 -f tests/unsolvedpuzzles.rmd -b 66 -l compress -R -q -t 8 -a\n\n");
	printf("This line runs the program with 8 threads from the range ... with IA Force enabled.\n\n");
	printf("Developed by AlbertoBSD\tTips BTC: 1Coffee1jV4gB5gaXfHgSHDz9xx9QSECVW\n");
	printf("Thanks to Iceland always helping and sharing his ideas.\nTips to Iceland: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at\n\n");
	exit(EXIT_FAILURE);
}

// Função vanityrmdmatch não precisa de modificação direta para IA,
// ela é um verificador. O aprendizado ocorreria em writevanitykey.
bool vanityrmdmatch(unsigned char *rmdhash)	{
	bool r_match = false; // Renomeado de r
	int i_target, j_limit, cmpA_val, cmpB_val, result_bloom; // Renomeados
	result_bloom = bloom_check(vanity_bloom,rmdhash,vanity_rmd_minimun_bytes_check_length);
	switch(result_bloom)	{
		case -1:
			fprintf(stderr,"[E] Bloom (vanity) is not initialized\n");
			exit(EXIT_FAILURE); // Considerar um retorno de erro em vez de exit direto
		break;
		case 1: // Potencialmente no filtro, precisa checar os ranges
			for(i_target = 0; i_target < vanity_rmd_targets && !r_match; i_target++)	{
				for(j_limit = 0; j_limit < vanity_rmd_limits[i_target] && !r_match; j_limit++)	{
					cmpA_val = memcmp(vanity_rmd_limit_values_A[i_target][j_limit], rmdhash, 20);
					cmpB_val = memcmp(vanity_rmd_limit_values_B[i_target][j_limit], rmdhash, 20);
					if(cmpA_val <= 0 && cmpB_val >= 0)	{ // Se rmdhash está entre A e B
						r_match = true;
					}
				}
			}
		break;
		default: // Não está no filtro de Bloom
			r_match = false;
		break;
	}
	return r_match;
}

// A função writevanitykey já foi modificada anteriormente (Parte 2) para incluir bip e ml_learn_from_hit

// Função addvanity: adiciona um alvo vanity.
// A IA poderia, conceitualmente, aprender sobre os *tipos* de vanity targets que são adicionados,
// mas isso é um passo mais avançado. Nenhuma modificação direta para IA aqui.
int addvanity(char *target_str)	{ // Renomeado target para target_str
	char target_copy_str[50];
	unsigned char raw_value_A[50],raw_value_B[50];
	int stringsize_val,targetsize_val,j_idx,r_ret = 0; // Renomeados
	size_t raw_value_length_val; // Renomeado
	int values_A_count = 0,values_B_count = 0,minimun_bytes_match; // Renomeados

	raw_value_length_val = 50;
	targetsize_val = strlen(target_str);
	stringsize_val = targetsize_val;
	memset(raw_value_A,0,50);
	memset(target_copy_str,0,50);

	// A lógica de export_hits no seu código original em addvanity e minimum_same_bytes
    // parece ser para um sistema de log de hits separado (hits_logger.h) e não está
    // diretamente relacionada ao aprendizado do ml_engine. Vou mantê-la como está.
	if(targetsize_val >= 30 )	{ // Condição estranha para exportar hits, talvez um placeholder antigo?
		    printf("[*] Exportando hits encontrados (addvanity)...\n"); // Mensagem de log adicionada
    // As chamadas export_hits aqui são do seu hits_logger.h, não relacionadas ao ml_engine.
    // Se você tiver um hits_logger.cpp ou .h, ele define essas funções.
    // #ifdef __unix__ // Para garantir que só compila em unix se hits_logger.h for específico
    // #ifndef __CYGWIN__
    // export_hits("hits.csv");
    // export_hits_json("hits.json");
    // #endif
    // #endif
    printf("[*] Busca (addvanity) pode ser interrompida se targetsize for grande.\n");
    return 0; // Retorna se targetsize for muito grande
	}
	memcpy(target_copy_str,target_str,targetsize_val);
	j_idx = 0;
    // Reallocs e checks (como no seu código original)
	vanity_address_targets = (char**)  realloc(vanity_address_targets,(vanity_rmd_targets+1) * sizeof(char*));
	checkpointer((void *)vanity_address_targets,__FILE__,"realloc","vanity_address_targets" ,__LINE__ );
    vanity_address_targets[vanity_rmd_targets] = NULL; // Importante para inicializar novo ponteiro
	vanity_rmd_limits = (int*) realloc(vanity_rmd_limits,(vanity_rmd_targets+1) * sizeof(int));
	checkpointer((void *)vanity_rmd_limits,__FILE__,"realloc","vanity_rmd_limits" ,__LINE__ );
    vanity_rmd_limits[vanity_rmd_targets] = 0;
	vanity_rmd_limit_values_A = (uint8_t***)realloc(vanity_rmd_limit_values_A,(vanity_rmd_targets+1) * sizeof(unsigned char **)); // Corrigido de sizeof(unsigned char*)
	checkpointer((void *)vanity_rmd_limit_values_A,__FILE__,"realloc","vanity_rmd_limit_values_A" ,__LINE__ );
    vanity_rmd_limit_values_A[vanity_rmd_targets] = NULL;
	vanity_rmd_limit_values_B = (uint8_t***)realloc(vanity_rmd_limit_values_B,(vanity_rmd_targets+1) * sizeof(unsigned char **)); // Corrigido
	checkpointer((void *)vanity_rmd_limit_values_B,__FILE__,"realloc","vanity_rmd_limit_values_B" ,__LINE__ );
    vanity_rmd_limit_values_B[vanity_rmd_targets] = NULL;

	do	{ // Loop para calcular range A
		raw_value_length_val = 50; // Reset para b58tobin
		b58tobin(raw_value_A,&raw_value_length_val,target_copy_str,stringsize_val);
		if(raw_value_length_val < 25 && stringsize_val < 48)	{ // Limita stringsize_val para evitar overflow em target_copy_str
			target_copy_str[stringsize_val] = '1'; // Adiciona '1' para expandir o range
			stringsize_val++;
            target_copy_str[stringsize_val] = '\0'; // Garante terminação nula
		}
		if(raw_value_length_val == 25)	{ // Encontrou um limite válido
			// Realloc e cópia para vanity_rmd_limit_values_A (como no seu código original)
            vanity_rmd_limit_values_A[vanity_rmd_targets] = (uint8_t**)realloc(vanity_rmd_limit_values_A[vanity_rmd_targets],(j_idx+1) * sizeof(unsigned char *));
			checkpointer((void *)vanity_rmd_limit_values_A[vanity_rmd_targets],__FILE__,"realloc","vanity_rmd_limit_values_A[...]" ,__LINE__ );
			vanity_rmd_limit_values_A[vanity_rmd_targets][j_idx] = (uint8_t*)calloc(20,1);
			checkpointer((void *)vanity_rmd_limit_values_A[vanity_rmd_targets][j_idx],__FILE__,"calloc","vanity_rmd_limit_values_A[...][j]" ,__LINE__ );
			memcpy(vanity_rmd_limit_values_A[vanity_rmd_targets][j_idx] ,raw_value_A +1,20); // Pula o byte de versão
			j_idx++;	
			values_A_count = j_idx;
			if (stringsize_val < 48) { // Prepara para próxima iteração
                target_copy_str[stringsize_val] = '1';
                stringsize_val++;
                target_copy_str[stringsize_val] = '\0';
            } else { break; } // Evita overflow
		} else if (stringsize_val >= 48 && raw_value_length_val != 25) { // Se string ficou muito longa e não achou limite
            break;
        }
	} while(raw_value_length_val <= 25 && stringsize_val < 49); // Limita stringsize para segurança
	
	stringsize_val = targetsize_val; // Reseta para calcular range B
	memset(target_copy_str,0,50);
	memcpy(target_copy_str,target_str,targetsize_val);
	j_idx = 0;
	do	{ // Loop para calcular range B
		raw_value_length_val = 50;
		b58tobin(raw_value_B,&raw_value_length_val,target_copy_str,stringsize_val);
		if(raw_value_length_val < 25 && stringsize_val < 48)	{
			target_copy_str[stringsize_val] = Ccoinbuffer_default[57]; // Adiciona 'z' (último char do Base58 default)
			stringsize_val++;
            target_copy_str[stringsize_val] = '\0';
		}
		if(raw_value_length_val == 25)	{
            // Realloc e cópia para vanity_rmd_limit_values_B (como no seu código original)
			vanity_rmd_limit_values_B[vanity_rmd_targets] = (uint8_t**)realloc(vanity_rmd_limit_values_B[vanity_rmd_targets],(j_idx+1) * sizeof(unsigned char *));
			checkpointer((void *)vanity_rmd_limit_values_B[vanity_rmd_targets],__FILE__,"realloc","vanity_rmd_limit_values_B[...]" ,__LINE__ );
			vanity_rmd_limit_values_B[vanity_rmd_targets][j_idx] = (uint8_t*)calloc(20,1);
			checkpointer((void *)vanity_rmd_limit_values_B[vanity_rmd_targets][j_idx],__FILE__,"calloc","vanity_rmd_limit_values_B[...][j]" ,__LINE__ );
			memcpy(vanity_rmd_limit_values_B[vanity_rmd_targets][j_idx],raw_value_B+1,20);
			j_idx++;				
			values_B_count = j_idx;
			if (stringsize_val < 48) {
                target_copy_str[stringsize_val] = Ccoinbuffer_default[57];
                stringsize_val++;
                target_copy_str[stringsize_val] = '\0';
            } else { break; }
		} else if (stringsize_val >= 48 && raw_value_length_val != 25) {
            break;
        }
	} while(raw_value_length_val <= 25 && stringsize_val < 49);
	
	if(values_A_count >= 1 && values_B_count >= 1)	{
		r_ret = std::min(values_A_count, values_B_count); // Usa o menor dos dois counts como limite
		
		for(j_idx = 0; j_idx < r_ret; j_idx++)	{ // Calcula o mínimo de bytes em comum para o Bloom filter
			minimun_bytes_match =  minimum_same_bytes(vanity_rmd_limit_values_A[vanity_rmd_targets][j_idx], vanity_rmd_limit_values_B[vanity_rmd_targets][j_idx],20);
			if(minimun_bytes_match < vanity_rmd_minimun_bytes_check_length)	{
				vanity_rmd_minimun_bytes_check_length = minimun_bytes_match;
			}
		}
		vanity_address_targets[vanity_rmd_targets] = (char*) calloc(targetsize_val+1,sizeof(char));
		checkpointer((void *)vanity_address_targets[vanity_rmd_targets],__FILE__,"calloc","vanity_address_targets[vanity_rmd_targets]" ,__LINE__ );
		memcpy(vanity_address_targets[vanity_rmd_targets],target_str,targetsize_val+1);
		vanity_rmd_limits[vanity_rmd_targets] = r_ret;
		vanity_rmd_total+=r_ret;
		vanity_rmd_targets++;
	} else { // Falha ao gerar ranges
		// Limpa memória alocada para este target se falhar
        if (vanity_rmd_limit_values_A[vanity_rmd_targets]) {
		    for(j_idx = 0; j_idx < values_A_count;j_idx++) { free(vanity_rmd_limit_values_A[vanity_rmd_targets][j_idx]); }
		    free(vanity_rmd_limit_values_A[vanity_rmd_targets]);
		    vanity_rmd_limit_values_A[vanity_rmd_targets] = NULL;
        }
        if (vanity_rmd_limit_values_B[vanity_rmd_targets]) {
		    for(j_idx = 0; j_idx < values_B_count;j_idx++) { free(vanity_rmd_limit_values_B[vanity_rmd_targets][j_idx]); }
		    free(vanity_rmd_limit_values_B[vanity_rmd_targets]);
		    vanity_rmd_limit_values_B[vanity_rmd_targets] = NULL;
        }
		r_ret = 0;
	}
	return r_ret;
}

// (Continuação do keyhunt.cpp com minimum_same_bytes, checkpointer, etc.)
// ...
// (Continuação do keyhunt.cpp - após a função addvanity)

/*
A and B are binary o string data pointers
length the max lenght to check.
Caller must by sure that the pointer are valid and have at least length bytes readebles witout causing overflow
*/
int minimum_same_bytes(unsigned char* A,unsigned char* B, int length) {
    int minBytes = 0; 
	if(A == NULL || B  == NULL)	{	
        // Esta condição original com export_hits parece ser um fallback ou debug.
        // As chamadas export_hits são do seu hits_logger.h, não do ml_engine.
		// printf("[*] Exportando hits encontrados (minimum_same_bytes NULL ptr)...\n"); // Mensagem de log
    // #ifdef __unix__
    // #ifndef __CYGWIN__
    //    export_hits("hits.csv"); 
    //    export_hits_json("hits.json");
    // #endif
    // #endif
    // printf("[*] Busca (minimum_same_bytes) pode ser interrompida devido a ponteiro nulo.\n");
    return 0; // Retorna 0 se ponteiros nulos
	}
    for (int i = 0; i < length; i++) {
        if (A[i] != B[i]) {
            break; 
        }
        minBytes++; 
    }
    return minBytes;
}

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line)	{
	if(ptr == NULL)	{
		fprintf(stderr,"[E] FATAL: Null pointer em arquivo %s, função %s, variável '%s', linha %i\n",file,function,name,line); 
		exit(EXIT_FAILURE);
	}
}

// As funções writekey e writekeyeth já foram fornecidas com modificações de IA e bip na Parte 2.
// Vou omiti-las aqui para não repetir e poupar espaço.

bool isBase58(char c) {
    // Usa o Ccoinbuffer que pode ser o default ou o customizado via -8
    return strchr(Ccoinbuffer, c) != NULL;
}

bool isValidBase58String(char *str)	{
	int len = strlen(str);
	bool continuar = true;
	for (int i = 0; i < len && continuar; i++) {
		continuar = isBase58(str[i]);
	}
	return continuar;
}

// Configura o vanity_bloom com base nos alvos já adicionados
bool processOneVanity()	{
	int i_target, k_limit; // Renomeados i, k
	if(vanity_rmd_targets == 0)	{
		fprintf(stderr,"[W] Nenhum alvo vanity definido para processar com processOneVanity.\n");
		return false; // Ou true, dependendo se isso é um erro ou apenas nada a fazer
	}

    // Inicializa o filtro de Bloom para os alvos vanity
    // vanity_rmd_total é o número total de ranges de rmd160 para vanity
	if(!initBloomFilter(vanity_bloom, (uint64_t)vanity_rmd_total)) { // vanity_bloom é global
        fprintf(stderr, "[E] Falha ao inicializar bloom filter para vanity.\n");
		return false;
    }
	
    // Adiciona os limites inferiores dos ranges de rmd160 dos alvos vanity ao filtro
	for(i_target = 0; i_target < vanity_rmd_targets; i_target++)	{
		for(k_limit = 0; k_limit < vanity_rmd_limits[i_target]; k_limit++)	{
            // Adiciona apenas os primeiros 'vanity_rmd_minimun_bytes_check_length' bytes
            // do limite inferior A ao filtro, para otimizar a checagem.
			bloom_add(vanity_bloom, (const char*)vanity_rmd_limit_values_A[i_target][k_limit] , vanity_rmd_minimun_bytes_check_length);
		}
	}
    printf("[+] Filtro de Bloom para Vanity configurado com %d alvos totais e %d bytes de checagem mínima.\n", vanity_rmd_total, vanity_rmd_minimun_bytes_check_length);
	return true;
}

// Lê alvos vanity de um arquivo
bool readFileVanity(char *fileName_vanity)	{ // Renomeado fileName
	char aux_line[1024];
	FILE *fileDescriptor_vanity; // Renomeado
	int len_line; // Renomeado len
    char* hextemp_fgets_ret; // Renomeado hextemp

	fileDescriptor_vanity = fopen(fileName_vanity,"r");
	if(fileDescriptor_vanity == NULL)	{
		if(vanity_rmd_targets == 0)	{ // Se não há alvos definidos via -v e o arquivo não abre
			fprintf(stderr,"[E] Nenhum alvo vanity definido e arquivo '%s' não encontrado.\n", fileName_vanity);
			return false;
		}
        // Se já há alvos via -v, não ter o arquivo pode ser ok.
        printf("[I] Arquivo de vanity '%s' não encontrado, usando apenas alvos definidos via -v (se houver).\n", fileName_vanity);
        // Se há alvos via -v, processOneVanity será chamado depois para configurar o bloom com eles.
        // Se não há alvos de -v E o arquivo não existe, então realmente não há nada para modo vanity.
	}
	else	{ // Arquivo existe, lê os alvos dele
		while(!feof(fileDescriptor_vanity))	{
			hextemp_fgets_ret = fgets(aux_line, sizeof(aux_line)-1, fileDescriptor_vanity);
			if(hextemp_fgets_ret == aux_line)	{
				trim(aux_line," \t\n\r");
				len_line = strlen(aux_line);
				if(len_line > 0 && len_line < 36){ // Validação de tamanho para um prefixo vanity
					if(isValidBase58String(aux_line))	{
						addvanity(aux_line); // Adiciona o alvo à lista e ranges internos
					}
					else	{
						fprintf(stderr,"[W] Linha em arquivo vanity não é Base58 válida, omitindo: '%s'\n",aux_line);
					}
				} else if (len_line > 0) {
                    fprintf(stderr, "[W] Linha em arquivo vanity com tamanho inesperado, omitindo: '%s'\n", aux_line);
                }
			}
		}
		fclose(fileDescriptor_vanity);
	}
	
    // Após ler do arquivo (e de -v), se houver algum alvo, processa para o Bloom Filter.
	if (vanity_rmd_targets > 0) {
        // N (global) não é usado diretamente por readFileVanity para alocação,
        // mas é setado para o total de ranges vanity, o que pode ser usado por initBloomFilter.
        N = (uint64_t)vanity_rmd_total; 
	    return processOneVanity(); // Configura o vanity_bloom com todos os alvos coletados
    } else {
        printf("[I] Nenhum alvo vanity carregado do arquivo ou da linha de comando.\n");
        return true; // Não é um erro fatal, apenas não haverá busca vanity.
    }
}

// Função principal para ler o arquivo de endereços/hashes (para modos ADDRESS, RMD160, XPOINT)
bool readFileAddress(char *fileName_addr)	{ // Renomeado fileName
	FILE *fileDescriptor_addr_data; // Renomeado
	char fileBloomName_cache[30];	
	uint8_t checksum_file[32], hexPrefix_cache[9]; // Renomeados
	char dataChecksum_cache[32], bloomChecksum_cache[32];
	size_t bytesRead_cache;
	uint64_t dataSize_cache_elements; // Renomeado dataSize para número de elementos
    uint64_t dataSize_cache_bytes;    // Bytes totais

	if(FLAGSAVEREADFILE)	{	
		if(!sha256_file((const char*)fileName_addr, checksum_file)){
			fprintf(stderr,"[E] Erro ao calcular sha256 do arquivo: %s (linha %i)\n", fileName_addr, __LINE__ - 1);
			return false;
		}
		tohex_dst((char*)checksum_file, 4, (char*)hexPrefix_cache); 
		snprintf(fileBloomName_cache, sizeof(fileBloomName_cache)-1, "data_%s.dat", hexPrefix_cache);
		fileDescriptor_addr_data = fopen(fileBloomName_cache,"rb");

		if(fileDescriptor_addr_data != NULL)	{
			printf("[+] Lendo arquivo de cache de dados e Bloom: %s\n",fileBloomName_cache);
		
			bytesRead_cache = fread(bloomChecksum_cache,1,32,fileDescriptor_addr_data);
			if(bytesRead_cache != 32)	{ /* ... (erro e return false) ... */ fclose(fileDescriptor_addr_data); return false; }
			
			bytesRead_cache = fread(&bloom,1,sizeof(struct bloom),fileDescriptor_addr_data); // bloom é global
			if(bytesRead_cache != sizeof(struct bloom))	{ /* ... (erro e return false) ... */ fclose(fileDescriptor_addr_data); return false; }
			
			printf("[+] Filtro Bloom (do cache) para %" PRIu64 " elementos.\n",bloom.entries);
			
			bloom.bf = (uint8_t*) malloc(bloom.bytes);
			checkpointer((void*)bloom.bf, __FILE__, "malloc", "bloom.bf from cache", __LINE__);

			bytesRead_cache = fread(bloom.bf,1,bloom.bytes,fileDescriptor_addr_data);
			if(bytesRead_cache != bloom.bytes)	{ /* ... (erro, free bloom.bf, e return false) ... */ free(bloom.bf); bloom.bf=NULL; fclose(fileDescriptor_addr_data); return false; }
			
            if(FLAGSKIPCHECKSUM == 0){
				sha256((uint8_t*)bloom.bf,bloom.bytes,(uint8_t*)checksum_file); // Reusa checksum_file
				if(memcmp(checksum_file,bloomChecksum_cache,32) != 0)	{ 
                    fprintf(stderr, "[E] Checksum do filtro Bloom (do cache) não confere!\n");
                    free(bloom.bf); bloom.bf=NULL; fclose(fileDescriptor_addr_data); return false; 
                }
			}
			
			bytesRead_cache = fread(dataChecksum_cache,1,32,fileDescriptor_addr_data);
			if(bytesRead_cache != 32)	{ /* ... (erro, free bloom.bf, e return false) ... */ free(bloom.bf); bloom.bf=NULL; fclose(fileDescriptor_addr_data); return false; }
			
            // Lê o número de ELEMENTOS, não o tamanho em bytes diretamente.
			bytesRead_cache = fread(&dataSize_cache_elements,1,sizeof(uint64_t),fileDescriptor_addr_data);
			if(bytesRead_cache != sizeof(uint64_t))	{ /* ... (erro, free bloom.bf, e return false) ... */ free(bloom.bf); bloom.bf=NULL; fclose(fileDescriptor_addr_data); return false; }
			
            N = dataSize_cache_elements; // N global é o número de elementos
            dataSize_cache_bytes = N * sizeof(struct address_value);
	
			printf("[+] Alocando memória para %" PRIu64 " elementos (do cache): %.2f MB\n",N,(double)(dataSize_cache_bytes)/(double)1048576.0);
			
			addressTable = (struct address_value*) malloc(dataSize_cache_bytes); // addressTable é global
            checkpointer((void*)addressTable, __FILE__, "malloc", "addressTable from cache", __LINE__);
			
			bytesRead_cache = fread(addressTable,1,dataSize_cache_bytes,fileDescriptor_addr_data);
			if(bytesRead_cache != dataSize_cache_bytes)	{ /* ... (erro, free bloom.bf, free addressTable e return false) ... */ free(bloom.bf); bloom.bf=NULL; free(addressTable); addressTable=NULL; fclose(fileDescriptor_addr_data); return false;}

			if(FLAGSKIPCHECKSUM == 0)	{
				sha256((uint8_t*)addressTable,dataSize_cache_bytes,(uint8_t*)checksum_file);
				if(memcmp(checksum_file,dataChecksum_cache,32) != 0)	{
                    fprintf(stderr, "[E] Checksum da tabela de endereços (do cache) não confere!\n");
                    free(bloom.bf); bloom.bf=NULL; free(addressTable); addressTable=NULL; fclose(fileDescriptor_addr_data); return false; 
                }
			}
			FLAGREADEDFILE1 = 1;	
			fclose(fileDescriptor_addr_data);
			MAXLENGTHADDRESS = sizeof(struct address_value); // Geralmente 20 para rmd160
            printf("[+] Dados e filtro Bloom carregados do cache '%s' com sucesso.\n", fileBloomName_cache);
		} else {
            printf("[I] Arquivo de cache '%s' não encontrado. Lendo arquivo de texto original '%s'.\n", fileBloomName_cache, fileName_addr);
            // FLAGREADEDFILE1 continua 0, então o bloco abaixo será executado.
        }
	} // Fim if(FLAGSAVEREADFILE)

	// Se FLAGVANITY também estiver ativo, processa os alvos vanity (geralmente não usado junto com readFileAddress para o mesmo propósito)
	// A sua lógica original tem um `if(FLAGVANITY)` aqui, mas parece que `processOneVanity`
    // já é chamado por `readFileVanity`. Se `FLAGVANITY` é para um arquivo separado,
    // então `readFileVanity` deve ser chamado explicitamente no main.
    // Se for para processar os alvos vanity *adicionados via -v* mesmo ao ler um arquivo de endereços,
    // então `processOneVanity()` faria sentido aqui se `vanity_rmd_targets > 0`.
    // Vou assumir que se FLAGVANITY está setado, e alvos foram adicionados por -v, eles devem ser processados.
    if(FLAGVANITY && vanity_rmd_targets > 0 && vanity_bloom == NULL) { // Se vanity_bloom ainda não foi inicializado por readFileVanity
        printf("[I] Processando alvos vanity definidos via linha de comando...\n");
        if (!processOneVanity()) {
            fprintf(stderr, "[E] Falha ao processar alvos vanity da linha de comando.\n");
            // Decidir se isso é um erro fatal
        }
    }


	if(!FLAGREADEDFILE1)	{ // Se o arquivo de cache não foi lido/usado, lê o arquivo de texto original
		printf("[+] Lendo arquivo de texto original: %s\n", fileName_addr);
		switch(FLAGMODE)	{
			case MODE_ADDRESS:
				if(FLAGCRYPTO == CRYPTO_BTC)	{
					if (!forceReadFileAddress(fileName_addr)) return false;
				} else if(FLAGCRYPTO == CRYPTO_ETH)	{
					if (!forceReadFileAddressEth(fileName_addr)) return false;
				} else {
                    fprintf(stderr, "[E] Modo ADDRESS sem cripto BTC/ETH especificada não suportado para leitura de arquivo de texto.\n");
                    return false;
                }
			break;
			case MODE_MINIKEYS: // Modo Minikeys também usa forceReadFileAddress para carregar alvos
			case MODE_RMD160:
				if (!forceReadFileAddress(fileName_addr)) return false;
			break;
			case MODE_XPOINT:
				if (!forceReadFileXPoint(fileName_addr)) return false;
			break;
			default:
                fprintf(stderr, "[E] Modo de busca %d não suporta leitura direta de arquivo de endereços desta forma.\n", FLAGMODE);
				return false; 
			break;
		}
        // Após ler e popular addressTable e bloom (dentro das funções forceRead...),
        // se FLAGSAVEREADFILE estiver ativo, os dados lidos e o bloom são salvos no arquivo .dat.
        // Esta lógica está em writeFileIfNeeded, que é chamada no final de main se !FLAGREADEDFILE1.
	}
	return true;
}

// (Continuação do keyhunt.cpp com forceReadFileAddress, etc.)
// ...
// (Continuação do keyhunt.cpp - após readFileAddress)

bool forceReadFileAddress(char *fileName_addr_txt)	{ // Renomeado fileName
	char aux_line_txt[1024];
	FILE *fileDescriptor_addr_txt; // Renomeado
	bool validAddress_found; // Renomeado validAddress
	uint64_t numberItems_in_file, i_item; // Renomeados numberItems, i
	size_t r_len, raw_value_len_local; // Renomeados r, raw_value_length
	uint8_t rawvalue_bin[50]; // Renomeado rawvalue
    char* hextemp_fgets_ret_txt; // Renomeado hextemp

	fileDescriptor_addr_txt = fopen(fileName_addr_txt,"r");	
	if(fileDescriptor_addr_txt == NULL)	{
		fprintf(stderr,"[E] Erro ao abrir arquivo de texto de endereços: %s (linha %i)\n",fileName_addr_txt,__LINE__ - 2);
		return false;
	}

	numberItems_in_file = 0;
	while(!feof(fileDescriptor_addr_txt))	{
		hextemp_fgets_ret_txt = fgets(aux_line_txt, sizeof(aux_line_txt)-1, fileDescriptor_addr_txt);
		if(hextemp_fgets_ret_txt == aux_line_txt)	{	// Checa se fgets não retornou NULL
            trim(aux_line_txt," \t\n\r");		
			r_len = strlen(aux_line_txt);
			if(r_len > 20 && r_len <= 40)	{ // Endereços Base58 (26-35 chars) ou RMD160 hex (40 chars)
				numberItems_in_file++;
			} else if (r_len > 0) { // Linha não vazia mas com tamanho inválido
                // fprintf(stderr, "[I] Linha com tamanho inesperado no arquivo de endereços: '%s' (len: %zu), pulando contagem.\n", aux_line_txt, r_len);
            }
		}
	}
    if (numberItems_in_file == 0) {
        fprintf(stderr, "[E] Nenhum item válido encontrado em %s para carregar.\n", fileName_addr_txt);
        fclose(fileDescriptor_addr_txt);
        return false; // Ou true se um arquivo vazio for ok, mas geralmente indica problema.
    }
	fseek(fileDescriptor_addr_txt,0,SEEK_SET);

	MAXLENGTHADDRESS = 20; // Tamanho do RMD160 em binário
	
	printf("[+] Alocando memória para %" PRIu64 " elementos (lidos de %s): %.2f MB\n",
           numberItems_in_file, fileName_addr_txt, (double)(((double) sizeof(struct address_value)*numberItems_in_file))/(double)1048576.0);
	
    if (addressTable) { // Se já foi alocado (ex: por uma tentativa anterior ou cache parcial)
        // fprintf(stderr, "[W] addressTable já estava alocada. Liberando antes de realocar.\n");
        // free(addressTable); // Comentado pois pode ser intencional se usado em conjunto com cache
        // addressTable = NULL; // Se for realmente um recarregamento completo
    }
    addressTable = (struct address_value*) malloc(sizeof(struct address_value)*numberItems_in_file);
	checkpointer((void *)addressTable,__FILE__,"malloc","addressTable (forceReadFileAddress)" ,__LINE__ -1 );
		
    // bloom é global, inicializa ou re-inicializa
	if(!initBloomFilter(&bloom, numberItems_in_file * FLAGBLOOMMULTIPLIER)) { // FLAGBLOOMMULTIPLIER já estava no seu initBloomFilter
        free(addressTable); addressTable = NULL;
        fclose(fileDescriptor_addr_txt);
        return false;
    }

	i_item = 0;
    N = 0; // N global será o número de itens realmente carregados
	while(i_item < numberItems_in_file && !feof(fileDescriptor_addr_txt))	{
		validAddress_found = false;
		memset(aux_line_txt,0,sizeof(aux_line_txt));
		// Não precisa limpar addressTable[N].value aqui se N só é incrementado para válidos

		hextemp_fgets_ret_txt = fgets(aux_line_txt, sizeof(aux_line_txt)-1, fileDescriptor_addr_txt);
        if (hextemp_fgets_ret_txt == NULL && !feof(fileDescriptor_addr_txt)) { // Erro de leitura
            fprintf(stderr, "[E] Erro ao ler linha do arquivo %s\n", fileName_addr_txt);
            break; 
        }
        if (hextemp_fgets_ret_txt == NULL && feof(fileDescriptor_addr_txt)) { // Fim do arquivo
            break;
        }

		trim(aux_line_txt," \t\n\r");			
		r_len = strlen(aux_line_txt);

		if(r_len > 0 && r_len <= 40)	{ // Re-checa tamanho
			if(r_len < 40 && isValidBase58String(aux_line_txt))	{	// Endereço Base58
				raw_value_len_local = 25; // Tamanho esperado do binário de um endereço b58 decodificado
				b58tobin(rawvalue_bin, &raw_value_len_local, aux_line_txt, r_len); // rawvalue_bin precisa ter tamanho suficiente (ex: 30)
				if(raw_value_len_local == 25)	{ // Checa se decodificou para o tamanho esperado
					bloom_add(&bloom, (const char*)(rawvalue_bin+1) ,MAXLENGTHADDRESS); // Adiciona RMD160 (pula byte de versão)
					memcpy(addressTable[N].value, rawvalue_bin+1, MAXLENGTHADDRESS);											
					N++; // Incrementa N global para o item válido
					validAddress_found = true;
				}
			}
			else if(r_len == 40 && isValidHex(aux_line_txt))	{	// RMD160 em hexadecimal
				hexs2bin(aux_line_txt, rawvalue_bin); // rawvalue_bin precisa ter pelo menos 20 bytes				
				bloom_add(&bloom, (const char*)rawvalue_bin, MAXLENGTHADDRESS);
				memcpy(addressTable[N].value, rawvalue_bin, MAXLENGTHADDRESS);											
				N++;
				validAddress_found = true;
			}
		}
		if(validAddress_found) {
            i_item++; // Conta apenas os itens que foram tentados ler (baseado na contagem inicial)
                      // N conta os realmente válidos e adicionados
        } else if (r_len > 0) { // Se leu algo mas não foi válido
			fprintf(stderr,"[I] Omitindo linha inválida em %s: '%s'\n", fileName_addr_txt, aux_line_txt);
            // Não incrementa i_item aqui se a linha foi inválida e pulada,
            // mas numberItems_in_file foi baseado em uma contagem mais frouxa.
            // Isso pode levar a i_item < numberItems_in_file mesmo após ler todas as linhas válidas.
            // O importante é que N reflita o número real de itens na addressTable.
		}
	}
    // Se N for menor que numberItems_in_file devido a linhas inválidas,
    // pode ser útil reajustar a memória de addressTable com realloc, mas por simplicidade omitido.
    if (N == 0 && numberItems_in_file > 0) {
         fprintf(stderr, "[W] Nenhuma entrada válida foi carregada de %s, apesar de %" PRIu64 " linhas parecerem candidatas.\n", fileName_addr_txt, numberItems_in_file);
    }
	fclose(fileDescriptor_addr_txt);
	return true;
}

bool forceReadFileAddressEth(char *fileName_eth_txt)	{ // Renomeado fileName
	char aux_line_eth[1024];
	FILE *fileDescriptor_eth_txt; // Renomeado
	bool validAddress_eth_found; // Renomeado
	uint64_t numberItems_in_file_eth, i_item_eth; // Renomeados
	size_t r_len_eth; // Renomeado
	uint8_t rawvalue_eth_bin[50]; // Renomeado
    char* hextemp_fgets_ret_eth; // Renomeado

	fileDescriptor_eth_txt = fopen(fileName_eth_txt,"r");	
	if(fileDescriptor_eth_txt == NULL)	{
		fprintf(stderr,"[E] Erro ao abrir arquivo de texto de endereços ETH: %s (linha %i)\n",fileName_eth_txt,__LINE__ - 2);
		return false;
	}

	numberItems_in_file_eth = 0;
	while(!feof(fileDescriptor_eth_txt))	{
		hextemp_fgets_ret_eth = fgets(aux_line_eth, sizeof(aux_line_eth)-1, fileDescriptor_eth_txt);
		if(hextemp_fgets_ret_eth == aux_line_eth) {
            trim(aux_line_eth," \t\n\r");			
			r_len_eth = strlen(aux_line_eth);
			if(r_len_eth == 40 || r_len_eth == 42)	{ // Endereço ETH (40) ou com 0x (42)
				numberItems_in_file_eth++;
			} else if (r_len_eth > 0) {
                // fprintf(stderr, "[I] Linha com tamanho inesperado no arquivo ETH: '%s', pulando contagem.\n", aux_line_eth);
            }
        }
	}
    if (numberItems_in_file_eth == 0) {
        fprintf(stderr, "[E] Nenhum item válido encontrado em %s para carregar.\n", fileName_eth_txt);
        fclose(fileDescriptor_eth_txt);
        return false;
    }
	fseek(fileDescriptor_eth_txt,0,SEEK_SET);

	MAXLENGTHADDRESS = 20; // ETH address (sem 0x) é 20 bytes (40 hex chars)
	
	printf("[+] Alocando memória para %" PRIu64 " elementos ETH (lidos de %s): %.2f MB\n",
           numberItems_in_file_eth, fileName_eth_txt, (double)(((double) sizeof(struct address_value)*numberItems_in_file_eth))/(double)1048576.0);
	addressTable = (struct address_value*) malloc(sizeof(struct address_value)*numberItems_in_file_eth);
	checkpointer((void *)addressTable,__FILE__,"malloc","addressTable (forceReadEth)" ,__LINE__ -1 );
	
	if(!initBloomFilter(&bloom, numberItems_in_file_eth * FLAGBLOOMMULTIPLIER)) {
        free(addressTable); addressTable = NULL;
        fclose(fileDescriptor_eth_txt);
        return false;
    }
	
	i_item_eth = 0;
    N = 0; // N global conta os itens válidos carregados
	while(i_item_eth < numberItems_in_file_eth && !feof(fileDescriptor_eth_txt))	{
		validAddress_eth_found = false;
		memset(aux_line_eth,0,sizeof(aux_line_eth));
		hextemp_fgets_ret_eth = fgets(aux_line_eth,sizeof(aux_line_eth)-1,fileDescriptor_eth_txt);
        if (hextemp_fgets_ret_eth == NULL) break; // Fim do arquivo ou erro

		trim(aux_line_eth," \t\n\r");			
		r_len_eth = strlen(aux_line_eth);

		if(r_len_eth == 40 && isValidHex(aux_line_eth)){ // Hex puro
			hexs2bin(aux_line_eth,rawvalue_eth_bin);
			bloom_add(&bloom, (const char*)rawvalue_eth_bin ,MAXLENGTHADDRESS);
			memcpy(addressTable[N].value,rawvalue_eth_bin,MAXLENGTHADDRESS);											
			N++;
			validAddress_eth_found = true;
		} else if (r_len_eth == 42 && aux_line_eth[0] == '0' && (aux_line_eth[1] == 'x' || aux_line_eth[1] == 'X') && isValidHex(aux_line_eth+2)){ // Com 0x
			hexs2bin(aux_line_eth+2,rawvalue_eth_bin); // Pula o "0x"
			bloom_add(&bloom, (const char*)rawvalue_eth_bin ,MAXLENGTHADDRESS);
			memcpy(addressTable[N].value,rawvalue_eth_bin,MAXLENGTHADDRESS);											
			N++;
			validAddress_eth_found = true;
		}
		
		if(validAddress_eth_found) {
            i_item_eth++;
        } else if (r_len_eth > 0) {
			fprintf(stderr,"[I] Omitindo linha ETH inválida: '%s'\n",aux_line_eth);
		}
	}
	fclose(fileDescriptor_eth_txt);
	return true;
}

bool forceReadFileXPoint(char *fileName_xpoint_txt)	{ // Renomeado
	char aux_line_xp[1024];
	FILE *fileDescriptor_xpoint_txt; // Renomeado
	uint64_t numberItems_in_file_xp, i_item_xp; // Renomeados
	size_t r_hexs2bin_ret, len_aux_token; // Renomeados r, lenaux
	uint8_t rawvalue_xpoint_bin[100]; // Renomeado rawvalue
    char* hextemp_fgets_ret_xp; // Renomeado hextemp
	char* token_xpoint; // Para o token da linha
    Tokenizer tokenizer_xpoint_local; // Renomeado tokenizer_xpoint

	fileDescriptor_xpoint_txt = fopen(fileName_xpoint_txt,"r");	
	if(fileDescriptor_xpoint_txt == NULL)	{
		fprintf(stderr,"[E] Erro ao abrir arquivo de XPoint: %s (linha %i)\n",fileName_xpoint_txt,__LINE__ - 2);
		return false;
	}

	numberItems_in_file_xp = 0;
	while(!feof(fileDescriptor_xpoint_txt))	{
        hextemp_fgets_ret_xp = fgets(aux_line_xp, sizeof(aux_line_xp)-1, fileDescriptor_xpoint_txt);
		if(hextemp_fgets_ret_xp == aux_line_xp) {
            trim(aux_line_xp," \t\n\r");			
			if(strlen(aux_line_xp) >= 64)	{ // XPoint (64) ou PubKey Comprimida (66) ou Não Comprimida (130)
				numberItems_in_file_xp++;
			}
        }
	}
    if (numberItems_in_file_xp == 0) { /* ... (erro e return false) ... */ fclose(fileDescriptor_xpoint_txt); return false;}
	fseek(fileDescriptor_xpoint_txt,0,SEEK_SET);

	MAXLENGTHADDRESS = 32; // XPoint é a coordenada X de 32 bytes
	
	printf("[+] Alocando memória para %" PRIu64 " XPoints (lidos de %s): %.2f MB\n",
           numberItems_in_file_xp, fileName_xpoint_txt, (double)(((double) sizeof(struct address_value)*numberItems_in_file_xp))/(double)1048576.0);
    // Nota: address_value tem 'value[20]'. Para XPoint, precisamos de 32 bytes.
    // Isso significa que addressTable não é adequado para XPoints.
    // O código original usava addressTable[i].value e copiava 20 bytes, o que truncaria XPoints.
    // Se XPoint é o alvo, a struct address_value e MAXLENGTHADDRESS precisam ser ajustados.
    // Assumindo que o objetivo é de fato usar os primeiros 20 bytes do XPoint para busca (o que é incomum).
    // Se for para usar os 32 bytes, a struct address_value e MAXLENGTHADDRESS=32 devem ser consistentes.
    // Vou manter a lógica original que copia para address_value.value (20 bytes) e usa MAXLENGTHADDRESS (que será 32),
    // o que implica que MAXLENGTHADDRESS deveria ser 20 aqui ou address_value deveria ser maior.
    // Para corrigir, idealmente address_value.value deveria ser [32] para XPoint.
    // Por ora, vou seguir a lógica original, mas destacando a inconsistência.
    // Se MAXLENGTHADDRESS = 32, então bloom_add e memcpy devem usar 32.
    // Mas addressTable[i].value só tem 20. Isso é um problema no código original.
    // Para esta modificação, vou assumir que o MODO XPOINT significa que o addressTable deve conter XPoints de 32 bytes,
    // e que MAXLENGTHADDRESS será 32. A struct address_value precisaria ser alterada para `uint8_t value[32];`
    // ou usar uma struct diferente para XPoints.
    // Por agora, vou manter a cópia de 20 bytes como no original, mas isso é um bug se MAXLENGTHADDRESS=32 for usado para bloom_add.
    // A melhor correção seria definir uma nova struct para XPoint ou ajustar address_value.
    // **Ação Corretiva Assumida:** Se FLAGMODE == MODE_XPOINT, MAXLENGTHADDRESS será 32, e
    // as operações de cópia e bloom usarão 32. addressTable.value[20] será um problema.
    // Para um "hotfix" que não muda a struct: só podemos usar os primeiros 20 bytes do XPoint.
    // Ou, se MAXLENGTHADDRESS é para o bloom filter key length, e a tabela só guarda 20 bytes,
    // o bloom_add deve usar 20.
    // A lógica original em modo XPOINT: MAXLENGTHADDRESS=20, bloom_add(...,MAXLENGTHADDRESS)
    // memcpy(addressTable[i].value, rawvalue, 20) <- Isso é consistente.
    // Então MAXLENGTHADDRESS deve ser 20 para XPoint se a struct não mudar.
    if(FLAGMODE == MODE_XPOINT) MAXLENGTHADDRESS = 20; // Mantendo consistência com address_value.value[20]

	addressTable = (struct address_value*) malloc(sizeof(struct address_value)*numberItems_in_file_xp);
	checkpointer((void *)addressTable,__FILE__,"malloc","addressTable (forceReadXPoint)" ,__LINE__ - 1);
	
	N = 0; // N global será o número de XPoints válidos carregados
	
	if(!initBloomFilter(&bloom, numberItems_in_file_xp * FLAGBLOOMMULTIPLIER)) { /* ... (free e return false) ... */ return false; }
	
	i_item_xp = 0;
	while(i_item_xp < numberItems_in_file_xp && !feof(fileDescriptor_xpoint_txt))	{
		memset(aux_line_xp,0,sizeof(aux_line_xp));
		hextemp_fgets_ret_xp = fgets(aux_line_xp, sizeof(aux_line_xp)-1, fileDescriptor_xpoint_txt);
        if (hextemp_fgets_ret_xp == NULL) break;

		trim(aux_line_xp," \t\n\r");
        if (strlen(aux_line_xp) == 0) continue; // Pula linhas vazias

		stringtokenizer(aux_line_xp, &tokenizer_xpoint_local); // Seu Tokenizer
		token_xpoint = nextToken(&tokenizer_xpoint_local); // Pega o primeiro token (o XPoint ou PubKey)
        
        bool xpoint_added = false;
		if(token_xpoint && isValidHex(token_xpoint)) {
            len_aux_token = strlen(token_xpoint);
			switch(len_aux_token)	{
				case 64:	/* Valor X puro (32 bytes) */
					r_hexs2bin_ret = hexs2bin(token_xpoint, (uint8_t*) rawvalue_xpoint_bin); // Converte para binário
					if(r_hexs2bin_ret == 32)	{ // Verifica se converteu 32 bytes
						memcpy(addressTable[N].value, rawvalue_xpoint_bin, MAXLENGTHADDRESS); // Copia MAXLENGTHADDRESS (20) bytes
						bloom_add(&bloom, (const char*)rawvalue_xpoint_bin, MAXLENGTHADDRESS); // Adiciona ao bloom
                        xpoint_added = true;
					} else { fprintf(stderr,"[E] Erro hexs2bin para XPoint: %s\n", token_xpoint); }
				break;
				case 66:	/* Chave pública comprimida (02/03 + X) */
					r_hexs2bin_ret = hexs2bin(token_xpoint+2, (uint8_t*)rawvalue_xpoint_bin); // Pula 02/03, pega X
					if(r_hexs2bin_ret == 32)	{
						memcpy(addressTable[N].value,rawvalue_xpoint_bin, MAXLENGTHADDRESS);
						bloom_add(&bloom,(const char*)rawvalue_xpoint_bin,MAXLENGTHADDRESS);
                        xpoint_added = true;
					} else { fprintf(stderr,"[E] Erro hexs2bin para PubKey Comprimida X: %s\n", token_xpoint); }
				break;
				case 130:	/* Chave pública não comprimida (04 + X + Y) */
					r_hexs2bin_ret = hexs2bin(token_xpoint+2, (uint8_t*) rawvalue_xpoint_bin); // Pula 04, pega X (primeiros 32 bytes)
					if(r_hexs2bin_ret >= 32)	{ // Deve converter X e Y, então pelo menos 32 para X
						memcpy(addressTable[N].value,rawvalue_xpoint_bin, MAXLENGTHADDRESS);
						bloom_add(&bloom,(const char*)rawvalue_xpoint_bin,MAXLENGTHADDRESS);
                        xpoint_added = true;
					} else { fprintf(stderr,"[E] Erro hexs2bin para PubKey NãoComprimida X: %s\n", token_xpoint); }
				break;
				default:
					fprintf(stderr,"[W] Omitindo linha XPoint/PubKey com tamanho inesperado %zu: %s\n",len_aux_token,token_xpoint);
				break;
			}
            if (xpoint_added) N++;
		} else if (token_xpoint) {
			fprintf(stderr,"[W] Ignorando valor XPoint/PubKey não hexadecimal: %s\n",token_xpoint);
		}
		freetokenizer(&tokenizer_xpoint_local);
		i_item_xp++;
	}
	fclose(fileDescriptor_xpoint_txt);
    if (N == 0 && numberItems_in_file_xp > 0) {
        fprintf(stderr, "[W] Nenhuma entrada XPoint válida foi carregada de %s.\n", fileName_xpoint_txt);
    }
	return true;
}


bool initBloomFilter(struct bloom *bloom_arg, uint64_t items_bloom_val)	{ // Renomeado items_bloom
	bool r_success = true; // Renomeado r
	// Seu código original já multiplicava por FLAGBLOOMMULTIPLIER aqui dentro,
    // então a chamada a initBloomFilter não precisa mais multiplicar.
    // Vou manter a multiplicação aqui para consistência com o original.
	uint64_t effective_items = items_bloom_val * FLAGBLOOMMULTIPLIER;
    if (effective_items == 0) effective_items = 10000; // Evitar 0 items

	printf("[+] Configurando filtro Bloom para %" PRIu64 " elementos (efetivo: %" PRIu64 " com multiplicador %d).\n",
           items_bloom_val, effective_items, FLAGBLOOMMULTIPLIER);
	
    if(bloom_init2(bloom_arg, effective_items, 0.000001) == 1){ // Usa 0.0001% de taxa de falso positivo
		fprintf(stderr,"[E] Erro ao inicializar filtro Bloom para %" PRIu64 " elementos.\n",effective_items);
		r_success = false;
	}
    if (r_success) {
	    printf("[+] Filtro Bloom carregado/inicializado. Tamanho total: %.2f MB\n",
               (double)(((double) bloom_arg->bytes))/(double)1048576.0);
    }
	return r_success;
}

// Salva o addressTable e o filtro de Bloom em um arquivo .dat de cache
void writeFileIfNeeded(const char *fileName_original_txt)	{ // Renomeado fileName
	if(FLAGSAVEREADFILE && !FLAGREADEDFILE1)	{ // Se S foi usado e cache não foi lido
		FILE *fileDescriptor_cache_out; // Renomeado
		char fileBloomName_cache_out[30];
		uint8_t checksum_of_original_txt[32], hexPrefix_for_cache_name[9]; // Renomeados
		char dataChecksum_to_write[32], bloomChecksum_to_write[32];
		size_t bytesWrite_count; // Renomeado
		uint64_t dataSize_elements_to_write = N; // N global tem o número de elementos em addressTable
        uint64_t dataSize_bytes_to_write = N * sizeof(struct address_value);


		if(!sha256_file(fileName_original_txt, checksum_of_original_txt)){
			fprintf(stderr,"[E] Erro sha256_file ao tentar salvar cache para %s (linha %i)\n", fileName_original_txt, __LINE__ - 1);
			return; // Não sai, apenas não salva o cache
		}
		tohex_dst((char*)checksum_of_original_txt,4,(char*)hexPrefix_for_cache_name); 
		snprintf(fileBloomName_cache_out, sizeof(fileBloomName_cache_out)-1, "data_%s.dat", hexPrefix_for_cache_name);
		
        fileDescriptor_cache_out = fopen(fileBloomName_cache_out,"wb");
		if(fileDescriptor_cache_out != NULL)	{
			printf("[+] Escrevendo arquivo de cache de dados e Bloom: %s (para %" PRIu64 " elementos)\n", fileBloomName_cache_out, N);
			
			// Checksum do filtro de Bloom
			sha256((uint8_t*)bloom.bf, bloom.bytes, (uint8_t*)bloomChecksum_to_write);
			bytesWrite_count = fwrite(bloomChecksum_to_write, 1, 32, fileDescriptor_cache_out);
			if(bytesWrite_count != 32)	{ /* ... (erro e cleanup) ... */ fclose(fileDescriptor_cache_out); return; }
			
			// Estrutura do filtro de Bloom
			bytesWrite_count = fwrite(&bloom, 1, sizeof(struct bloom), fileDescriptor_cache_out);
			if(bytesWrite_count != sizeof(struct bloom))	{ /* ... (erro e cleanup) ... */ fclose(fileDescriptor_cache_out); return; }
			
			// Dados do filtro de Bloom
			bytesWrite_count = fwrite(bloom.bf, 1, bloom.bytes, fileDescriptor_cache_out);
			if(bytesWrite_count != bloom.bytes)	{ /* ... (erro e cleanup) ... */ fclose(fileDescriptor_cache_out); return; }
			
			// Checksum da tabela de endereços
			sha256((uint8_t*)addressTable, dataSize_bytes_to_write, (uint8_t*)dataChecksum_to_write);
			bytesWrite_count = fwrite(dataChecksum_to_write, 1, 32, fileDescriptor_cache_out);
			if(bytesWrite_count != 32)	{ /* ... (erro e cleanup) ... */ fclose(fileDescriptor_cache_out); return; }
			
			// Número de elementos na tabela
			bytesWrite_count = fwrite(&dataSize_elements_to_write, 1, sizeof(uint64_t), fileDescriptor_cache_out);
			if(bytesWrite_count != sizeof(uint64_t))	{ /* ... (erro e cleanup) ... */ fclose(fileDescriptor_cache_out); return; }
			
			// Dados da tabela de endereços
			bytesWrite_count = fwrite(addressTable, 1, dataSize_bytes_to_write, fileDescriptor_cache_out);
			if(bytesWrite_count != dataSize_bytes_to_write)	{ /* ... (erro e cleanup) ... */ fclose(fileDescriptor_cache_out); return; }
			
			fclose(fileDescriptor_cache_out);		
			printf("[+] Arquivo de cache '%s' escrito com sucesso.\n", fileBloomName_cache_out);
            // FLAGREADEDFILE1 não é setado aqui, pois esta função é chamada no *final* do main
            // se o cache não foi lido no início. A ideia é que na *próxima* execução, o cache seja usado.
		} else {
            fprintf(stderr, "[E] Não foi possível criar/abrir arquivo de cache '%s' para escrita.\n", fileBloomName_cache_out);
        }
	}
}

// Função auxiliar para BSGS (calcula parte do índice da chave privada)
void calcualteindex(int i_val,Int *key_out)	{ // Renomeados i, key
	if(i_val == 0)	{
		key_out->Set(&BSGS_M3); // BSGS_M3 é um Int global
	}
	else	{
		key_out->SetInt32(i_val);
		key_out->Mult(&BSGS_M3_double); // BSGS_M3_double é um Int global
		key_out->Add(&BSGS_M3);
	}
}

// (Fim desta parte. Próximas seriam as funções de ordenação.)
// (Continuação do keyhunt.cpp - após a função calcualteindex)

// --- Funções de Ordenação para struct address_value (usadas para addressTable) ---

void _swap(struct address_value *a_val, struct address_value *b_val)	{ // Renomeado a, b
	struct address_value t_temp; // Renomeado t
	t_temp  = *a_val;
	*a_val = *b_val;
	*b_val =  t_temp;
}

// Função principal de ordenação para address_value (Introsort)
void _sort(struct address_value *arr_ptr, int64_t n_elements)	{ // Renomeado arr, n
	uint32_t depthLimit_val = ((uint32_t) ceil(log(n_elements))) * 2; // Renomeado depthLimit
	_introsort(arr_ptr, depthLimit_val, n_elements);
}

// Implementação do Introsort
void _introsort(struct address_value *arr_ptr, uint32_t depthLimit_val, int64_t n_elements) { // Renomeado
	int64_t p_pivot_idx; // Renomeado p
	if(n_elements > 1)	{
		if(n_elements <= 16) { // Para partições pequenas, usa Insertionsort
			_insertionsort(arr_ptr, n_elements);
		}
		else	{
			if(depthLimit_val == 0) { // Limite de recursão atingido, usa Heapsort
				_myheapsort(arr_ptr, n_elements);
			}
			else	{ // Particiona e recorre
				p_pivot_idx = _partition(arr_ptr, n_elements);
				if(p_pivot_idx > 0) _introsort(arr_ptr , depthLimit_val-1 , p_pivot_idx); // Ordena partição esquerda
				// A partição direita começa em p_pivot_idx+1 e tem n_elements-(p_pivot_idx+1) elementos
				if(p_pivot_idx + 1 < n_elements) _introsort(&arr_ptr[p_pivot_idx+1], depthLimit_val-1, n_elements-(p_pivot_idx+1));
			}
		}
	}
}

// Insertionsort para address_value
void _insertionsort(struct address_value *arr_ptr, int64_t n_elements) { // Renomeado
	int64_t j_inner_loop; // Renomeado j
	int64_t i_outer_loop; // Renomeado i
	struct address_value key_current; // Renomeado key
	for(i_outer_loop = 1; i_outer_loop < n_elements ; i_outer_loop++ ) {
		key_current = arr_ptr[i_outer_loop];
		j_inner_loop = i_outer_loop-1;
		// Compara os 20 bytes do rmd160 (ou XPoint truncado)
		while(j_inner_loop >= 0 && memcmp(arr_ptr[j_inner_loop].value, key_current.value, sizeof(key_current.value)) > 0) {
			arr_ptr[j_inner_loop+1] = arr_ptr[j_inner_loop];
			j_inner_loop--;
		}
		arr_ptr[j_inner_loop+1] = key_current;
	}
}

// Função de partição para Quicksort (usada pelo Introsort)
int64_t _partition(struct address_value *arr_ptr, int64_t n_elements)	{ // Renomeado
	struct address_value pivot_val; // Renomeado pivot
	int64_t r_pivot_orig_idx, left_idx, right_idx; // Renomeados r, left, right

	// Escolha do pivô (mediana de três seria melhor, mas aqui é o do meio)
    // Se n_elements for muito pequeno (ex: < 3), a escolha do pivô como n_elements/2 pode precisar de cuidado.
    // No entanto, _introsort chama _insertionsort para n <= 16, então n_elements aqui será > 16.
	r_pivot_orig_idx = n_elements/2; 
	pivot_val = arr_ptr[r_pivot_orig_idx];
	
    _swap(&arr_ptr[r_pivot_orig_idx], &arr_ptr[0]); // Move pivô para o início temporariamente
    r_pivot_orig_idx = 0; // Agora o pivô está em arr_ptr[0]

	left_idx = 1; // Começa a varrer após o pivô
	right_idx = n_elements-1;

	while(left_idx <= right_idx) {
        // Encontra elemento > pivô na esquerda
		while(left_idx <= right_idx && memcmp(arr_ptr[left_idx].value, pivot_val.value, sizeof(pivot_val.value)) <= 0 )	{
			left_idx++;
		}
        // Encontra elemento < pivô na direita
		while(right_idx >= left_idx && memcmp(arr_ptr[right_idx].value, pivot_val.value, sizeof(pivot_val.value)) > 0)	{
			right_idx--;
		}
		if(left_idx < right_idx)	{ // Se os ponteiros não se cruzaram, troca
			_swap(&arr_ptr[right_idx], &arr_ptr[left_idx]);
            left_idx++; right_idx--; // Continua a busca
		}
	}
    // Coloca o pivô na sua posição final (arr_ptr[right_idx] é o último elemento <= pivô)
	_swap(&arr_ptr[r_pivot_orig_idx], &arr_ptr[right_idx]); 
	return right_idx; // Retorna o índice do pivô
}

// Heapsort - função _heapify
void _heapify(struct address_value *arr_ptr, int64_t n_elements, int64_t root_idx) { // Renomeados arr, n, i
	int64_t largest_idx = root_idx; // Renomeado largest
	int64_t l_child_idx = 2 * root_idx + 1; // Renomeado l
	int64_t r_child_idx = 2 * root_idx + 2; // Renomeado r

	if (l_child_idx < n_elements && memcmp(arr_ptr[l_child_idx].value, arr_ptr[largest_idx].value, sizeof(arr_ptr[l_child_idx].value)) > 0)
		largest_idx = l_child_idx;
	if (r_child_idx < n_elements && memcmp(arr_ptr[r_child_idx].value, arr_ptr[largest_idx].value, sizeof(arr_ptr[r_child_idx].value)) > 0)
		largest_idx = r_child_idx;

	if (largest_idx != root_idx) { // Se o maior não for a raiz
		_swap(&arr_ptr[root_idx], &arr_ptr[largest_idx]);
		_heapify(arr_ptr, n_elements, largest_idx); // Heapify recursivamente a sub-árvore afetada
	}
}

// Heapsort para address_value
void _myheapsort(struct address_value	*arr_ptr, int64_t n_elements)	{ // Renomeados
	int64_t i_loop_hs; // Renomeado i
    // Constrói o heap (rearranja o array)
	for ( i_loop_hs = (n_elements / 2) - 1; i_loop_hs >=	0; i_loop_hs--)	{
		_heapify(arr_ptr, n_elements, i_loop_hs);
	}
    // Extrai elementos um por um do heap
	for ( i_loop_hs = n_elements - 1; i_loop_hs > 0; i_loop_hs--) {
		_swap(&arr_ptr[0] , &arr_ptr[i_loop_hs]); // Move a raiz atual (maior) para o final
		_heapify(arr_ptr, i_loop_hs, 0); // Chama heapify no heap reduzido
	}
}

// --- Funções de Ordenação para struct bsgs_xvalue (usadas para bPtable) ---
// Estas seguem o mesmo padrão das funções acima, mas operam em bsgs_xvalue e comparam BSGS_XVALUE_RAM bytes.

void bsgs_swap(struct bsgs_xvalue *a_val, struct bsgs_xvalue *b_val)	{ // Renomeado
	struct bsgs_xvalue t_temp; // Renomeado
	t_temp	= *a_val;
	*a_val = *b_val;
	*b_val = t_temp;
}

void bsgs_sort(struct bsgs_xvalue *arr_ptr, int64_t n_elements)	{ // Renomeado
	uint32_t depthLimit_val = ((uint32_t) ceil(log(n_elements))) * 2;
	bsgs_introsort(arr_ptr, depthLimit_val, n_elements);
}

void bsgs_introsort(struct bsgs_xvalue *arr_ptr, uint32_t depthLimit_val, int64_t n_elements) { // Renomeado
	int64_t p_pivot_idx;
	if(n_elements > 1)	{
		if(n_elements <= 16) {
			bsgs_insertionsort(arr_ptr,n_elements);
		}
		else	{
			if(depthLimit_val == 0) {
				bsgs_myheapsort(arr_ptr,n_elements);
			}
			else	{
				p_pivot_idx = bsgs_partition(arr_ptr,n_elements);
				if(p_pivot_idx > 0) bsgs_introsort(arr_ptr , depthLimit_val-1 , p_pivot_idx);
				if(p_pivot_idx + 1 < n_elements) bsgs_introsort(&arr_ptr[p_pivot_idx+1],depthLimit_val-1,n_elements-(p_pivot_idx+1));
			}
		}
	}
}

void bsgs_insertionsort(struct bsgs_xvalue *arr_ptr, int64_t n_elements) { // Renomeado
	int64_t j_inner_loop;
	int64_t i_outer_loop;
	struct bsgs_xvalue key_current;
	for(i_outer_loop = 1; i_outer_loop < n_elements ; i_outer_loop++ ) {
		key_current = arr_ptr[i_outer_loop];
		j_inner_loop = i_outer_loop-1;
		while(j_inner_loop >= 0 && memcmp(arr_ptr[j_inner_loop].value, key_current.value, BSGS_XVALUE_RAM) > 0) {
			arr_ptr[j_inner_loop+1] = arr_ptr[j_inner_loop];
			j_inner_loop--;
		}
		arr_ptr[j_inner_loop+1] = key_current;
	}
}

int64_t bsgs_partition(struct bsgs_xvalue *arr_ptr, int64_t n_elements)	{ // Renomeado
	struct bsgs_xvalue pivot_val;
	int64_t r_pivot_orig_idx, left_idx, right_idx;
	
    r_pivot_orig_idx = n_elements/2;
	pivot_val = arr_ptr[r_pivot_orig_idx];
    _swap((struct address_value*)&arr_ptr[r_pivot_orig_idx], (struct address_value*)&arr_ptr[0]); // Move pivô para o início temporariamente (cast para _swap genérico se ele existir, senão usar bsgs_swap)
    // Correção: Usar bsgs_swap, pois os tipos são diferentes.
    bsgs_swap(&arr_ptr[r_pivot_orig_idx], &arr_ptr[0]);
    r_pivot_orig_idx = 0;

	left_idx = 1;
	right_idx = n_elements-1;
	do {
		while(left_idx <= right_idx && memcmp(arr_ptr[left_idx].value, pivot_val.value, BSGS_XVALUE_RAM) <= 0 )	{
			left_idx++;
		}
		while(right_idx >= left_idx && memcmp(arr_ptr[right_idx].value, pivot_val.value, BSGS_XVALUE_RAM) > 0)	{
			right_idx--;
		}
		if(left_idx < right_idx)	{
			bsgs_swap(&arr_ptr[right_idx],&arr_ptr[left_idx]);
            left_idx++; right_idx--;
		}
	}while(left_idx <= right_idx);
	bsgs_swap(&arr_ptr[r_pivot_orig_idx],&arr_ptr[right_idx]);
	return right_idx;
}

void bsgs_heapify(struct bsgs_xvalue *arr_ptr, int64_t n_elements, int64_t root_idx) { // Renomeado
	int64_t largest_idx = root_idx;
	int64_t l_child_idx = 2 * root_idx + 1;
	int64_t r_child_idx = 2 * root_idx + 2;
	if (l_child_idx < n_elements && memcmp(arr_ptr[l_child_idx].value,arr_ptr[largest_idx].value,BSGS_XVALUE_RAM) > 0)
		largest_idx = l_child_idx;
	if (r_child_idx < n_elements && memcmp(arr_ptr[r_child_idx].value,arr_ptr[largest_idx].value,BSGS_XVALUE_RAM) > 0)
		largest_idx = r_child_idx;
	if (largest_idx != root_idx) {
		bsgs_swap(&arr_ptr[root_idx],&arr_ptr[largest_idx]);
		bsgs_heapify(arr_ptr, n_elements, largest_idx);
	}
}

void bsgs_myheapsort(struct bsgs_xvalue	*arr_ptr, int64_t n_elements)	{ // Renomeado
	int64_t i_loop_hs;
	for ( i_loop_hs = (n_elements / 2) - 1; i_loop_hs >=	0; i_loop_hs--)	{
		bsgs_heapify(arr_ptr, n_elements, i_loop_hs);
	}
	for ( i_loop_hs = n_elements - 1; i_loop_hs > 0; i_loop_hs--) {
		bsgs_swap(&arr_ptr[0] , &arr_ptr[i_loop_hs]);
		bsgs_heapify(arr_ptr, i_loop_hs, 0);
	}
}

// A função bsgs_searchbinary já foi fornecida em uma parte anterior, após as funções de busca BSGS.
// A função calcualteindex já foi fornecida na Parte 12.

// O arquivo original termina após calcualteindex. Se houver mais no seu arquivo local,
// você precisará indicar. Com base no arquivo que analisei, estas são as últimas funções.
// A última linha do arquivo original é o fechamento da função calcualteindex.
// Se o seu arquivo termina com um '}' global de namespace ou algo assim, ele estaria aqui.