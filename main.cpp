
#include "sealInclude.h"
#include "openssl/evp.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include "cryptopp/elgamal.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#define GMPXX_USE_GMP_H
#include <gmpxx.h>
#include <fstream>  

extern "C" {
    #include <gmp.h>        // GMP header
    #include <paillier.h>   // Paillier header
} 

#define SENDING
#define SEAL_USE_ZSTD 
#define SEAL_USE_ZLIB
using namespace std;
using namespace seal;

char buffer[100];
//-- Update Time function
void updateTime(char* buffer, std::size_t bufferSize) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) % 1000000;
    std::tm* local_time = std::localtime(&now_c);
    std::strftime(buffer, bufferSize, "%H:%M:%S", local_time);
    // Add the microsecond
    snprintf(buffer + std::strlen(buffer), bufferSize - std::strlen(buffer), ".%06ld", microseconds.count());
}

static std::vector<uint8_t> packet;
std::vector<double> data_double;


//El Gamal function used to evaluate the El Gamal packet dimension and the elaboration time
void elGamal() {
      
    using namespace CryptoPP;
    AutoSeededRandomPool rng;
    updateTime(buffer, sizeof(buffer));
    cout<< "-----------------------------------------------------------"<<endl;
    std::cout << "Start key generation EL GAMAL" << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;
    //ElGamal Key Generator
    ElGamalKeys::PrivateKey privateKey;
    ElGamalKeys::PublicKey publicKey;
    //2048 bit key length
    privateKey.GenerateRandomWithKeySize(rng, 2048);
    privateKey.MakePublicKey(publicKey);
    updateTime(buffer, sizeof(buffer));
    std::cout << "Start EL GAMAL encryption " << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;
    std::vector<uint8_t> cipherText;
    // Encryption
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_encode_sum(0);
    int count =10;
    for (int i = 0; i < count; i++)
    {
    time_start = chrono::high_resolution_clock::now();
    ElGamalEncryptor encryptor(publicKey);
    StringSource(packet.data(), packet.size(), true,
        new PK_EncryptorFilter(rng, encryptor, new VectorSink(cipherText)));
    time_end = chrono::high_resolution_clock::now();
    time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    auto avg_encode = time_encode_sum.count() / count;
    std::cout << "Average El Gamal Encryption: " << avg_encode << "microseconds"<<  std::endl;
    std::string encoded;
    StringSource(cipherText.data(), cipherText.size(), true,   new HexEncoder(new StringSink(encoded)));
    std::cout << "Ciphertext dimension: " << cipherText.size() << " byte" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "End EL GAMAL Cryptography " << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;
    // Decryption
    //std::vector<uint8_t> recoveredText;
    //ElGamalDecryptor decryptor(privateKey);
    //StringSource(cipherText.data(), cipherText.size(), true, new PK_DecryptorFilter(rng, decryptor, new VectorSink(recoveredText)));

}

//AES function used to elaborate and analyze the AES encryption and decryption time and packet dimension
void aes_encryption(int packetDimension) {
  
    long long count = 100;
    std::vector<uint8_t> key(16);  // 32 per AES-256, 16 per avere AES-128
    std::vector<uint8_t> iv(16);   // IV
    std::generate(key.begin(), key.end(), [](){ return rand() % 256; });
    std::generate(iv.begin(), iv.end(), [](){ return rand() % 256; });
 
    // Context creation
    EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();
    if (!ctx_enc || !ctx_dec) {
        throw std::runtime_error("Error in context creation");
    }

    std::vector<uint8_t> ciphertext(packet.size() + EVP_MAX_BLOCK_LENGTH);
    std::vector<uint8_t> decryptedtext(packet.size() + EVP_MAX_BLOCK_LENGTH);

    int len, ciphertext_len;
    chrono::microseconds time_encode_sum(0), time_decode_sum(0);
    
    // Init crypto
    EVP_EncryptInit_ex(ctx_enc, EVP_aes_128_cbc(), nullptr, key.data(), iv.data());

    std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Start AES encryption" << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
    
    for (int i = 1; i <= count; i++) {
        auto time_start = chrono::high_resolution_clock::now();
        EVP_EncryptUpdate(ctx_enc, ciphertext.data(), &len, packet.data(), packet.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx_enc, ciphertext.data() + len, &len);
        ciphertext_len += len;
        auto time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }

    auto avg_encode = time_encode_sum.count() / count;
    std::cout << "Average AES Encryption: " << avg_encode << " microseconds, with packet size: " << ciphertext_len << " and data length encrypted: " << packet.size() << std::endl;

    // Init Decryption
    EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_cbc(), nullptr, key.data(), iv.data());
    std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing inizio decifratura AES" << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
    int decrypted_len;
    for (int i = 1; i <= count; i++) {
        auto time_start = chrono::high_resolution_clock::now();
        EVP_DecryptUpdate(ctx_dec, decryptedtext.data(), &len, ciphertext.data(), ciphertext_len);
        decrypted_len = len;
        EVP_DecryptFinal_ex(ctx_dec, decryptedtext.data() + len, &len);
        decrypted_len += len;
        auto time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "End AES decryption" << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;

    auto avg_decode = time_decode_sum.count() / count;
    std::cout << "Average AES Decryption: " << avg_decode << " microseconds" << std::endl;

    // Scrivi dati su file
    std::ofstream file("encryption_data_aes_2.csv", std::ios::app);
    if (file.is_open()) {
        file << avg_encode << "," << ciphertext_len << "," << avg_decode << ","<< "\n";
        file.close();
        std::cout << "Data saved to encryption_data_aes.csv" << std::endl;
    } else {
        std::cerr << "Error opening file!" << std::endl;
    }

    // Freeing memory
    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);

    

    
}

void generate_random_data(size_t size) {
    packet.resize(size);  
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dis(0, 20);
    std::generate(packet.begin(), packet.end(), [&]() {
        return static_cast<uint8_t>(dis(gen)); 
    });
    
}

paillier_plaintext_t* convert_vector_to_paillier_plaintext(const std::vector<uint8_t>& packet) {
    size_t len = packet.size();
    cout<<"Dimension "<< len<< endl;
    void* byte_array = static_cast<void*>(const_cast<uint8_t*>(packet.data()));
    
    // Paillier plaintext
    paillier_plaintext_t* plaintext = paillier_plaintext_from_bytes(byte_array, len);
    
    return plaintext; 
}

void paillier() {

    paillier_plaintext_t* plaintext = convert_vector_to_paillier_plaintext(packet);
    int modulus_bits = 3072;
    paillier_pubkey_t *pubkey;
    paillier_prvkey_t *privkey;
    updateTime(buffer, sizeof(buffer));

    // Key Generation
    paillier_keygen(modulus_bits, &pubkey, &privkey, paillier_get_rand_devurandom);
    updateTime(buffer, sizeof(buffer));

    size_t pubkey_size = (size_t)mpz_sizeinbase(pubkey->n, 2); // Dimensione in bit
    printf("Public Key Size (N): %zu bits, %zu bytes\n", pubkey_size, (pubkey_size + 7) / 8);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    int count = 10;

    paillier_ciphertext_t *ciphertext1, *ciphertext2, *sum_ciphertext;

    // Encryption 
    for (int i = 0; i < count; i++) {
        time_start = chrono::high_resolution_clock::now();
        ciphertext1 = paillier_enc(NULL, pubkey, plaintext, paillier_get_rand_devurandom);
        time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    auto avg_encode = time_encode_sum.count() / count;
    std::cout << "Average Paillier Encryption: " << avg_encode << " microseconds" << std::endl;

    size_t ciphertext_size = (size_t)mpz_sizeinbase(ciphertext1->c, 2); // Dimensione in bit
    printf("Ciphertext Size: %zu bits, %zu bytes\n", ciphertext_size, (ciphertext_size + 7) / 8);

    //Second plaintext
    paillier_plaintext_t* plaintext2 = convert_vector_to_paillier_plaintext(packet);

    //Plaintext sum
    paillier_plaintext_t* expected_sum = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
    mpz_init(expected_sum->m);
    mpz_add(expected_sum->m, plaintext->m, plaintext2->m);

    // Encryption second plaintext
    ciphertext2 = paillier_enc(NULL, pubkey, plaintext2, paillier_get_rand_devurandom);

    // Ciphertext sum
    sum_ciphertext = paillier_create_enc_zero();
    paillier_mul(pubkey, sum_ciphertext, ciphertext1, ciphertext2);

    // Sum decryption
    paillier_plaintext_t *decrypted_sum;
    for (int i = 0; i < count; i++) {
        time_start = chrono::high_resolution_clock::now();
        decrypted_sum = paillier_dec(NULL, pubkey, privkey, sum_ciphertext);
        time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    auto avg_decode = time_decode_sum.count() / count;
    std::cout << "Average Paillier Decryption: " << avg_decode << " microseconds" << std::endl;

    // Comparison and printing of the sum
    if (mpz_cmp(decrypted_sum->m, expected_sum->m) == 0) {
        std::cout << "Sum operation verified successfully: decrypted_sum matches expected_sum." << std::endl;
    } else {
        std::cerr << "Sum operation failed: decrypted_sum does not match expected_sum." << std::endl;
    }

    // Printing sum
    char* decrypted_sum_str = mpz_get_str(NULL, 10, decrypted_sum->m);
    std::cout << "Decrypted sum: " << decrypted_sum_str << std::endl;
    free(decrypted_sum_str); 

    // Freeing memory
    paillier_freepubkey(pubkey);
    paillier_freeprvkey(privkey);
    paillier_freeplaintext(plaintext);
    paillier_freeplaintext(plaintext2);
    paillier_freeplaintext(decrypted_sum);
    paillier_freeplaintext(expected_sum);
    paillier_freeciphertext(ciphertext1);
    paillier_freeciphertext(ciphertext2);
    paillier_freeciphertext(sum_ciphertext);
    
}



// Function to calculate the error between original and decrypted vectors used at the beginning to check the basic operations
double calculate_error(const vector<double>& original, const vector<double>& decrypted, int fieldFactor)
{
    if (original.size() != decrypted.size())
    {
        cout << "Original Dimension " <<original.size()<< "encrypted dimension" << decrypted.size() << endl;
        throw invalid_argument("Vectors must have the same size");
    }

    double error_sum = 0.0;
    for (size_t i = 0; i <= original.size(); i=i+fieldFactor)
    {
        error_sum += abs(original[i] - decrypted[i]);
    }

    return error_sum / original.size(); // Return the average error
} 

void ckks_encryption(size_t grado, SEALContext context, int dimension){
    
 chrono::high_resolution_clock::time_point time_start, time_end;
 //Open the file
 std::ofstream file("encryption_data_ckks_zstd_zlib.csv", std::ios::app); 

    //print_parameters(context);
    cout << "byte: "<< dimension<< endl;

    auto &parms = context.first_context_data()->parms();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    //cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    cout << "secret_key dimension: " << secret_key.save_size() << "public_key dimension: " << public_key.save_size()<< endl; 

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    chrono::microseconds time_diff;
    if (context.using_keyswitching())
    {
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_relin_keys(relin_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context.first_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

        cout << "Generating Galois keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_galois_keys(gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }
    cout << "dimensione chiave relkin " << relin_keys.save_size() << "dimensione chiave galois " << gal_keys.save_size()<< endl; 

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_serialize_sum(0);
#ifdef SEAL_USE_ZLIB
    chrono::microseconds time_serialize_zlib_sum(0);
#endif
#ifdef SEAL_USE_ZSTD
    chrono::microseconds time_serialize_zstd_sum(0);
#endif
    /*
    How many times to run the test?
    */
    long long count = 10;

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    size_t buf_sizeNone;
    size_t buf_sizeZLIB;
    size_t buf_sizeZstandard;

    for (size_t i = 0; i < dimension && i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    Plaintext plain2(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);
    double scale = sqrt(static_cast<double>(parms.coeff_modulus().back().value()));
    ckks_encoder.encode(pod_vector, scale, plain2);
    Ciphertext encrypted(context);
    encryptor.encrypt(plain2, encrypted);

    cout << "Running tests ";
    std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Start CKKS encryption " << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
    for (long long i = 0; i < count; i++)
    {
        /*
        [Encoding]
        */
        Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);
        /*

        */
        double scale = sqrt(static_cast<double>(parms.coeff_modulus().back().value()));
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.encode(pod_vector, scale, plain);
        time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        
        /*
        [Encryption]
        */
        
        time_start = chrono::high_resolution_clock::now();
        encryptor.encrypt(plain, encrypted);
        time_end = chrono::high_resolution_clock::now();
        time_encrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Serialize Ciphertext]
        */
        buf_sizeNone = static_cast<size_t>(encrypted.save_size(compr_mode_type::none));
        vector<seal_byte> buf(buf_sizeNone);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_sizeNone, compr_mode_type::none);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#ifdef SEAL_USE_ZLIB
        /*
        [Serialize Ciphertext (ZLIB)]
        */
        buf_sizeZLIB = static_cast<size_t>(encrypted.save_size(compr_mode_type::zlib));
        buf.resize(buf_sizeZLIB);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_sizeZLIB, compr_mode_type::zlib);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_zlib_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#endif
#ifdef SEAL_USE_ZSTD
        /*
        [Serialize Ciphertext (Zstandard)]
        */
        buf_sizeZstandard = static_cast<size_t>(encrypted.save_size(compr_mode_type::zstd));
        buf.resize(buf_sizeZstandard);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_sizeZstandard, compr_mode_type::zstd);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_zstd_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#endif
    }
    std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing end CKKS Decryption " << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
      for (long long i = 0; i < count; i++){  
         Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0); 
        /*
        [Decoding]
        */
        vector<double> pod_vector2(ckks_encoder.slot_count());
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.decode(plain2, pod_vector2);
        time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Decryption]
        */
        Plaintext plain2(poly_modulus_degree, 0);
        time_start = chrono::high_resolution_clock::now();
        decryptor.decrypt(encrypted, plain2);
        time_end = chrono::high_resolution_clock::now();
        time_decrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        
        cout << ".";
        cout.flush();
    }  
std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "End CKKS decryption " << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
    cout << " Done" << endl << endl;
    cout.flush();

    auto avg_encode = time_encode_sum.count() / count;
    auto avg_decode = time_decode_sum.count() / count;
    auto avg_encrypt = time_encrypt_sum.count() / count;
    auto avg_decrypt = time_decrypt_sum.count() / count;
    auto avg_serialize = time_serialize_sum.count() / count;
#ifdef SEAL_USE_ZLIB
    auto avg_serialize_zlib = time_serialize_zlib_sum.count() / count;
#endif
#ifdef SEAL_USE_ZSTD
    auto avg_serialize_zstd = time_serialize_zstd_sum.count() / count;
#endif
    cout << "Average encode: " << avg_encode << " microseconds" << endl;
    cout << "Average decode: " << avg_decode << " microseconds" << endl;
    cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
    cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
    cout << "Average serialize ciphertext: " << avg_serialize << " microseconds" << endl;
#ifdef SEAL_USE_ZLIB
    cout << "Average compressed (ZLIB) serialize ciphertext: " << avg_serialize_zlib << " microseconds" << endl;
#endif
#ifdef SEAL_USE_ZSTD
    cout << "Average compressed (Zstandard) serialize ciphertext: " << avg_serialize_zstd << " microseconds" << endl;
#endif   
    cout.flush();
    auto totTimeEncryption = avg_encode+avg_encrypt+avg_serialize;
    auto totTimeDecryption = avg_decode+avg_decrypt;
   if (file.is_open()) {
        file << grado << "," << totTimeEncryption   << ","<< avg_serialize_zlib << "," << avg_serialize_zstd << ","  << dimension << "," <<totTimeDecryption<< "\n";
        file.close();
        std::cout << "Data saved to encryption_dataCkks.csv" << std::endl;
    } else {
        std::cerr << "Error opening file!" << std::endl;
    }
}


void ckks_variance(SEALContext context)
{
   
    chrono::high_resolution_clock::time_point time_start, time_end, time_start_variance, time_end_variance;

    //print_parameters(context);
    //cout << endl;
   
    updateTime(buffer, sizeof(buffer));
    cout<< "-----------------------------------------------------------"<<endl;
    std::cout << "Start CKKS Key generation: " << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;
    auto &parms = context.first_context_data()->parms();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    chrono::microseconds time_diff;
    if (context.using_keyswitching())
    {
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_relin_keys(relin_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context.first_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

        cout << "Generating Galois keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_galois_keys(gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }
    updateTime(buffer, sizeof(buffer));
    cout<< "-----------------------------------------------------------"<<endl;
    std::cout << "End key generation CKKS keys" << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_variance(0);
    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_serialize_sum(0);
#ifdef SEAL_USE_ZLIB
    chrono::microseconds time_serialize_zlib_sum(0);
#endif
#ifdef SEAL_USE_ZSTD
    chrono::microseconds time_serialize_zstd_sum(0);
#endif
    /*
    How many times to run the test?
    */
    long long count = 10;
    for (int i=1; i<=count; i++){
    vector<double> pod_vector;
    random_device rd;
    int fieldFactor=1;
    int scaleFactor= 28;
    double householders=ckks_encoder.slot_count()/fieldFactor;
    double avegareFactor=  1/householders; 
    
    vector<double> average_vector;
    vector<double> average_vectorPos;
    int slot=0;
    cout<<"Available slot"<< ckks_encoder.slot_count()<<endl;
    //Populating the vectors
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        if (i % fieldFactor == 0 && i<=householders*fieldFactor) {
        average_vector.push_back(-avegareFactor);
        average_vectorPos.push_back(avegareFactor);
        pod_vector.push_back(0.0005+i*0.0005); 
        slot++;
        }
        else
        {
        average_vectorPos.push_back(1.00);
        average_vector.push_back(1.00);
        pod_vector.push_back(1.00); 
        }

    }
    cout<<"Used slot: "<<slot<<endl;

       // Print the data
    //cout << "data: ";
    //for (double val : pod_vector)
    //{
     //   cout << val << " ";
    //}
    //cout<<endl;

    
   // for (long long i = 0; i < count; i++)
    //{
        /*
        [Encoding]
              */
        Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);
        /*

        */
        double scale =  pow(2.0, scaleFactor);
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.encode(pod_vector, scale, plain);
        time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
       
        /*
        [Encryption]
        */
        Ciphertext encrypted(context);
        time_start = chrono::high_resolution_clock::now();
        encryptor.encrypt(plain, encrypted);
        time_end = chrono::high_resolution_clock::now();
        time_encrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        size_t buf_sizeEncrypt = static_cast<size_t>(encrypted.save_size(compr_mode_type::none));

        cout << "Variance packet dimension: "<< buf_sizeEncrypt << endl;
        /*
        [Add]
        */
        time_start_variance = chrono::high_resolution_clock::now();
        Ciphertext SumC = encrypted;
        Ciphertext encrypted2 = encrypted;
        time_start = chrono::high_resolution_clock::now();
        int rotation=0;
        for (int i=0; i<=ckks_encoder.slot_count()/fieldFactor-1; i++){
        evaluator.rotate_vector_inplace(encrypted, fieldFactor, gal_keys);
        evaluator.add_inplace(SumC, encrypted);
        rotation++;
        }
        //MEAN
        Plaintext plainAverage;
        Plaintext plainAveragePos;
        Ciphertext AverageNegated;
        ckks_encoder.encode(average_vector, scale, plainAverage);
        ckks_encoder.encode(average_vectorPos, scale, plainAveragePos);

        evaluator.multiply_plain(SumC, plainAverage, AverageNegated);   
        evaluator.relinearize_inplace(AverageNegated, relin_keys);

        evaluator.rescale_to_next_inplace(AverageNegated);
    
        Plaintext plainAverageN(poly_modulus_degree, 0);
        decryptor.decrypt(AverageNegated, plainAverageN);
        //vector<double> pod_vector4(ckks_encoder.slot_count());
        //ckks_encoder.decode(plainAverageN, pod_vector4); 
        //cout << "Average: ";
        //for (int i = 0; i <= householders-1; i++){
        //        cout << pod_vector4[i]<< " ";
        //
        //    }

        //SUBSTRACTION
        Ciphertext CSubstracted;
        
        AverageNegated.scale()=pow(2.0, scaleFactor);
        parms_id_type last_parms_id = AverageNegated.parms_id();
        evaluator.mod_switch_to_inplace(encrypted, last_parms_id);
        evaluator.add(encrypted, AverageNegated, CSubstracted);
        
        //SQUARED
        Ciphertext squared;
        evaluator.square(CSubstracted, squared);
        //Plaintext plainSquared(poly_modulus_degree, 0);
        //decryptor.decrypt(squared, plainSquared);
      
        evaluator.relinearize_inplace(squared, relin_keys);
        evaluator.rescale_to_next_inplace(squared);
        squared.scale()=pow(2.0, scaleFactor);
        Ciphertext SumSquared = squared;
        //SUM
        for (int i=0; i<=ckks_encoder.slot_count()/fieldFactor-1; i++){
        evaluator.rotate_vector_inplace(squared, fieldFactor, gal_keys);
        evaluator.add_inplace(SumSquared, squared);
        }
        Ciphertext Result;
        Ciphertext AveragePos;
        evaluator.mod_switch_to_inplace(plainAveragePos, SumSquared.parms_id());
        encryptor.encrypt(plainAveragePos, AveragePos);
        evaluator.multiply_inplace(SumSquared, AveragePos);
        evaluator.relinearize_inplace(SumSquared, relin_keys);
        time_end_variance = chrono::high_resolution_clock::now();
        /*
        [Decryption]
        */
        Plaintext plain2(poly_modulus_degree, 0);
        time_start = chrono::high_resolution_clock::now();
        decryptor.decrypt(SumSquared, plain2);
        time_end = chrono::high_resolution_clock::now();
        time_decrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  
         /*
        [Decode]
        */
        vector<double> pod_vector2(ckks_encoder.slot_count());
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.decode(plain2, pod_vector2);
        time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);  

         // Print the decrypted data
         /*
            cout << "Decrypted data: ";

            for (int i = 0; i <= householders-1; i=i+fieldFactor){
                cout << pod_vector2[i]<< " ";
        
            }
            */

    // Calculate and print the error
    // double error = calculate_error(pod_vector, pod_vector2, fieldFactor);
    // cout << "Average error between original and decrypted data: " << error << endl;
        /*
        [Serialize Ciphertext]
        */
        size_t buf_size = static_cast<size_t>(encrypted.save_size(compr_mode_type::none));
        vector<seal_byte> buf(buf_size);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_size, compr_mode_type::none);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#ifdef SEAL_USE_ZLIB
        /*
        [Serialize Ciphertext (ZLIB)]
        */
        buf_size = static_cast<size_t>(encrypted.save_size(compr_mode_type::zlib));
        buf.resize(buf_size);
        cout <<"chipertext dimension using compression ZLIB: "<< buf_size <<endl;  
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_size, compr_mode_type::zlib);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_zlib_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#endif
#ifdef SEAL_USE_ZSTD
        /*
        [Serialize Ciphertext (Zstandard)]
        */
        buf_size = static_cast<size_t>(encrypted.save_size(compr_mode_type::zstd));
        buf.resize(buf_size);
        cout <<"chipertext dimension using compression ZSTD: "<< buf_size <<endl;
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_size, compr_mode_type::zstd);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_zstd_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#endif
         time_variance += chrono::duration_cast<chrono::microseconds>(time_end_variance - time_start_variance);
     }
    
    auto time_operation = time_variance.count()/count;
    auto avg_encode = time_encode_sum.count() / count;
    auto avg_decode = time_decode_sum.count() / count;
    auto avg_encrypt = time_encrypt_sum.count() / count;
    auto avg_decrypt = time_decrypt_sum.count() / count;
    auto avg_serialize = time_serialize_sum.count() / count;
#ifdef SEAL_USE_ZLIB
    auto avg_serialize_zlib = time_serialize_zlib_sum.count() / count;
#endif
#ifdef SEAL_USE_ZSTD
    auto avg_serialize_zstd = time_serialize_zstd_sum.count() / count;
#endif
auto avg_tot_encrypt=avg_encode+avg_encrypt+avg_serialize_zstd;
auto avg_tot_decrypt=avg_decode+avg_decrypt;

    cout<<"Average encrypt operation"<<avg_tot_encrypt<<endl;
    cout<<"Average decrypt operation"<<avg_tot_decrypt<<endl;
    cout << "Average encode: " << avg_encode << " microseconds" << endl;
    cout << "Average decode: " << avg_decode << " microseconds" << endl;
    cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
    cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
    cout << "Average serialize ciphertext: " << avg_serialize << " microseconds" << endl;
#ifdef SEAL_USE_ZLIB
    cout << "Average compressed (ZLIB) serialize ciphertext: " << avg_serialize_zlib << " microseconds" << endl;
#endif
#ifdef SEAL_USE_ZSTD
    cout << "Average compressed (Zstandard) serialize ciphertext: " << avg_serialize_zstd << " microseconds" << endl;
#endif

    cout<<"Time operation: "<< time_operation <<" microseconds"<< endl;
    cout.flush();
}

void paillier_example_sum(int num_addends) {
    int modulus_bits = 3072;
    paillier_pubkey_t *pubkey;
    paillier_prvkey_t *privkey;

    // Key Generation
    paillier_keygen(modulus_bits, &pubkey, &privkey, paillier_get_rand_devurandom);

    // Ciphertext Init
    paillier_ciphertext_t *sum_ciphertext = paillier_create_enc_zero();

    // Plaintext for verification
    mpz_t plaintext_sum;
    mpz_init(plaintext_sum);

    std::chrono::microseconds time_encode_sum(0), time_homomorphic_sum(0), time_decode_sum(0);
    size_t total_ciphertext_size = 0;

    // Encrypt and add
    for (int i = 1; i <= num_addends; i++) {
        // Init Operation
        paillier_plaintext_t *plaintext_addend = paillier_plaintext_from_ui(i);
        mpz_add(plaintext_sum, plaintext_sum, plaintext_addend->m);  // Somma plaintext per verifica

        // Time cryptografy
        auto time_start = std::chrono::high_resolution_clock::now();
        paillier_ciphertext_t *ciphertext_addend = paillier_enc(NULL, pubkey, plaintext_addend, paillier_get_rand_devurandom);
        auto time_end = std::chrono::high_resolution_clock::now();
        time_encode_sum += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

        // Cipertext dimension
        size_t ciphertext_size = mpz_sizeinbase(ciphertext_addend->c, 2); // Dimensione in bit
        total_ciphertext_size += ciphertext_size;

        // Time measuring
        time_start = std::chrono::high_resolution_clock::now();
        paillier_mul(pubkey, sum_ciphertext, sum_ciphertext, ciphertext_addend);
        time_end = std::chrono::high_resolution_clock::now();
        time_homomorphic_sum += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

        paillier_freeplaintext(plaintext_addend);
        paillier_freeciphertext(ciphertext_addend);
    }

    // decryption of the result
    auto time_start = std::chrono::high_resolution_clock::now();
    paillier_plaintext_t *decrypted_sum = paillier_dec(NULL, pubkey, privkey, sum_ciphertext);
    auto time_end = std::chrono::high_resolution_clock::now();
    time_decode_sum = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

    // Verification
    char* decrypted_sum_str = mpz_get_str(NULL, 10, decrypted_sum->m);
    char* plaintext_sum_str = mpz_get_str(NULL, 10, plaintext_sum);
    std::cout << "Decrypted sum of 1 to " << num_addends << ": " << decrypted_sum_str << std::endl;
    std::cout << "Expected sum of 1 to " << num_addends << ": " << plaintext_sum_str << std::endl;

    //Time
    auto avg_encode_time = time_encode_sum.count() / num_addends;
    auto avg_ciphertext_size = total_ciphertext_size / num_addends;
    std::cout << "Average encryption time: " << avg_encode_time << " microseconds" << std::endl;
    std::cout << "Total homomorphic addition time: " << time_homomorphic_sum.count() << " microseconds" << std::endl;
    std::cout << "Decryption time: " << time_decode_sum.count() << " microseconds" << std::endl;
    std::cout << "Average ciphertext size: " << avg_ciphertext_size << " bits, " << (avg_ciphertext_size + 7) / 8 << " bytes" << std::endl;

    // Export in csv
    std::ofstream file("paillier_performance_data.csv", std::ios::app);
    if (file.is_open()) {
        file << num_addends << "," 
             << avg_encode_time << "," 
             << time_homomorphic_sum.count() << "," 
             << time_decode_sum.count() << ","
             << avg_ciphertext_size << "\n";
        file.close();
        std::cout << "Data saved to paillier_performance_data.csv" << std::endl;
    } else {
        std::cerr << "Error opening file!" << std::endl;
    }

    // Memory freeing 
    free(decrypted_sum_str);
    free(plaintext_sum_str);
    mpz_clear(plaintext_sum);
    paillier_freepubkey(pubkey);
    paillier_freeprvkey(privkey);
    paillier_freeplaintext(decrypted_sum);
    paillier_freeciphertext(sum_ciphertext);
}


void generate_ckks_key_sizes(const std::string &filename) {
    
    // Open the file
    std::ofstream outfile(filename);
    if (!outfile.is_open()) {
        std::cerr << "Error opening file." << std::endl;
        return;
    }

    outfile << "Polynomial Degree,Public Key (bytes),Secret Key (bytes),Relinearization Key (bytes),Galois Key (bytes)\n";

    for (size_t poly_degree = 1024; poly_degree <= 32768; poly_degree *= 2) {

        seal::EncryptionParameters params(scheme_type::ckks);
        params.set_poly_modulus_degree(poly_degree);
        params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_degree)); 

        SEALContext context(params);
        RelinKeys relin_keys;
    	GaloisKeys gal_keys;
 	
    	PublicKey public_key;
   
        // Key Generation
         KeyGenerator keygen(context);
         keygen.create_public_key(public_key);
      	 auto secret_key = keygen.secret_key();

  if (context.using_keyswitching()){
         keygen.create_relin_keys(relin_keys);
         keygen.create_galois_keys(gal_keys);
        }
        // Save to file
        outfile << poly_degree << ","
                << public_key.save_size(seal::compr_mode_type::none) << ","
                << secret_key.save_size(seal::compr_mode_type::none) << ","
                << relin_keys.save_size(seal::compr_mode_type::none) << ","
                << gal_keys.save_size(seal::compr_mode_type::none) << "\n";

        std::cout << "Processed polynomial degree: " << poly_degree << std::endl;
    }

    outfile.close();
    std::cout << "Key sizes saved to " << filename << std::endl;
}

double calculateVariance(const std::vector<double>& data, int iterations) {
    
    double totalTime = 0.0;
    double variance = 0.0;

    for (int iter = 0; iter < iterations; ++iter) {
        auto start = std::chrono::high_resolution_clock::now();

        // Mean
        double sum = 0.0;
        for (double value : data) {
            sum += value;
        }
        double mean = sum / data.size();

        // Variance
        variance = 0.0;
        for (double value : data) {
            variance += (value - mean) * (value - mean);
        }
        variance /= data.size();

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        totalTime += elapsed.count();
    }

    double averageTime = totalTime / iterations;
    std::cout << "Average time taken for variance calculation over " << iterations << " iterations: " << averageTime << " ms" << std::endl;

    return variance;
}

int main()
{

//AES and CKKS Evaluation
size_t poly_modulus_degree = 1024;

for (int i = 1; i <= 255; i++) {

    //generate_random_data(i);

    // ENCRYPTION SECTION
    // AES ENCRYPTION
    aes_encryption(i);

    // CKKS Encryption
    EncryptionParameters parms(scheme_type::ckks);
    if (i > poly_modulus_degree / 2) {
        poly_modulus_degree *= 2;
        if (poly_modulus_degree > 16384) {
            poly_modulus_degree = 16384; 
        }
    }

    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree, seal::sec_level_type::tc128));

    ckks_encryption(poly_modulus_degree, parms, i);

    
    paillier_example_sum(i);
}
//Alternative Scheme evaluation

    //El Gamal Encryption
     elGamal();

    // Paillier Encryption
     paillier();

//encryption_ckks_paillier(parmsScenario1);

//CKKS Key size comparison   
    
    generate_ckks_key_sizes("ckks_key_sizes.csv");

//Scenario - CKKS Variance - Server Execution - Used to calculate and verify variance calculation

    EncryptionParameters parms2(scheme_type::ckks);
    size_t poly_modulus_degree2= 8192;
    parms2.set_poly_modulus_degree(poly_modulus_degree2);
    parms2.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree2, {60,29,29,60}));
    ckks_variance(parms2);

//Edge device variance calculation 
    std::vector<double> data;
    int n = 4096;
    for (int i = 0; i < n; ++i) {
        data.push_back(0.0005 + i * 0.0005);
    }
    double variance = calculateVariance(data, 10);
    std::cout << "Variance: " << variance << std::endl;
}