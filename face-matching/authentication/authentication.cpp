///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
//
//   Project     : Secure Face Matching (Eyeverify/Zoloz)
//   File        : authentication.cpp
//   Description : user face authentication, probe feature encryption,
//                 probe feature matching with encrypted database, decrypt matching score
//
//   Created On: 05/01/2018
//   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
////////////////////////////////////////////////////////////////////////////

#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <random>
#include <limits>

#include <time.h>
#include <cmath>

#include "seal/seal.h"

using namespace std;
using namespace seal;

void print_parameters(const SEALContext &context)
{
    cout << "/ Encryption parameters:" << endl;
    cout << "| poly_modulus: " << context.poly_modulus().to_string() << endl;

    /*
    Print the size of the true (product) coefficient modulus
    */
    cout << "| coeff_modulus size: "
        << context.total_coeff_modulus().significant_bit_count() << " bits" << endl;

    cout << "| plain_modulus: " << context.plain_modulus().value() << endl;
    cout << "\\ noise_standard_deviation: " << context.noise_standard_deviation() << endl;
    cout << endl;
}

int main()
{

    int nrows, slot_count, row_size;
    EncryptionParameters parms;
    GaloisKeys gal_keys;
    EvaluationKeys ev_keys;
    PublicKey public_key;
    SecretKey secret_key;
    float precision;
    vector<int64_t> pod_result;

    precision = 125; // precision of 1/125 = 0.004
    parms.set_poly_modulus("1x^4096 + 1"); // 4096/2 is maximum feature vector size
    parms.set_coeff_modulus(coeff_modulus_128(4096)); // change to coeff_modulus_192 for 192 bits of security
    parms.set_plain_modulus(40961);

    cout << "\nTotal memory allocated by global memory pool: "
        << (MemoryPoolHandle::Global().alloc_byte_count() >> 20) << " MB" << endl;

    SEALContext context(parms);
    print_parameters(context);
    auto qualifiers = context.qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.enable_batching << endl;

    ifstream ifile;
    string name;

    // load back the keys (public, secret, evaluator and galois)
    name = "../data/public_key.bin";
    cout << "Loading Public Key: " << name << endl;
    ifile.open(name.c_str(), ios::in|ios::binary);
    public_key.load(ifile);
    ifile.close();

    name = "../data/secret_key.bin";
    cout << "Loading Private Key: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    secret_key.load(ifile);
    ifile.close();

    name = "../data/evaluator_key.bin";
    cout << "Loading Evaluation Keys: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    ev_keys.load(ifile);
    ifile.close();

    name = "../data/galois_key.bin";
    cout << "Loading Galois Keys: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    gal_keys.load(ifile);
    ifile.close();

    KeyGenerator keygen(context, secret_key, public_key);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    PolyCRTBuilder crtbuilder(context);

    nrows = 2;
    slot_count = crtbuilder.slot_count();
    row_size = slot_count / nrows;
    cout << "Plaintext matrix row size: " << row_size << endl;

    // Load the Gallery
    vector<Ciphertext> encrypted_gallery;
    
    int numg=5; // assuming only one gallery to load
    for (int i=0; i < numg; i++)
    {
        name = "../data/encrypted_gallery_" + std::to_string(i) + ".bin";
        ifile.open(name.c_str(), ios::in|ios::binary);
        Ciphertext encrypted_matrix1;
        encrypted_matrix1.load(ifile);
        ifile.close();
        encrypted_gallery.push_back(encrypted_matrix1);
    }

    int num, dim;
    ifile.open ("../data/probe.bin", ios::in|ios::binary);
    ifile.read((char *)&num, sizeof(int));
    ifile.read((char *)&dim, sizeof(int));

    float score;
    float data[dim * num];
    Ciphertext encrypted_matrix1;
    Ciphertext encrypted_score;
    Plaintext plain_result;
    int count = 0;

    for (int i=0; i < num; i++)
    {
        // Load vector of data from file
        ifile.read((char *)&data[i*dim], dim * sizeof(float));
        
        // push data into a vector of size 4096
        // actually we should be able to squeeze two data instances into one vector
        // this depends on implementation, can get 2x speed up and 2x less storage
        Plaintext plain_matrix1;
        vector<int64_t> pod_matrix1;
        for (int j=0;j<nrows*row_size;j++)
        {
            if (((0 <= j) and (j < dim)))
            {
                pod_matrix1.push_back((int64_t) roundf(precision*data[count]));
                count++;
            }
            else{
                pod_matrix1.push_back((int64_t) 0);
            }
        }

        // Encrypt entire vector of data
        crtbuilder.compose(pod_matrix1, plain_matrix1);
        cout << "Encrypting Probe: " << i << endl;
        encryptor.encrypt(plain_matrix1, encrypted_matrix1);

        for (int k=0; k<numg; k++)
        {
            Ciphertext encrypted_matrix = Ciphertext(encrypted_matrix1);
            
            // compute the encrypted inner product, this will run on server
            evaluator.multiply(encrypted_matrix, encrypted_gallery[k]);
            evaluator.relinearize(encrypted_matrix, ev_keys);

            Ciphertext temp = Ciphertext(encrypted_matrix);
            for (int l=0; l<log2(row_size); l++)
            {
                evaluator.rotate_rows(temp, pow(2,l), gal_keys, encrypted_matrix);
                evaluator.add(temp, encrypted_matrix);
            }

            // decrypt and extract the score, this will run on the client device
            Plaintext plain_result;
            decryptor.decrypt(temp, plain_result);
            crtbuilder.decompose(plain_result, pod_result);
            float score = (float) pod_result[0];
            score  = score / (precision * precision);
            cout << "Matching Score (probe " << i << ", and gallery " << k << "): " << score << endl;
        }
    }
    cout << "Done" << endl;
    ifile.close();
    return 0;
}