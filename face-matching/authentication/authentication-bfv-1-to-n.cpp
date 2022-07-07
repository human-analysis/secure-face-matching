///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
//
//   Project     : Secure Face Matching
//   File        : authentication-bfv-1-to-n.cpp
//   Description : user face authentication, probe feature encryption,
//                 probe feature matching with encrypted database, decrypt matching score
//                 uses BFV scheme for 1:N matching
//   Input       : needs gallery size as input
//
//   Created On: 05/01/2018
//   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
//   Modified On: 07/06/2022
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
#include <cmath>

#include "seal/seal.h"
#include "utils.h"

using namespace std;
using namespace seal;

int main(int argc, char **argv)
{
    float precision;
    vector<int64_t> pod_result;
    int num_gallery = atoi(argv[1]);
    int security_level = atoi(argv[2]);

    RelinKeys relin_key;
    PublicKey public_key;
    SecretKey secret_key;

    precision = 125; // precision of 1/125 = 0.004

    size_t poly_modulus_degree;
    EncryptionParameters parms(scheme_type::BFV);

    // these parameters have not been optimized for speed
    if (security_level == 128)
    {
        poly_modulus_degree = 32768;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree, sec_level_type::tc128));
    }
    else if (security_level == 192)
    {
        poly_modulus_degree = 32768;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree, sec_level_type::tc192));
    }
    else if (security_level == 256)
    {
        poly_modulus_degree = 32768;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree, sec_level_type::tc256));
    }
    
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20)); // 16 might also work

    cout << "\nTotal memory allocated by global memory pool: "
        << (MemoryPoolHandle::Global().alloc_byte_count() >> 20) << " MB" << endl;

    auto context = SEALContext::Create(parms);
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    ifstream ifile;
    string name;
    stringstream stream;

    // load back the keys (public, secret and evaluator)
    name = "../data/keys/public_key_bfv_1_to_n.bin";
    cout << "Loading Public Key: " << name << endl;
    ifile.open(name.c_str(), ios::in|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        public_key.unsafe_load(context, stream);
    }
    ifile.close();
    stream.str(std::string());

    name = "../data/keys/secret_key_bfv_1_to_n.bin";
    cout << "Loading Private Key: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        secret_key.unsafe_load(context, stream);
    }
    ifile.close();
    stream.str(std::string());

    name = "../data/keys/relin_key_bfv_1_to_n.bin";
    cout << "Loading Relin Keys: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        relin_key.unsafe_load(context, stream);
    }
    ifile.close();
    stream.str(std::string());

    KeyGenerator keygen(context, secret_key, public_key);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    int slot_count = batch_encoder.slot_count();

    int num_probe, dim_probe;
    ifile.open ("../data/probe-1-to-1.bin", ios::in|ios::binary);
    ifile.read((char *)&num_probe, sizeof(int));
    ifile.read((char *)&dim_probe, sizeof(int));
    ifile.close();

    // Load the Gallery
    // We assume that gallery and probe have the same dimensions
    vector<Ciphertext> encrypted_gallery;
    for (int i=0; i < dim_probe; i++)
    {
        Ciphertext encrypted_matrix;
        name = "../data/gallery/encrypted_gallery_bfv_1_to_n_" + std::to_string(i) + ".bin";
        ifile.open(name.c_str(), ios::in|ios::binary);
        if (ifile.fail())
        {
            cout << name + " file does not exist." << endl;
        }
        else
        {
            stream << ifile.rdbuf();
            encrypted_matrix.load(context, stream);
            encrypted_gallery.push_back(encrypted_matrix);
        }
        ifile.close();
    }

    float score;
    float probe;
    Plaintext plain_probe;
    Ciphertext encrypted_probe, encrypted_zero;

    vector<int64_t> pod_vector;
    for (int k=0;k<slot_count;k++)
    {
        pod_vector.push_back(0);
    }
    batch_encoder.encode(pod_vector, plain_probe);
    encryptor.encrypt(plain_probe, encrypted_zero);
    pod_vector.clear();

    ifile.open ("../data/probe-1-to-1.bin", ios::in|ios::binary);
    ifile.read((char *)&num_probe, sizeof(int));
    ifile.read((char *)&dim_probe, sizeof(int));

    double time_total;
    std::chrono::steady_clock::time_point time_start, time_end;

    for (int i=0; i < num_probe; i++)
    {
        time_start = std::chrono::steady_clock::now();

        vector<int64_t> pod_result_quant;
        vector<double> pod_result;
        Ciphertext encrypted_result = Ciphertext(encrypted_zero);
        
        // we do not want to measure the time for printing
        time_end = std::chrono::steady_clock::now();
        time_total += std::chrono::duration_cast<std::chrono::milliseconds>(time_end - time_start).count();
        cout << "Encrypting Probe: " << i << endl;
        time_start = std::chrono::steady_clock::now();

        for (int j=0; j < dim_probe; j++)
        {
            // we do not want to measure the time for loading from disk
            time_end = std::chrono::steady_clock::now();
            time_total += std::chrono::duration_cast<std::chrono::milliseconds>(time_end - time_start).count();

            // Load vector of probe from file
            ifile.read((char *)&probe, sizeof(float));

            // start the timer again
            time_start = std::chrono::steady_clock::now();
            
            int a = (int64_t) roundf(precision*probe);

            for (int k=0;k<slot_count;k++)
            {
                pod_vector.push_back(a);
            }

            // Encrypt entire vector of probe
            batch_encoder.encode(pod_vector, plain_probe);
            encryptor.encrypt(plain_probe, encrypted_probe);
            pod_vector.clear();

            Ciphertext temp = Ciphertext(encrypted_probe);
            evaluator.multiply_inplace(temp, encrypted_gallery[j]);
            evaluator.relinearize_inplace(temp, relin_key);
            evaluator.add_inplace(encrypted_result, temp);
        }

        Plaintext plain_result;
        decryptor.decrypt(encrypted_result, plain_result);
        batch_encoder.decode(plain_result, pod_result_quant);

        for (int k=0; k < slot_count; k++)
        {
            pod_result.push_back(double(pod_result_quant[k])/(precision*precision));
        }
        // we are done now and don't want to measure time for printing
        time_end = std::chrono::steady_clock::now();
        time_total += std::chrono::duration_cast<std::chrono::milliseconds>(time_end - time_start).count();
        
        for (int k=0; k < num_gallery; k++)
        {
            score = float(pod_result[k]);
            cout << "Matching Score (probe " << i << ", and gallery " << k << "): " << score << endl;
        }
        cout << " " << endl;
        pod_result.clear();
        pod_result_quant.clear();
    }
    cout << "Avg time:" <<  time_total / (num_gallery * num_probe) << endl;
    cout << "Matching Probes: Done" << endl;
    ifile.close();
    return 0;
}