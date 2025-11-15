# Pqc_project
Exploring Post-Quantum Cryptography with liboqs
---

# 🧮 Task 1: Listing All Available Algorithms (liboqs)

## 🎯 Objective
The goal of this task is to **explore all post-quantum algorithms** supported in the local liboqs build and understand their basic properties such as key and ciphertext sizes.

---

## 🧠 Concept Overview

**liboqs** is an open-source C library developed by the **Open Quantum Safe (OQS)** project.  
It provides implementations of **Post-Quantum Cryptography (PQC)** algorithms — cryptosystems designed to remain secure against quantum attacks.

This task helps you identify which **KEMs (Key Encapsulation Mechanisms)** and **SIGs (Digital Signature Schemes)** are available in your build of liboqs.

---

## ⚙️ Features Implemented

The program (`list_algorithms.c`) lists:_

- All **available KEM algorithms** (e.g., Kyber512, NTRU, BIKE, etc.)
- All **available Signature algorithms** (e.g., Dilithium, Falcon, SPHINCS+, etc.)
- For each KEM, it prints:
  - Algorithm name  
  - Public key length  
  - Secret key length  
  - Ciphertext length  

---

## 🧩 Functions & APIs Used

| Function | Description |
|-----------|--------------|
| `OQS_KEM_alg_count()` | Returns number of available KEM algorithms. |
| `OQS_KEM_alg_identifier(i)` | Returns the name (string) of the *i-th* KEM algorithm. |
| `OQS_SIG_alg_count()` | Returns number of available Signature algorithms. |
| `OQS_SIG_alg_identifier(i)` | Returns the name (string) of the *i-th* Signature algorithm. |
| `OQS_KEM_new(name)` | Initializes a KEM object for that algorithm. |
| `OQS_KEM_free()` | Frees allocated memory for KEM structure. |
| `OQS_SIG_new(name)` | Initializes a Signature object for that algorithm. |
| `OQS_SIG_free()` | Frees allocated memory for SIG structure. |

---
# 🛠️ Commands & Installation 
---
```bash
sudo apt update && sudo apt upgrade -y


###  Install Required Packages 
Installs build tools (gcc, make), cmake, git, and OpenSSL development libraries (libssl-dev)
sudo apt install -y build-essential cmake git libssl-dev

---

### Clone liboqs Repository 
cd ~
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build

---

### Configure and Build liboqs 
Configure the build and set install prefix to /usr/local
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
Build the library using all available CPU cores
make -j$(nproc)
sudo make install

---

### Verify Installation
Check for liboqs shared libraries
ls /usr/local/lib | grep liboqs

Check for liboqs header files
ls /usr/local/include | grep oqs

---

## Set Library Path 
# Crucial for the system linker to find the newly installed liboqs shared library at runtime
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

---

## Setup Project Folder
cd ~
mkdir -p pqc_project/task1_list_algorithms
cd pqc_project/task1_list_algorithms

---

## Create C Program (list_algorithms.c)
Opens the nano editor to paste your C code (from Task 1)
nano list_algorithms.c

---

## Compile Task 1 Program

## Compile the C program, linking against liboqs (-loqs) and OpenSSL (-lcrypto)
gcc -O2 -o list_algorithms list_algorithms.c \
    -I/usr/local/include -L/usr/local/lib -loqs -lcrypto

---

## Run Task 1 Program
Execute the program and simultaneously pipe the output to both the console and the file 'alg_list.txt'
./list_algorithms | tee alg_list.txt

---

## Verify Output 
Display the contents of the output file
cat alg_list.txt

```
# 📄 Task 1: Output – List of PQC Algorithms

This file shows the **output of Task 1**, where we listed all available **Key Encapsulation Mechanisms (KEMs)** and **Digital Signature Schemes (SIGs)** in our `liboqs` build.

---

## 🔑 Key Encapsulation Mechanisms (KEMs)

| No. | Algorithm Name          | Public Key (bytes) | Secret Key (bytes) | Ciphertext (bytes) |
|-----|------------------------|-----------------|-----------------|------------------|
| 1   | Kyber512               | 800             | 1632            | 768              |
| 2   | Kyber768               | 1184            | 2400            | 1088             |
| 3   | Kyber1024              | 1568            | 3168            | 1568             |
| 4   | NTRU-HPS-2048-509      | 699             | 935             | 699              |
| 5   | NTRU-HPS-2048-677      | 1024            | 1267            | 1024             |
| ... | ...                    | ...             | ...             | ...              |

> ✅ **Note:** Actual algorithms and sizes depend on your installed liboqs build.

---

## ✍️ Digital Signature Schemes (SIGs)

| No. | Algorithm Name          | Public Key (bytes) | Secret Key (bytes) | Signature (bytes) |
|-----|------------------------|-----------------|-----------------|-----------------|
| 1   | Dilithium2             | 1312            | 2528            | 2420            |
| 2   | Dilithium3             | 1952            | 4000            | 3293            |
| 3   | Dilithium5             | 2592            | 4864            | 4595            |
| 4   | Falcon-512             | 897             | 1281            | 666              |
| 5   | Falcon-1024            | 1793            | 2305            | 1280             |
| 6   | SPHINCS+-SHA2-128f-simple | 896           | 2048            | 16976           |
| ... | ...                    | ...             | ...             | ...              |

---

## 📋 Full Command to Generate This Output

```bash
cd ~/pqc_project/task1_list_algorithms
./list_algorithms | tee alg_list.txt
cat alg_list.txt
```

# 🧩 Task 2: KEM Exchange Utility (`kem_exchange`)

The `kem_exchange` utility is a **command-line tool** designed for **testing, benchmarking, and validating Key Encapsulation Mechanisms (KEMs)**, primarily leveraging algorithms from the **Open Quantum Safe (OQS) library**.

It focuses on **Post-Quantum Cryptography (PQC)** algorithms recommended or under evaluation by the **National Institute of Standards and Technology (NIST)**, including the **CRYSTALS-Kyber/ML-KEM** family.

---


## 📊 System Flowchart

The following flowchart illustrates the **overall workflow** of the `kem_exchange` utility — covering key generation, encapsulation, decapsulation, and shared secret verification processes.

<p align="center">
  <img src="codetoflow.png" alt="KEM Exchange Utility Flowchart" width="90%">
</p>

---

## 🚀 Overview

The utility performs a full KEM exchange simulation between **Alice** and **Bob**, executing all fundamental cryptographic operations — key generation, encapsulation, decapsulation, and shared secret verification.

---

## ⚙️ Core Operations

The exchange workflow consists of four main steps:

1. **Key Generation:** Alice generates a public/secret key pair.  
2. **Encapsulation:** Alice uses Bob’s public key to produce a ciphertext and a shared secret (Alice’s secret).  
3. **Decapsulation:** Bob uses his secret key and Alice’s ciphertext to derive a matching shared secret (Bob’s secret).  
4. **Verification:** The tool compares both shared secrets to confirm exchange validity.

---

## 🧾 Example Output

The utility outputs algorithm information, key/data sizes, timing metrics, and a verification message.

| Field | Description | Example Output |
| :--- | :--- | :--- |
| **Algorithm** | Displays the KEM name and version under test. | `Using KEM: %s`, `Selected candidate algorithm: %s`. |
| **Key/Data Sizes** | Reports the lengths of public key, ciphertext, and shared secret. | `public key len : %zu`, `ciphertext len : %zu`, `shared secret len: %zu` |
| **Timings** | Shows latency for each cryptographic operation. |`Key generation : %.3f ms`, `Encapsulation : %.3f ms`, `Decapsulation : %.3f ms` |
| **Verification** | Indicates whether the secrets matched successfully. | `Success: shared secrets match!`, `FAIL: shared secrets differ!` |

---

## 🔐 Supported Algorithms

The utility supports multiple PQC KEM families and their respective security levels:

| Algorithm Family | Variants |
| :--- | :--- |
| **ML-KEM (Kyber)** | `Kyber512`, `Kyber768`, `Kyber1024`, `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`. |
| **Classic McEliece** | `Classic-McEliece-348864`, `Classic-McEliece-460896f`, `Classic-McEliece-8192128` |
| **NTRU / SNTRUP** | `NTRU-HPS-2048-509`, `NTRU-HRSS-701`, `sntrup761` |
| **BIKE** | `BIKE-L1`, `BIKE-L3`, `BIKE-L5` |
| **FrodoKEM** |`FrodoKEM-640-AES`, `FrodoKEM-976-SHAKE`, `FrodoKEM-1344-AES` |
| **HQC** | `HQC-128`, `HQC-192`, `HQC-256` |

---

# 🧩 Compilation
gcc -o kem_exchange kem_exchange.c -loqs -lcrypto -lssl -lm

# 🚀 Execution (Example: Testing Classic-McEliece)
./kem_exchange Classic-McEliece-348864

---

## 🧠 Technical Dependencies

The tool depends on several essential libraries to provide cryptographic robustness, system functionality, and performance optimizations.

### **Core Libraries**

- **OpenSSL (`libcrypto.so.3`)**  
  Used for cryptographic primitives such as hashing (`SHA256`, `SHAKE128` ), encryption modes (`AES-128-CTR` ), and randomness sources (`RAND_bytes`, `RAND_poll` ).

- **Standard C Library (`libc.so.6`)**  
  Provides memory management (`malloc`, `free` ) and I/O operations (`puts`, `perror` ).

### **Compiler / Platform Optimizations**

- Support for CPU acceleration using instruction sets such as `AVX2` and `AVX512` for optimized cryptographic computations.

---

✅ **Summary:**  
The `kem_exchange` utility serves as a **comprehensive benchmarking and validation framework** for **post-quantum key exchange mechanisms**, providing both correctness verification and performance insights across a variety of PQC algorithms.





# 📝 **Task 3: Digital Signature Demo (`sig_demo`)**

`sig_demo.c` demonstrates **Digital Signatures** using **Post-Quantum Cryptography (PQC)** and **classical cryptography** (RSA-2048 and ECDSA-P256).
It highlights **key generation, signing, verification**, **key & signature sizes**, and **execution timings**.

---

## 🚀 Features

| Type           | Algorithms                        | Features                                                                                      |
| -------------- | --------------------------------- | --------------------------------------------------------------------------------------------- |
| **PQC**        | Dilithium2/3/5, ML-DSA (fallback) | Key generation, signing, verification, Hexadecimal signature output, Timing measurements (ms) |
| **Classical**  | RSA-2048                          | SHA-256 signing, Key & signature sizes, Verification                                          |
| **Classical**  | ECDSA-P256                        | SHA-256 signing, Compact key (~65 bytes), Signature size ~64–72 bytes, Verification           |
| **Comparison** | All                               | Performance comparison between PQC and classical signatures                                   |

---

## 📝 Table of Contents

* [Overview](#overview)
* [Dependencies](#dependencies)
* [Installation](#installation)
* [Compilation](#compilation)
* [Usage](#usage)
* [Algorithm Details](#algorithm-details)
* [Sample Output](#sample-output)
* [Contributing](#contributing)
* [License](#license)

---

## 🔍 Overview

This project demonstrates digital signatures by:

1. Generating **public/private key pairs** for PQC and classical algorithms
2. Signing a sample message:

```
"Post-Quantum Cryptography is the future"
```

3. Verifying the signature
4. Measuring execution time for **key generation**, **signing**, and **verification**
5. Printing **key sizes** and **signature lengths**

---

## 🧩 Dependencies

| Dependency                   | Purpose                  |
| ---------------------------- | ------------------------ |
| GCC                          | Compiler                 |
| OpenSSL (`libssl-dev`)       | RSA, ECDSA, SHA-256      |
| Open Quantum Safe (`liboqs`) | PQC signature algorithms |

**Ubuntu/Debian Installation:**

```bash
sudo apt update
sudo apt install build-essential libssl-dev cmake ninja-build git
```

**Build and Install liboqs:**

```bash
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
```

---

## ⚙️ Compilation

```bash
gcc -O2 -o sig_demo sig_demo.c -I/usr/local/include -L/usr/local/lib -loqs -lcrypto
```

---

## 🏃 Usage

```bash
LD_LIBRARY_PATH=/usr/local/lib ./sig_demo
```

Program workflow:

1. Select a PQC algorithm (**Dilithium2 preferred**)
2. Generate **public/private keys**
3. Sign and verify the sample message
4. Print **signature in hexadecimal**
5. Display **timings**, **key sizes**, and **verification results**

---

## 🔑 Algorithm Details

| Algorithm            | Public Key Size | Secret Key Size | Signature Size | Notes                                                    |
| -------------------- | --------------- | --------------- | -------------- | -------------------------------------------------------- |
| **Dilithium2 (PQC)** | 1312 bytes      | 2528 bytes      | 2420 bytes     | OQS library, PQC security, measured timings in ms        |
| **RSA-2048**         | ~294 bytes      | N/A             | 256 bytes      | Classical, SHA-256 signed, measured timings              |
| **ECDSA-P256**       | ~65 bytes       | N/A             | 64–72 bytes    | Classical, compact key, SHA-256 signed, measured timings |

---

## 📊 Sample Output

| Algorithm            | Verification | KeyGen (ms) | Sign (ms) | Verify (ms) | Signature (hex, truncated) |
| -------------------- | ------------ | ----------- | --------- | ----------- | -------------------------- |
| **Dilithium2 (PQC)** | ✅ SUCCESS    | 2.345       | 0.456     | 0.123       | `12ab34cd...`              |
| **RSA-2048**         | ✅ SUCCESS    | 45.678      | 1.234     | 0.987       | `a1b2c3d4...`              |
| **ECDSA-P256**       | ✅ SUCCESS    | 0.456       | 0.123     | 0.078       | `abcd1234...`              |

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am "Add feature"`
4. Push branch: `git push origin feature-name`
5. Open a Pull Request

---

---

# 🧪 Task - 04: Comparative Study

## 🔍 Post-Quantum Cryptography (PQC) vs Classical Cryptography 🔐


This project presents a **comparative study** between **Post-Quantum Cryptography (PQC)** algorithms and **Classical Cryptographic** algorithms using key metrics such as:

- 🔑 **Key sizes**
- ✍️ **Signature / Ciphertext sizes**
- ⏱️ **Execution times**

---

## 📚 Algorithms Compared

| 🔐 Category        | ⚙️ Algorithm     |
|--------------------|------------------|
| **PQC - KEM**      | Kyber512         |
| **PQC - Signature**| Dilithium2       |
| **Classical - SIG**| RSA-2048, ECDSA P-256 |

---

## 🎯 Objectives

This program demonstrates:

- ✅ Generation of key pairs for PQC and classical algorithms  
- 📦 Signing, encapsulation, verification, and decapsulation operations  
- 📏 Measurement and display of key sizes, signature/ciphertext sizes  
- ⏱️ Timing for key generation, signing, and verification operations  
- 🔁 Verifying correctness of cryptographic operations

---

## 🛠️ Technologies Used

- 💻 **Language**: C  
- 🧪 **Libraries**: 
  - [liboqs](https://openquantumsafe.org/) – for PQC algorithms  
  - [OpenSSL](https://www.openssl.org/) – for classical algorithms

---

## 🧰 Requirements

Make sure you have the following installed:

- ✅ `liboqs` (compiled and installed)
- ✅ `OpenSSL`
- ✅ `gcc` or `clang` with C99 support

---

## ⚙️ How to Compile and Run

```bash
# Basic compilation (if libraries are in standard paths)
gcc -o pqc_vs_classical pqc_vs_classical.c -loqs -lcrypto

# Run the program
./pqc_vs_classical
````

If you have custom paths:

```bash
gcc -I/path/to/liboqs/include -I/usr/include/openssl \
    -L/path/to/liboqs/lib -L/usr/lib \
    -o pqc_vs_classical pqc_vs_classical.c -loqs -lcrypto
./pqc_vs_classical
```

---

## 📊 Sample Output (Simplified)

```
=== PQC vs Classical Comparative Study ===

--- PQC KEM: Kyber512 Demo ---
KeyGen time: ~3.21 ms
Encaps time: ~1.78 ms
Decaps time: ~1.76 ms
Public key length: 800 bytes
Secret key length: 1632 bytes
Ciphertext length: 736 bytes
Shared secrets match? YES

--- PQC SIG: Dilithium2 Demo ---
KeyGen time: ~12.43 ms
Sign time: ~3.12 ms
Public key length: 1312 bytes
Secret key length: 2528 bytes
Signature length: 2420 bytes
Signature verification: SUCCESS

--- Classical SIG: RSA-2048 Demo ---
KeyGen time: ~345 ms
Sign time: ~2.34 ms
Public key approx size: ~294 bytes
Private key approx size: ~1190 bytes
Signature length: 256 bytes
Signature verification: SUCCESS

--- Classical SIG: ECDSA P-256 Demo ---
KeyGen time: ~6.52 ms
Sign time: ~1.12 ms
Signature length: 71 bytes
Signature verification: SUCCESS
```

---

## 📌 Comparative Summary

| Algorithm                  | ⏱️ KeyGen (ms) | ✍️ Sign/Encaps (ms) | ✅ Verify/Decaps (ms) | 📏 Public Key Size | 🔐 Secret Key Size | 📄 Signature/Ciphertext Size |
| -------------------------- | -------------- | ------------------- | -------------------- | ------------------ | ------------------ | ---------------------------- |
| **Kyber512 (PQC - KEM)**   | ~3.0           | ~1.8                | ~1.8                 | 800 bytes          | 1632 bytes         | 736 bytes                    |
| **Dilithium2 (PQC - SIG)** | ~12.4          | ~3.1                | —                    | 1312 bytes         | 2528 bytes         | 2420 bytes                   |
| **RSA-2048**               | ~345.0         | ~2.3                | —                    | ~294 bytes         | ~1190 bytes        | 256 bytes                    |
| **ECDSA P-256**            | ~6.5           | ~1.1                | —                    | N/A                | N/A                | 71 bytes                     |

> 🧠 *Note: Times may vary slightly depending on system hardware and OS.*

---

## 📝 Observations

* 🧪 PQC algorithms like **Kyber512** and **Dilithium2** offer strong post-quantum security
* 🐢 **RSA-2048** has the **slowest** key generation time
* 🧵 **ECDSA** is compact and fast but relies on classical assumptions
* 🔒 PQC signatures and ciphertexts are **larger**, which may impact bandwidth and storage
* 🔐 **Key sizes** in PQC are significantly **larger**, but acceptable considering quantum resilience

---

## 📚 References

* 🌐 [Open Quantum Safe Project (liboqs)](https://openquantumsafe.org/)
* 🔐 [OpenSSL Library](https://www.openssl.org/)
* 🏛️ [NIST PQC Standardization Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
