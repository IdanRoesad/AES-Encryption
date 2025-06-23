# AES-128 Encryption in C++

This project is a C++ implementation of the Advanced Encryption Standard (AES) algorithm with a 128-bit key. It was developed as a final project to demonstrate a fundamental understanding of symmetric-key cryptography and its core components.

## Overview

The application takes a user-provided plaintext string (up to 16 ASCII characters), encrypts it using a hardcoded 128-bit key, and then decrypts the resulting ciphertext to recover the original message. This project covers the essential transformations of the AES algorithm.

## Features

* **AES-128 Encryption & Decryption:** Implements the full 10-round AES cipher for both encryption and decryption.
* **Key Expansion:** Correctly generates the 11 round keys from the initial 128-bit secret key.
* **Core Transformations:** Includes all four main AES operations:
    * `SubBytes` (using the standard S-Box)
    * `ShiftRows`
    * `MixColumns` (with Galois Field arithmetic)
    * `AddRoundKey`
* **PKCS#7 Padding:** Automatically pads input to fit the required 16-byte block size.

## How to Build and Run

You can compile and run this project using a standard C++ compiler like `g++`.

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd <repository-name>
    ```

2.  **Compile the source code:**
    ```bash
    g++ -std=c++11 -o aes_app main.cpp
    ```
    *(Note: `-std=c++11` or newer is recommended)*

3.  **Run the application:**
    ```bash
    ./aes_app
    ```

4.  **Follow the prompt:**
    The program will ask you to enter a plaintext message. After you provide the input, it will display the plaintext in hex, the secret key, the resulting ciphertext, and the final decrypted message.

## Project Purpose

This application was created as a final project for "Cryptography and Network Security" at Gadjah Mada University. The primary goal was to build a working AES implementation from scratch to gain a hands-on understanding of its internal mechanics.
