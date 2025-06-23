#include <iostream>
#include <vector>
#include <array>
#include <cstdint>
#include <string>
#include <stdexcept>
#include <algorithm>

using State = std::array<std::array<uint8_t, 4>, 4>;

std::array<uint8_t, 16> hexStringToBytes(const std::string& hex) {
    if (hex.length() > 32) {
        throw std::invalid_argument("Hex string is too long for a 16-byte array.");
    }
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even number of characters.");
    }

    std::array<uint8_t, 16> bytes{}; 

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes[i / 2] = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
    }
    return bytes;
}

constexpr std::array<uint8_t, 256> s_box = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

constexpr std::array<uint8_t, 256> inv_s_box = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

constexpr std::array<uint8_t, 11> rcon = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

void subBytes(State& state) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = s_box[state[i][j]];
        }
    }
}

void shiftRows(State& state) {
    uint8_t temp = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = temp;
    std::swap(state[2][0], state[2][2]); std::swap(state[2][1], state[2][3]);
    temp = state[3][0]; state[3][0] = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = temp;
}

uint8_t gmul2(uint8_t a) { return (a << 1) ^ ((a & 0x80) ? 0x1b : 0x00); }
uint8_t gmul3(uint8_t a) { return gmul2(a) ^ a; }

void mixColumns(State& state) {
    for (int c = 0; c < 4; ++c) {
        uint8_t s0 = state[0][c], s1 = state[1][c], s2 = state[2][c], s3 = state[3][c];
        state[0][c] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3;
        state[1][c] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3;
        state[2][c] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3);
        state[3][c] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3);
    }
}

void invSubBytes(State& state) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = inv_s_box[state[i][j]];
        }
    }
}

void invShiftRows(State& state) {
    uint8_t temp = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = temp;
    std::swap(state[2][0], state[2][2]); std::swap(state[2][1], state[2][3]);
    temp = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = temp;
}

uint8_t gmul9(uint8_t a) { return gmul2(gmul2(gmul2(a))) ^ a; }
uint8_t gmul11(uint8_t a) { return gmul2(gmul2(gmul2(a))) ^ gmul2(a) ^ a; }
uint8_t gmul13(uint8_t a) { return gmul2(gmul2(gmul2(a))) ^ gmul2(gmul2(a)) ^ a; }
uint8_t gmul14(uint8_t a) { return gmul2(gmul2(gmul2(a))) ^ gmul2(gmul2(a)) ^ gmul2(a); }

void invMixColumns(State& state) {
    for (int c = 0; c < 4; ++c) {
        uint8_t s0 = state[0][c], s1 = state[1][c], s2 = state[2][c], s3 = state[3][c];
        state[0][c] = gmul14(s0) ^ gmul11(s1) ^ gmul13(s2) ^ gmul9(s3);
        state[1][c] = gmul9(s0)  ^ gmul14(s1) ^ gmul11(s2) ^ gmul13(s3);
        state[2][c] = gmul13(s0) ^ gmul9(s1)  ^ gmul14(s2) ^ gmul11(s3);
        state[3][c] = gmul11(s0) ^ gmul13(s1) ^ gmul9(s2)  ^ gmul14(s3);
    }
}

void addRoundKey(State& state, const State& roundKey) {
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            state[r][c] ^= roundKey[r][c];
        }
    }
}

void keyExpansion(const std::array<uint8_t, 16>& key, std::vector<State>& round_keys) {
    const int Nk = 4, Nr = 10;
    std::array<uint8_t, 16 * (Nr + 1)> w;
    for (int i = 0; i < 4 * Nk; ++i) { w[i] = key[i]; }
    for (int i = Nk; i < 4 * (Nr + 1); ++i) {
        std::array<uint8_t, 4> temp = { w[4 * (i - 1) + 0], w[4 * (i - 1) + 1], w[4 * (i - 1) + 2], w[4 * (i - 1) + 3] };
        if (i % Nk == 0) {
            uint8_t t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            temp[0] = s_box[temp[0]]; temp[1] = s_box[temp[1]]; temp[2] = s_box[temp[2]]; temp[3] = s_box[temp[3]];
            temp[0] ^= rcon[i / Nk];
        }
        w[4 * i + 0] = w[4 * (i - Nk) + 0] ^ temp[0];
        w[4 * i + 1] = w[4 * (i - Nk) + 1] ^ temp[1];
        w[4 * i + 2] = w[4 * (i - Nk) + 2] ^ temp[2];
        w[4 * i + 3] = w[4 * (i - Nk) + 3] ^ temp[3];
    }
    round_keys.resize(Nr + 1);
    for (int r = 0; r < Nr + 1; ++r) {
        for (int c = 0; c < 4; ++c) {
            for (int row = 0; row < 4; ++row) {
                round_keys[r][row][c] = w[r * 16 + c * 4 + row];
            }
        }
    }
}

void aesEncryptBlock(std::array<uint8_t, 16>& block, const std::vector<State>& round_keys) {
    State state;
    for (int i = 0; i < 4; ++i) { for (int j = 0; j < 4; ++j) { state[j][i] = block[i * 4 + j]; } }
    addRoundKey(state, round_keys[0]);
    for (int round = 1; round < 10; ++round) {
        subBytes(state); shiftRows(state); mixColumns(state); addRoundKey(state, round_keys[round]);
    }
    subBytes(state); shiftRows(state); addRoundKey(state, round_keys[10]);
    for (int i = 0; i < 4; ++i) { for (int j = 0; j < 4; ++j) { block[i * 4 + j] = state[j][i]; } }
}

void aesDecryptBlock(std::array<uint8_t, 16>& block, const std::vector<State>& round_keys) {
    State state;
    for (int i = 0; i < 4; ++i) { for (int j = 0; j < 4; ++j) { state[j][i] = block[i * 4 + j]; } }
    addRoundKey(state, round_keys[10]);
    for (int round = 9; round >= 1; --round) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, round_keys[round]);
        invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, round_keys[0]);
    for (int i = 0; i < 4; ++i) { for (int j = 0; j < 4; ++j) { block[i * 4 + j] = state[j][i]; } }
}

template<typename T>
void printHex(const T& container, const std::string& label) {
    std::cout << label << "\n";
    for (const auto& byte : container) {
        std::cout << std::hex << (byte < 0x10 ? "0" : "") << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << "\n\n";
}

void printUnpaddedAscii(const std::array<uint8_t, 16>& block, const std::string& label) {
    std::cout << label << "\n";
    uint8_t padding_val = block.back();
    size_t original_length = 16;

    if (padding_val > 0 && padding_val <= 16) {
        bool is_padded = true;
        for (size_t i = 16 - padding_val; i < 16; ++i) {
            if (block[i] != padding_val) {
                is_padded = false;
                break;
            }
        }
        if (is_padded) {
            original_length = 16 - padding_val;
        }
    }
    
    for (size_t i = 0; i < original_length; ++i) {
        std::cout << static_cast<char>(block[i]);
    }
    std::cout << "\n\n";
}

int main() {
    std::string plaintext_str;
    std::cout << "Enter plaintext (this version handles up to 16 characters): ";
    std::getline(std::cin, plaintext_str);

    if (plaintext_str.length() > 16) {
        std::cout << "Input is too long, truncating to 16 characters." << std::endl;
        plaintext_str.resize(16);
    }

    std::array<uint8_t, 16> plaintext_bytes{};
    size_t message_len = plaintext_str.length();
    uint8_t padding_val = 16 - message_len;
    
    for(size_t i = 0; i < message_len; ++i) {
        plaintext_bytes[i] = static_cast<uint8_t>(plaintext_str[i]);
    }
    for(size_t i = message_len; i < 16; ++i) {
        plaintext_bytes[i] = padding_val;
    }

    std::array<uint8_t, 16> key_bytes = {
        0x69, 0x64, 0x61, 0x6e, 0x67, 0x61, 0x6e, 0x73,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    printHex(plaintext_bytes, "Plaintext (Hex):");
    printHex(key_bytes, "Secret Key:");

    std::vector<State> round_keys;
    keyExpansion(key_bytes, round_keys);

    std::array<uint8_t, 16> ciphertext = plaintext_bytes;
    aesEncryptBlock(ciphertext, round_keys);
    printHex(ciphertext, "Ciphertext:");
    
    std::array<uint8_t, 16> decryptedtext = ciphertext;
    aesDecryptBlock(decryptedtext, round_keys);
    printHex(decryptedtext, "Decrypted plaintext:");
    
    printUnpaddedAscii(decryptedtext, "Plaintext after decryption:");

    return 0;
}