//
// Created by nte on 12/5/19.
//

#ifndef UNTITLED3_AES256CIPHER_H
#define UNTITLED3_AES256CIPHER_H


#include <vector>
#include <cstdint>
#include <string>
#include <sstream>
#include <fstream>
#include <mutex>
#include "IntoBits.h"

class AES256cipher {
public:
    explicit AES256cipher(const std::vector<uint8_t>& key){
        this->cryptoKey = key;
        this->expandedKey = keyExpansion(key);
    }

    virtual ~AES256cipher();
    void bufferedAESencryption(std::vector<uint8_t> key, std::string path);



private:
    static std::vector<std::vector<uint32_t>> keyExpansion(std::vector<uint8_t> key);
    static uint32_t turnFourBytesIntoUint32t(std::vector<uint8_t> input);
    static uint32_t rotWord(uint32_t);
    static uint32_t subWord(uint32_t input);
    static void subBytes(std::vector<uint32_t> & inputState);
    static std::vector<uint32_t> shiftRows(std::vector<uint32_t>);
    static std::pair<uint8_t, uint8_t> getRowAndColFromHex(uint8_t);
    static uint8_t charToUint8t (char input);
    std::vector<uint8_t>  cipher (std::vector<uint8_t> input);
    std::vector<uint8_t> invCipher(std::vector<uint8_t> input);
    static std::vector<uint32_t> addRoundKey(std::vector<uint32_t> inputState, std::vector<uint32_t> roundKey);
    static std::vector<uint32_t > mixColumns(std::vector<uint32_t> input);
    static std::vector<uint32_t> invMixColumns(std::vector<uint32_t> input);
    static uint8_t getNthByteofUint32_t (uint32_t input, int byteToGet);
    static std::vector<std::vector<uint8_t>> uint32VectorTransposition(std::vector<uint32_t> input);
    static uint8_t mul2 ( uint8_t input);
    static uint8_t mul3 ( uint8_t input);
    static uint8_t mul9 ( uint8_t input);
    static uint8_t mul11 ( uint8_t input);
    static uint8_t mul13 ( uint8_t input);
    static uint8_t mul14 ( uint8_t input);
    static std::vector<uint8_t> turnUint32tIntoFourBytes (uint32_t input);
    static std::vector<uint32_t> invShiftRows(std::vector<uint32_t>);
    static uint32_t invSubWord(uint32_t input);
    static void invSubBytes(std::vector<uint32_t> & inputState);
    void threadedEncryption(std::vector<uint64_t> &inputVector,
                            std::vector<uint64_t> &outputVector,
                            uint64_t &key,
                            unsigned long long startIndex,
                            unsigned long long stopIndex,
                            unsigned long long & pBarValue,
                            std::mutex & mutex);
    //number of 32 bit words in a block
    constexpr static int Nb = 4;

    //number of round interation 10 for 128bit key 12 for 192 bit key 14 for 256 bit key
    constexpr static int Nr = 10;

    //number of 32 bit words in the key
    constexpr static int Nk = 4;

    std::vector<uint8_t> cryptoKey;
    std::vector<std::vector<uint32_t>> expandedKey;

};

class TooManyBytesException : public std::exception {};


#endif //UNTITLED3_AES256CIPHER_H
