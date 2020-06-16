//
// Created by Grzegorz on 28.09.2019.
//

#ifndef UNTITLED_ENCRYPTOR_H
#define UNTITLED_ENCRYPTOR_H

#include <bitset>
#include <exception>
#include <cstdint>
#include <vector>
#include <map>
#include <cmath>
#include <climits>
#include <typeinfo>
#include <QObject>
#include <QCoreApplication>
#include <QDebug>
#include <thread>
#include <mutex>
#include "IntoBits.h"
#include "time.h"

class WrongFileException: public std::exception {};

class DES64Crypto : public QObject {

    Q_OBJECT


public:
    DES64Crypto(uint64_t inputKey){
        cryptoKey = inputKey;
    }
    DES64Crypto() = default;

    ~DES64Crypto() override = default;

    void encryptFileECB (const std::string& path, uint64_t key);
    void bufferedFileEncryptionECB (const std::string& path, uint64_t key);
    void bufferedFileDecryptionECB (const std::string& path, uint64_t key);
    void decryptFileECB(const std::string& path, uint64_t key);
    void setCryptoKey(uint64_t cryptoKey) {
        this->cryptoKey = cryptoKey;
    }
    uint64_t getCryptoKey(){
        return this->cryptoKey;
    }

private:
    uint64_t cryptoKey{};
    static uint64_t decryptBlock(uint64_t& input64bitBlock, const uint64_t & inputKey);
    static uint64_t encryptBlock(uint64_t& inputByte, const uint64_t & inputKey);
    static inline uint8_t sBOX(uint8_t input, std::vector<std::vector<uint8_t>> currentSBOX);
    static void turnEightBytesToUint64_t(uint64_t & tempVar, unsigned long long i, std::vector<char> & buffer, int bytesToWriteInBlock);
    static std::vector<uint64_t> sixteenSubKeysGeneration(uint64_t initialKey);
    static uint64_t permutateUint64(uint64_t & input, const std::vector<int> & permutationOrder);
    static uint64_t initialPermutation(uint64_t & input);
    static uint64_t finalPermutation (uint64_t & input);
    static uint64_t keyEncryption (uint64_t inputByte, const std::vector<uint64_t> & keyVector);
    static uint64_t keyDecryption(uint64_t inputByte, const std::vector<uint64_t> & keyVector);
    static std::vector<uint64_t> divideIntoLeftAndRight32BitHalves (uint64_t input);
    static uint64_t mingleMethod(uint64_t input, uint64_t key);
    static void threadedEncryption (std::vector<uint64_t>& inputVector,
                                    std::vector<uint64_t>& outputVector,
                                    uint64_t &key,
                                    unsigned long long startIndex,
                                    unsigned long long stopIndex,
                                    unsigned long long & pBarValue,
                                    std::mutex & mutex);

    static void threadedDecryption(std::vector<uint64_t> &inputVector,
                                         std::vector<uint64_t> &outputVector,
                                         uint64_t &key,
                                         unsigned long long startIndex,
                                         unsigned long long stopIndex,
                                         unsigned long long & pBarValue,
                                         std::mutex & mutex);

signals:
    void valueChanged(int value);
    void sizeOfBar(int value);
    void updateTextField(QString string);
};

#endif //UNTITLED_ENCRYPTOR_H
