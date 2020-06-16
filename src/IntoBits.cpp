//
// Created by Grzegorz on 27.09.2019.
//

#include <cmath>
#include "IntoBits.h"

std::vector<char> IntoBits::turnInputIntoByteArray(std::string filePath, size_t & inputSize) {

    /**
     * Open a stream to the desired file
     */
    std::ifstream is(filePath.c_str(), std::ios::in | std::ios::binary);
    if (is) {
        // get length of file:
        is.seekg(0, std::ifstream::end);
        long long length = is.tellg();
        inputSize = length;
        is.seekg(0, std::ifstream::beg);

        // allocate memory:
//        auto *buffer = new char[length];
        std::vector<char> buffer(length);
        // read data as a block:
        is.read(&buffer[0], length);
        is.close();

        return buffer;
    } else{

    }

}

std::vector<uint64_t> IntoBits::turnFileIntoUint64tEnc(const std::string& filePath, size_t & outputSize){
    size_t fileSize = 0;
    std::vector<char> inputFileVector = IntoBits::turnInputIntoByteArray(filePath, fileSize);

    uint64_t noOf64BitsBlock = static_cast<uint64_t>(std::floor(fileSize / 8));
    /**
     * +1 block for size of the remainder and +1 for the actual remainder bytes
     */

    uint64_t remainderBytes = fileSize % 8;
    outputSize = noOf64BitsBlock + 2;

    std::vector<uint64_t> outputVector(outputSize);
    outputVector[0] = remainderBytes;
    for (unsigned long long i = 0; i < outputSize - 1; i ++){
        uint64_t temp = 0;
        if ( i < (outputSize - 2)){
            for (int j = 0; j < 8; j++){
                if (inputFileVector[i*8+j] < 0) {
                    auto sigToUnsig = static_cast<uint8_t >(inputFileVector[i * 8 + j]);
                    auto output = static_cast<uint64_t >(sigToUnsig);
                    temp = temp | (output << j * 8);
                } else {
                    auto curr = static_cast<uint64_t>(inputFileVector[i*8+j]);
                    temp =  temp | (curr << j*8);
                }
            }
            outputVector[i+1] = temp;
            temp = 0;

        } else {
            for (uint64_t j = 0; j < remainderBytes; j++){
                if (inputFileVector[i*8+j] < 0) {
                    auto sigToUnsig = static_cast<uint8_t >(inputFileVector[i * 8 + j]);
                    auto output = static_cast<uint64_t >(sigToUnsig);
                    temp = temp | (output << j * 8);
                } else {
                    auto curr = static_cast<uint64_t>(inputFileVector[i*8+j]);
                    temp =  temp | (curr << j*8);
                }
            }
            outputVector[i+1] = temp;
            temp = 0;
        }
    }
    return outputVector;
}
std::vector<uint64_t> IntoBits::turnFileIntoUint64tDec(const std::string& filePath, size_t & outputSize){
    size_t fileSize = 0;
    //turn the encrypted file into a byte array
    std::vector<char> inputFileVector = IntoBits::turnInputIntoByteArray(filePath, fileSize);

    unsigned long long noOf64BitsBlock = fileSize/8;
    short rem = fileSize%8;
    if (rem != 0){
        std::cout<<"This file has not been encrypted with this program or became corrupt"<<std::endl;
    }
    /**
     * +1 block for size of the remainder and +1 for the actual remainder bytes
     */
    outputSize = noOf64BitsBlock;

    std::vector<uint64_t> outputVector(outputSize);

    for (unsigned long long i = 0; i < noOf64BitsBlock; i ++){
        uint64_t temp = 0;
        for (int j = 0; j < 8; j++){
            if (inputFileVector[i*8+j] < 0){

                auto sigToUnsig = static_cast<uint8_t >(inputFileVector[i * 8 + j]);
                auto output = static_cast<uint64_t >(sigToUnsig);
                temp =  temp | (output << j*8);

            } else {
                auto curr = static_cast<uint64_t>(inputFileVector[i*8+j]);
                temp =  temp | (curr << j*8);
            }
        }
        outputVector[i] = temp;
        temp = 0;
    }
    return outputVector;
}
uint64_t IntoBits::turnStringKeyIntoUint64T (const std::string key){
    size_t keySize = key.length();
    if (keySize > 8){
        return 0;
    }else {
        uint64_t uint64TKey = 0;
        for(size_t i = 0; i < keySize; ++i){
            uint8_t selection = static_cast<uint8_t>(key[i]);
            uint64_t castSelection = static_cast<uint64_t>(selection);
            castSelection = castSelection << (i*8);
            uint64TKey = uint64TKey | castSelection;
        }
        return uint64TKey;
    }
}

long long IntoBits::getFileSize(std::string path) {
    std::ifstream fs(path, std::ios::in | std::ios::binary);
    if(fs) {
        fs.seekg(0, std::fstream::end);
        long long fSize = fs.tellg();
        fs.close();
        return fSize;
    } else {
        return -1;
    }
}


