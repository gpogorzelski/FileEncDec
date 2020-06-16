//
// Created by Grzegorz on 27.09.2019.
//

#ifndef UNTITLED_INTOBITS_H
#define UNTITLED_INTOBITS_H

#include <vector>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <fstream>


class IntoBits {
private:
    static std::vector<char> turnInputIntoByteArray (std::string filePath, size_t & size);

public:
    IntoBits(){}
    ~IntoBits(){}

    static std::vector<uint64_t> turnFileIntoUint64tEnc(const std::string& filePath, size_t & outputSize);
    static std::vector<uint64_t> turnFileIntoUint64tDec(const std::string& filePath, size_t &outputSize);
    static uint64_t turnStringKeyIntoUint64T (const std::string key);
    static long long getFileSize (std::string path);
};


#endif //UNTITLED_INTOBITS_H
