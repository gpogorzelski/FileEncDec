//
// Created by nte on 12/5/19.
//

#include <iomanip>
#include "AES256cipher.h"
const std::vector<std::vector<uint8_t>> SBOX =      {
                                                    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
                                                    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
                                                    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
                                                    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
                                                    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
                                                    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
                                                    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
                                                    {0x51, 0xa3 ,0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
                                                    {0xcd, 0x0c ,0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                                                    {0x60, 0x81 ,0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                                                    {0xe0, 0x32 ,0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                                                    {0xe7, 0xc8 ,0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                                                    {0xba, 0x78 ,0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                                                    {0x70, 0x3e ,0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                                                    {0xe1, 0xf8 ,0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                                                    {0x8c, 0xa1 ,0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
                                                    };
const std::vector<std::vector<uint8_t>> InvSBOX =   {
                                                    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
                                                    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
                                                    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
                                                    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
                                                    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
                                                    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
                                                    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
                                                    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
                                                    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                                                    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
                                                    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
                                                    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
                                                    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
                                                    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
                                                    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
                                                    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
                                                    };
const std::vector<uint32_t> Rcon =                  {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

void AES256cipher::bufferedAESencryption(std::vector<uint8_t> key, std::string path){

    long long fileSize = IntoBits::getFileSize(path);
    long long bufferSize = 32000000;

    long long bufferIterations = fileSize/bufferSize;
    long long remainderBytes = fileSize%bufferSize;
    uint8_t lastBlockSize = remainderBytes%16;
    if (lastBlockSize != 0){
        remainderBytes += (16 - (lastBlockSize));
    }

    //specify buffer read operations number
    if (bufferIterations == 0 && remainderBytes != 0){
        bufferIterations = 1;

    } else if (bufferIterations != 0 && remainderBytes != 0){
        bufferIterations += 1;
    }
    std::vector<char> inputFileBytes(bufferSize);
    std::ifstream istream (path, std::ios::in | std::ios::binary);
    std::ofstream ostream (path, std::ios::out | std::ios::binary);

    for (int i = 0; i < bufferIterations; ++i){
        if (i != (bufferIterations-1)){ //if any but last iteration
            istream.read(&inputFileBytes[0], bufferSize); //read the file into the buffer
            long long encryptionIterations = bufferSize/16;
            for (long long i = 0; i < encryptionIterations; ++i){
                std::vector<char>::const_iterator first{inputFileBytes.begin() + (16*i)};
                std::vector<char>::const_iterator last{inputFileBytes.begin() + (16*i + 15)};
                std::vector<uint8_t> output = this->cipher(std::vector<uint8_t>(first, last));
            }

        }else{ //if last iteration
            inputFileBytes.resize(remainderBytes);
            istream.read(&inputFileBytes[0], remainderBytes); //read the file into the buffer

        }
    }


}


/**********************************************************************************/
std::vector<std::vector<uint32_t>> AES256cipher::keyExpansion(std::vector<uint8_t> key) {

    std::vector<uint32_t> expandedKey(Nb*(Nr+1));
    std::vector<std::vector<uint32_t>> fourWordVectorsOfExpandedKey{Nr+1, std::vector<uint32_t>(4) };
    int i{};
    while (i < Nk){
        expandedKey[i] = turnFourBytesIntoUint32t(std::vector<uint8_t>{key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]});
        i++;
    }
    i = Nk;

    while ( i < (Nb * (Nr +1))){
        uint32_t temp = expandedKey[i - 1];
        if ( i % Nk == 0){
            temp = subWord(rotWord(temp)) xor Rcon[(i/Nk)-1];
        }else if ((Nk > 6) && (i % Nk == 4)){
            temp = subWord(rotWord(temp));
        }
        expandedKey[i] = expandedKey[i-Nk] xor temp;
        i++;
    }
    for (int k = 0; k < (Nr + 1); ++k){
        for(int l = 0; l < 4; ++l){
            fourWordVectorsOfExpandedKey[k][l] = expandedKey[k * 4 + l];
        }
    }
    return fourWordVectorsOfExpandedKey;

}
/**********************************************************************************/
uint32_t AES256cipher::turnFourBytesIntoUint32t(std::vector<uint8_t> input) {

    if (input.size() != 4){
        throw TooManyBytesException();
    } else {
        uint32_t result = 0;
        for (int i = 0; i < 4; ++i){
            uint32_t temp{static_cast<uint32_t>(input[3-i])};
            uint32_t movedBits = temp << i*8;
            result = result | movedBits;
        }
        return result;
    }
}
/**********************************************************************************/
std::vector<uint8_t> AES256cipher::turnUint32tIntoFourBytes (uint32_t input){

    std::vector<uint8_t>output{getNthByteofUint32_t(input, 0),
                               getNthByteofUint32_t(input,1),
                               getNthByteofUint32_t(input, 2),
                               getNthByteofUint32_t(input, 3)};

    return output;
}
uint32_t AES256cipher::rotWord(uint32_t input) {

    uint32_t getFirstEightBits = 255<<24;
    uint32_t frontEightBits = (input & getFirstEightBits)>>24;
    uint32_t backTwentyFourBits = input << 8;
    uint32_t result = frontEightBits | backTwentyFourBits;
    return result;
}
/**********************************************************************************/
uint32_t AES256cipher::subWord(uint32_t input) {
    uint32_t eightBitsOn = 255<<24;
    std::vector<uint8_t> uint32tBytesVector(4);

    //turn 32 bits into 4 separate bytes
    for (int i = 0; i < 4; ++i){
        uint32_t temp{};
        temp = ((eightBitsOn >> (i*8)) & input) >> (3 - i)*8;
        uint32tBytesVector[i] = static_cast<uint8_t>(temp);
    }

    std::vector<uint8_t> bytesAfterSBOXTransformation(4);

    //bytes SBOX transformation
    for (int i = 0; i < 4; ++i){
        std::pair<uint8_t, uint8_t> SBOXCoordinates = getRowAndColFromHex(uint32tBytesVector[i]);
        bytesAfterSBOXTransformation[i] = SBOX[SBOXCoordinates.first][SBOXCoordinates.second];
    }
    uint32_t returnResult = turnFourBytesIntoUint32t(bytesAfterSBOXTransformation);
    return returnResult;
}
/**********************************************************************************/
uint32_t AES256cipher::invSubWord(uint32_t input) {
    uint32_t eightBitsOn = 255<<24;
    std::vector<uint8_t> uint32tBytesVector(4);

    //turn 32 bits into 4 separate bytes
    for (int i = 0; i < 4; ++i){
        uint32_t temp{};
        temp = ((eightBitsOn >> (i*8)) & input) >> (3 - i)*8;
        uint32tBytesVector[i] = static_cast<uint8_t>(temp);
    }

    std::vector<uint8_t> bytesAfterSBOXTransformation(4);

    //bytes SBOX transformation
    for (int i = 0; i < 4; ++i){
        std::pair<uint8_t, uint8_t> SBOXCoordinates = getRowAndColFromHex(uint32tBytesVector[i]);
        bytesAfterSBOXTransformation[i] = InvSBOX[SBOXCoordinates.first][SBOXCoordinates.second];
    }
    uint32_t returnResult = turnFourBytesIntoUint32t(bytesAfterSBOXTransformation);
    return returnResult;
}
/**********************************************************************************/
void AES256cipher::subBytes(std::vector<uint32_t> & inputState){
    std::vector<uint32_t> output(4);
    for (int i = 0; i < 4; ++i){
        inputState[i] = subWord(inputState[i]);
    }
}
/**********************************************************************************/
void AES256cipher::invSubBytes(std::vector<uint32_t> & inputState){
    std::vector<uint32_t> output(4);
    for (int i = 0; i < 4; ++i){
        inputState[i] = invSubWord(inputState[i]);
    }
}
/**********************************************************************************/
std::pair<uint8_t, uint8_t> AES256cipher::getRowAndColFromHex(uint8_t input){

    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    ss<< std::setw(2) << static_cast<unsigned>(input);
    std::string result = ss.str();
    char first = result[0];
    char second = result[1];
    std::pair<uint8_t, uint8_t> returnPair{charToUint8t(first), charToUint8t(second)};
    return returnPair;
}
/**********************************************************************************/
uint8_t AES256cipher::charToUint8t (char input) {
    if(input == '0'){
        return 0;
    } else if (input == '1'){
        return 1;
    } else if (input == '2'){
        return 2;
    } else if (input == '3'){
        return 3;
    } else if (input == '4'){
        return 4;
    } else if (input == '5'){
        return 5;
    } else if (input == '6'){
        return 6;
    } else if (input == '7'){
        return 7;
    } else if (input == '8'){
        return 8;
    } else if (input == '9'){
        return 9;
    } else if (input == 'a'){
        return 10;
    } else if (input == 'b'){
        return 11;
    } else if (input == 'c'){
        return 12;
    } else if (input == 'd'){
        return 13;
    } else if (input == 'e'){
        return 14;
    } else if (input == 'f'){
        return 15;
    } else {
        return 255;
    }
}
/**********************************************************************************/
std::vector<uint32_t> AES256cipher::addRoundKey(std::vector<uint32_t> inputState, std::vector<uint32_t> roundKey){
    std::vector<uint32_t> output(4);
    for(int i = 0; i < 4; ++i){
        output[i] = inputState[i] xor roundKey[i];
    }
    return output;
}
/**********************************************************************************/
std::vector<uint8_t> AES256cipher::cipher(std::vector<uint8_t> input) {

    std::vector<uint32_t> state(4);
    for (int i = 0; i < 4; ++i){
        state[i] = turnFourBytesIntoUint32t({input[4*i], input[4*i + 1], input[4*i + 2], input[4*i + 3]});
    }

    state = addRoundKey(state, this->expandedKey[0]);

    for (int i = 1; i < Nr; ++i ){
        subBytes(state);
        state = shiftRows(state);
        state = mixColumns(state);
        state = addRoundKey(state, this->expandedKey[i]);
    }

    subBytes(state);
    state = shiftRows(state);
    state = addRoundKey(state, this->expandedKey[Nr]);

    std::vector<uint8_t> output(16);

    for (int i = 0; i < 4; ++i){
        output[i*4] = getNthByteofUint32_t(state[i], 0);
        output[i*4 + 1] = getNthByteofUint32_t(state[i], 1);
        output[i*4 + 2] = getNthByteofUint32_t(state[i], 2);
        output[i*4 + 3] = getNthByteofUint32_t(state[i], 3);
    }


    return output;
}
/**********************************************************************************/
std::vector<uint8_t> AES256cipher::invCipher(std::vector<uint8_t> input) {
    std::vector<uint32_t> state(4);
    for (int i = 0; i < 4; ++i){
        state[i] = turnFourBytesIntoUint32t({input[4*i], input[4*i + 1], input[4*i + 2], input[4*i + 3]});
    }

    state = addRoundKey(state, this->expandedKey[Nr]);

    for (int i = Nr-1; i > 0; --i ){
        state = invShiftRows(state);
        invSubBytes(state);
        state = addRoundKey(state, this->expandedKey[i]);
        state = invMixColumns(state);
    }
    state = invShiftRows(state);
    invSubBytes(state);
    state = addRoundKey(state, this->expandedKey[0]);
    std::vector<uint8_t> output(16);

    for (int i = 0; i < 4; ++i){
        output[i*4] = getNthByteofUint32_t(state[i], 0);
        output[i*4 + 1] = getNthByteofUint32_t(state[i], 1);
        output[i*4 + 2] = getNthByteofUint32_t(state[i], 2);
        output[i*4 + 3] = getNthByteofUint32_t(state[i], 3);
    }
    return output;

}
/**********************************************************************************/
std::vector<uint32_t> AES256cipher::shiftRows(std::vector<uint32_t> inputState) {

    std::vector<std::vector<uint8_t>> shiftRowResult(4);
    std::vector<std::vector<uint8_t>> transposedVector = uint32VectorTransposition(inputState);

    shiftRowResult[0] = transposedVector[0];
    shiftRowResult[1] = {transposedVector[1][1], transposedVector[1][2], transposedVector[1][3], transposedVector[1][0]};
    shiftRowResult[2] = {transposedVector[2][2], transposedVector[2][3], transposedVector[2][0], transposedVector[2][1]};
    shiftRowResult[3] = {transposedVector[3][3], transposedVector[3][0], transposedVector[3][1], transposedVector[3][2]};

    std::vector<uint32_t> transposedOutput    {turnFourBytesIntoUint32t({shiftRowResult[0][0], shiftRowResult[1][0], shiftRowResult[2][0],  shiftRowResult[3][0]}),
                                               turnFourBytesIntoUint32t({shiftRowResult[0][1], shiftRowResult[1][1], shiftRowResult[2][1],  shiftRowResult[3][1]}),
                                               turnFourBytesIntoUint32t({shiftRowResult[0][2], shiftRowResult[1][2], shiftRowResult[2][2],  shiftRowResult[3][2]}),
                                               turnFourBytesIntoUint32t({shiftRowResult[0][3], shiftRowResult[1][3], shiftRowResult[2][3],  shiftRowResult[3][3]})};
    return transposedOutput;
}
/**********************************************************************************/
std::vector<uint32_t> AES256cipher::invShiftRows(std::vector<uint32_t> inputState) {

    std::vector<std::vector<uint8_t>> shiftRowResult(4);
    std::vector<std::vector<uint8_t>> transposedVector = uint32VectorTransposition(inputState);

    shiftRowResult[0] = transposedVector[0];
    shiftRowResult[1] = {transposedVector[1][3], transposedVector[1][0], transposedVector[1][1], transposedVector[1][2]};
    shiftRowResult[2] = {transposedVector[2][2], transposedVector[2][3], transposedVector[2][0], transposedVector[2][1]};
    shiftRowResult[3] = {transposedVector[3][1], transposedVector[3][2], transposedVector[3][3], transposedVector[3][0]};

    std::vector<uint32_t> transposedOutput    {turnFourBytesIntoUint32t({shiftRowResult[0][0], shiftRowResult[1][0], shiftRowResult[2][0],  shiftRowResult[3][0]}),
                                               turnFourBytesIntoUint32t({shiftRowResult[0][1], shiftRowResult[1][1], shiftRowResult[2][1],  shiftRowResult[3][1]}),
                                               turnFourBytesIntoUint32t({shiftRowResult[0][2], shiftRowResult[1][2], shiftRowResult[2][2],  shiftRowResult[3][2]}),
                                               turnFourBytesIntoUint32t({shiftRowResult[0][3], shiftRowResult[1][3], shiftRowResult[2][3],  shiftRowResult[3][3]})};
    return transposedOutput;
}
/**********************************************************************************/
std::vector<uint32_t> AES256cipher::mixColumns(std::vector<uint32_t> input) {

    std::vector<std::vector<uint8_t>> transposedInput{
                                                      {getNthByteofUint32_t(input[0], 0), getNthByteofUint32_t(input[0], 1), getNthByteofUint32_t(input[0], 2), getNthByteofUint32_t(input[0], 3)},
                                                      {getNthByteofUint32_t(input[1], 0), getNthByteofUint32_t(input[1], 1), getNthByteofUint32_t(input[1], 2), getNthByteofUint32_t(input[1], 3)},
                                                      {getNthByteofUint32_t(input[2], 0), getNthByteofUint32_t(input[2], 1), getNthByteofUint32_t(input[2], 2), getNthByteofUint32_t(input[2], 3)},
                                                      {getNthByteofUint32_t(input[3], 0), getNthByteofUint32_t(input[3], 1), getNthByteofUint32_t(input[3], 2), getNthByteofUint32_t(input[3], 3)}
                                                      };
    std::vector<std::vector<uint8_t>> afterMixColBytes = transposedInput;

    for (int i = 0; i < 4; ++i){
        afterMixColBytes[i][0] = mul2(transposedInput[i][0]) ^ mul3(transposedInput[i][1]) ^ transposedInput[i][2] ^ transposedInput[i][3];
        afterMixColBytes[i][1] = transposedInput[i][0] ^ mul2(transposedInput[i][1]) ^ mul3(transposedInput[i][2]) ^ transposedInput[i][3];
        afterMixColBytes[i][2] = transposedInput[i][0] ^ transposedInput[i][1] ^ mul2(transposedInput[i][2]) ^ mul3(transposedInput[i][3]);
        afterMixColBytes[i][3] = mul3(transposedInput[i][0]) ^ transposedInput[i][1] ^ transposedInput[i][2] ^ mul2(transposedInput[i][3]);

    }
    std::vector<uint32_t> afterMixColumns{turnFourBytesIntoUint32t(afterMixColBytes[0]),
                                          turnFourBytesIntoUint32t(afterMixColBytes[1]),
                                          turnFourBytesIntoUint32t(afterMixColBytes[2]),
                                          turnFourBytesIntoUint32t(afterMixColBytes[3])};
    return afterMixColumns;
}
/**********************************************************************************/
std::vector<uint32_t> AES256cipher::invMixColumns(std::vector<uint32_t> input) {

    std::vector<std::vector<uint8_t>> transposedInput{
            {getNthByteofUint32_t(input[0], 0), getNthByteofUint32_t(input[0], 1), getNthByteofUint32_t(input[0], 2), getNthByteofUint32_t(input[0], 3)},
            {getNthByteofUint32_t(input[1], 0), getNthByteofUint32_t(input[1], 1), getNthByteofUint32_t(input[1], 2), getNthByteofUint32_t(input[1], 3)},
            {getNthByteofUint32_t(input[2], 0), getNthByteofUint32_t(input[2], 1), getNthByteofUint32_t(input[2], 2), getNthByteofUint32_t(input[2], 3)},
            {getNthByteofUint32_t(input[3], 0), getNthByteofUint32_t(input[3], 1), getNthByteofUint32_t(input[3], 2), getNthByteofUint32_t(input[3], 3)}
    };
    std::vector<std::vector<uint8_t>> afterMixColBytes = transposedInput;

    for (int i = 0; i < 4; ++i){
        afterMixColBytes[i][0] = mul14(transposedInput[i][0]) ^ mul11(transposedInput[i][1]) ^ mul13(transposedInput[i][2]) ^ mul9(transposedInput[i][3]);
        afterMixColBytes[i][1] = mul9(transposedInput[i][0]) ^ mul14(transposedInput[i][1]) ^ mul11(transposedInput[i][2]) ^ mul13(transposedInput[i][3]);
        afterMixColBytes[i][2] = mul13(transposedInput[i][0]) ^ mul9(transposedInput[i][1]) ^ mul14(transposedInput[i][2]) ^ mul11(transposedInput[i][3]);
        afterMixColBytes[i][3] = mul11(transposedInput[i][0]) ^ mul13(transposedInput[i][1]) ^ mul9(transposedInput[i][2]) ^ mul14(transposedInput[i][3]);

    }
    std::vector<uint32_t> afterMixColumns{turnFourBytesIntoUint32t(afterMixColBytes[0]),
                                          turnFourBytesIntoUint32t(afterMixColBytes[1]),
                                          turnFourBytesIntoUint32t(afterMixColBytes[2]),
                                          turnFourBytesIntoUint32t(afterMixColBytes[3])};
    return afterMixColumns;
}
/**********************************************************************************/
uint8_t AES256cipher::getNthByteofUint32_t (uint32_t input, int byteToGet){
    uint32_t byteMask = 0xff000000 >> (byteToGet*8);

    uint32_t theByte = input & byteMask;
    uint8_t placesToShift = 24 - (byteToGet*8);
    theByte = theByte >> placesToShift;
    uint8_t output = static_cast<uint8_t >(theByte);
    return theByte;
}
/**********************************************************************************/
uint8_t AES256cipher::mul2 (uint8_t input){
    bool isFirstBitOn = input & 0x80;
    uint8_t temp = input << 1;
    if(isFirstBitOn){
        temp = temp ^0x11b;
    }
    return temp;
}
/**********************************************************************************/
uint8_t AES256cipher::mul3 ( uint8_t input){
    return mul2(input) ^ input;
}
/**********************************************************************************/
uint8_t AES256cipher::mul9 (uint8_t input){
    return mul2(mul2(mul2(input))) ^ input;
}
/**********************************************************************************/
uint8_t AES256cipher::mul11 (uint8_t input){
    return mul2(input ^ mul2(mul2(input))) ^ input;
}
/**********************************************************************************/
uint8_t AES256cipher::mul13 (uint8_t input){
    return mul2(mul2(input ^ mul2(input))) ^ input;
}
/**********************************************************************************/
uint8_t AES256cipher::mul14 (uint8_t input){
    return mul2(mul2(input^ mul2(input))^ input);
}
/**********************************************************************************/
std::vector<std::vector<uint8_t>> AES256cipher::uint32VectorTransposition(std::vector<uint32_t> input){
    std::vector<std::vector<uint8_t>>output(4, std::vector<uint8_t>(4));
    std::vector<uint8_t> temp(4);

    for (int i = 0; i < 4; ++i){
        temp[0] = getNthByteofUint32_t(input[0], i);
        temp[1] = getNthByteofUint32_t(input[1], i);
        temp[2] = getNthByteofUint32_t(input[2], i);
        temp[3] = getNthByteofUint32_t(input[3], i);
        output[i] = temp;
    }
    return output;
}
/**********************************************************************************/
AES256cipher::~AES256cipher() = default;
