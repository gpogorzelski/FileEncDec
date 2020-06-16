#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"
//
// Created by Grzegorz on 28.09.2019.
//

#include "DES64Crypto.h"
#include <QElapsedTimer>

unsigned long long pBarVal = 0;
unsigned long long iterationsSoFar = 0;

const std::vector<int> init_vector =            {56, 48, 40, 32, 24, 16, 8,
                                                0, 57, 49, 41, 33, 25, 17,
                                                9, 1, 58, 50, 42, 34, 26,
                                                18, 10, 2, 59, 51, 43, 35,
                                                62, 54, 46, 38, 30, 22, 14,
                                                6, 61, 53, 45, 37, 29, 21,
                                                13, 5, 60, 52, 44, 36, 28,
                                                20, 12, 4, 27, 19, 11, 3};

const std::vector<int> init_perm_vec =          {57, 49, 41, 33, 25, 17, 9, 1,
                                        59, 51, 43, 35, 27, 19, 11, 3,
                                        61, 53, 45, 37, 29, 21, 13, 5,
                                        63, 55, 47, 39, 31, 23, 15, 7,
                                        56, 48, 40, 32, 24, 16, 8, 0,
                                        58, 50, 42, 34, 26, 18, 10, 2,
                                        60, 52, 44, 36, 28, 20, 12, 4,
                                        62, 54, 46, 38, 30, 22, 14, 6};

const std::vector<int> PC_1 =                   {56, 48, 40, 32, 24, 16, 8,
                                        0, 57, 49, 41, 33, 25, 17,
                                        9, 1, 58, 50, 42, 34, 26,
                                        18, 10, 2, 59, 51, 43, 35,
                                        62, 54, 46, 38, 30, 22, 14,
                                        6, 61, 53, 45, 37, 29, 21,
                                        13, 5, 60, 52, 44, 36, 28,
                                        20, 12, 4, 27, 19, 11, 3};

const std::vector<int> PO =                     {39, 7, 47, 15, 55, 23, 63, 31,
                                        38, 6, 46, 14, 54, 22, 62, 30,
                                        37, 5, 45, 13, 53, 21, 61, 29,
                                        36, 4, 44, 12, 52, 20, 60, 28,
                                        35, 3, 43, 11, 51, 19, 59, 27,
                                        34, 2, 42, 10, 50, 18, 58, 26,
                                        33, 1, 41, 9, 49, 17, 57, 25,
                                        32, 0, 40, 8, 48, 16, 56, 24};

const std::vector<int> rotateOneBitLeft =       {1, 2, 3, 4, 5, 6,
                                             7, 8, 9, 10, 11, 12, 13, 14,
                                             15, 16, 17, 18, 19, 20, 21, 22,
                                             23, 24, 25, 26, 27, 0};

const std::vector<int> rotateTwoBitsLeft =      {2, 3, 4, 5,
                                             6, 7, 8, 9, 10, 11, 12, 13,
                                             14, 15, 16, 17, 18, 19, 20, 21,
                                             22, 23, 24, 25, 26, 27, 0, 1};

const std::vector<int> PC_2 =                   {13, 16, 10, 23, 0, 4, 2, 27,
                                             14, 5, 20, 9, 22, 18, 11, 3,
                                             25, 7, 15, 6, 26, 19, 12, 1,
                                             40, 51, 30, 36, 46, 54, 29, 39,
                                             50, 44, 32, 47, 43, 48, 38, 55,
                                             33, 52, 45, 41, 49, 35, 28, 31};

const std::vector<std::vector<uint8_t>> SBOX1 = {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                                                 {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                                                 {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                                                 {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}};

const std::vector<std::vector<uint8_t>> SBOX2 = {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                                                 {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                                                 {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                                                 {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}};

const std::vector<std::vector<uint8_t>> SBOX3 = {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                                                 {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                                                 {13, 6, 4, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                                                 {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}};

const std::vector<std::vector<uint8_t>> SBOX4 = {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                                                 {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                                                 {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                                                 {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}};

const std::vector<std::vector<uint8_t>> SBOX5 = {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                                                 {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                                                 {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                                                 {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}};

const std::vector<std::vector<uint8_t>> SBOX6 = {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 2, 11},
                                                 {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                                                 {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                                                 {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}};

const std::vector<std::vector<uint8_t>> SBOX7 = {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                                                 {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                                                 {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                                                 {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}};

const std::vector<std::vector<uint8_t>> SBOX8 = {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                                                 {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                                                 {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                                                 {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

const std::vector<std::vector<std::vector<uint8_t>>> SBOXVector = {SBOX1, SBOX2, SBOX3, SBOX4, SBOX5, SBOX6, SBOX7, SBOX8};

const std::vector<int> E_selection =            {31, 0, 1, 2, 3, 4, 3, 4,
                                        5, 6, 7, 8, 7, 8, 9, 10,
                                        11, 12, 11, 12, 13, 14, 15, 16,
                                        15, 16, 17, 18, 19, 20, 19, 20,
                                        21, 22, 23, 24, 23, 24, 25, 26,
                                        27, 28, 27, 28, 29, 30, 31, 0};

const std::vector<int> permutationP =           {15, 6, 19, 20, 28, 11, 27, 16,
                                        0, 14, 22, 25, 4, 17, 30, 9,
                                        1, 7, 23, 13, 31, 26, 2, 8,
                                        18, 12, 29, 5, 21, 10, 3, 24};

std::vector<uint64_t> sixteenEncryptionKeys;
std::vector<std::vector<uint64_t>> tripleDESsixteenEncryptionKeys;


uint64_t DES64Crypto::permutateUint64 (uint64_t & input, const std::vector<int> & permutationOrder) {
    uint64_t output = 0;
    uint64_t temp = 1;
    for (size_t i = 0; i < permutationOrder.size(); ++i){
        if (i <= permutationOrder[i]){
            output = output | ((input & (temp << permutationOrder[i])) >> (permutationOrder[i] - i));
        } else {
            output = output | ((input & (temp << permutationOrder[i])) << (i - permutationOrder[i]));
        }
    }
    return output;
}
/*********************************************************************************************/
uint64_t DES64Crypto::initialPermutation(uint64_t & input) {

    //Initial data permutation
    uint64_t output =  DES64Crypto::permutateUint64(input, init_perm_vec);
    return output;
}
/*********************************************************************************************/
std::vector<uint64_t> DES64Crypto::sixteenSubKeysGeneration(uint64_t initialKey) {

    // Initial key permutation
    uint64_t nextPermutationResult = DES64Crypto::permutateUint64(initialKey, PC_1);

    //Split key into two 28 bits parts
    //value with bits 0 - 27 ON
     uint64_t getLastTwentyEightBits = 268435455;

     uint64_t secondPart = nextPermutationResult >> 28u;
     uint64_t firstPart = nextPermutationResult & getLastTwentyEightBits;

    std::vector<uint64_t> sixteenConcatenatedShiftedKeys;

    for (int i = 0; i < 16; ++i){
        if (i == 0 || i == 1 || i == 8 || i == 15){
            uint64_t firstPartTempCn = DES64Crypto::permutateUint64(firstPart, rotateOneBitLeft);
            uint64_t secondPartTempDn = DES64Crypto::permutateUint64(secondPart, rotateOneBitLeft);
            uint64_t nRoundKey = (secondPartTempDn << 28) | firstPartTempCn;
            sixteenConcatenatedShiftedKeys.push_back(nRoundKey);
            firstPart = firstPartTempCn;
            secondPart = secondPartTempDn;
        } else {
            uint64_t firstPartTempCn = DES64Crypto::permutateUint64(firstPart, rotateTwoBitsLeft);
            uint64_t secondPartTempDn = DES64Crypto::permutateUint64(secondPart, rotateTwoBitsLeft);
            uint64_t nRoundKey = (secondPartTempDn << 28u) | firstPartTempCn;
            sixteenConcatenatedShiftedKeys.push_back(nRoundKey);
            firstPart = firstPartTempCn;
            secondPart = secondPartTempDn;
        }
     }
     std::vector<uint64_t> sixteenSubKeys(16);
     for (int i =0; i < 16; ++i){
         sixteenSubKeys[i] = DES64Crypto::permutateUint64(sixteenConcatenatedShiftedKeys[i], PC_2);
     }
    return sixteenSubKeys;
}
/*********************************************************************************************/
uint8_t DES64Crypto::sBOX(uint8_t input, std::vector<std::vector<uint8_t> > currentSBOX) {

    uint8_t outerBit = 32;
    uint8_t innerBit = 1;
    uint8_t row = ((input & outerBit) >> 4) | (input & innerBit);
    uint8_t column = (input & 30) >> 1;
    return currentSBOX[row][column];
}
/*********************************************************************************************/
uint64_t DES64Crypto::mingleMethod (uint64_t input, uint64_t key){

    uint64_t P32to48Permutation = DES64Crypto::permutateUint64(input, E_selection);

    //XoR the output of 32 to 48 permutation with the key

    uint64_t xorOutputAndKey = key xor P32to48Permutation;

    //Get the SBOX addresses

    std::vector<uint8_t> SBOXaddresses;

    for (int i = 0; i < 8; ++i){
        uint64_t tempAddress = 63;
        uint64_t currentBitSelection = tempAddress << (i*6);
        uint64_t nRoundBits = xorOutputAndKey & currentBitSelection;
        uint64_t tempResult = nRoundBits >> (i*6);
        SBOXaddresses.push_back(static_cast<uint8_t>(tempResult));
    }

    std::vector<uint8_t> SBOXResults(8);

    for (int i = 0; i < 8; ++i){
        SBOXResults[i] = DES64Crypto::sBOX(SBOXaddresses[i], SBOXVector[i]);
    }
    uint64_t outputAndKeyAfterSBOX = 0;

    for (int i = 0; i < 8; ++i){
        uint64_t temp = 0;
        uint64_t nRoundBits = temp | SBOXResults[i];
        uint64_t nRoundBitsInTheRightPos = nRoundBits << (i * 4);
        outputAndKeyAfterSBOX = outputAndKeyAfterSBOX | nRoundBitsInTheRightPos;
    }

    //permutation P on the SBOX results 32 into 32
    uint64_t mingleOutput = DES64Crypto::permutateUint64(outputAndKeyAfterSBOX, permutationP);

    return mingleOutput;
}
/*********************************************************************************************/
uint64_t DES64Crypto::keyEncryption(uint64_t inputByte, const std::vector<uint64_t> & keyVector) {

    //Split the input byte into two parts

    std::vector<uint64_t> splitInputData = DES64Crypto::divideIntoLeftAndRight32BitHalves(inputByte);
    uint64_t L_0 = splitInputData[0];
    uint64_t R_0 = splitInputData[1];
    uint64_t L_1;
    uint64_t R_1;

    //16 iteration of the input data
    for (int i = 1; i < 17; ++i){
        L_1 = R_0;
        R_1 = L_0 ^ DES64Crypto::mingleMethod(R_0, keyVector[i - 1]);
        R_0 = R_1;
        L_0 = L_1;
    }

    //reverse the order of the two blocks to R_L
    uint64_t finalResultOne = (R_1 << 32) ;
    uint64_t finalResult = finalResultOne | L_1;

    return finalResult;
}
/*********************************************************************************************/
uint64_t DES64Crypto::keyDecryption(uint64_t inputByte, const std::vector<uint64_t> & keyVector) {

    //Split the input byte into two parts
    std::vector<uint64_t> splitInputData = DES64Crypto::divideIntoLeftAndRight32BitHalves(inputByte);
    uint64_t L_0 = splitInputData[0];
    uint64_t R_0 = splitInputData[1];
    uint64_t L_1;
    uint64_t R_1;

    //16 iteration of the input data
    for (int i = 1; i < 17; ++i){
        L_1 = R_0;
        R_1 = L_0 ^ DES64Crypto::mingleMethod(R_0, keyVector[keyVector.size() - i]);
        R_0 = R_1;
        L_0 = L_1;
    }

    //reverse the order of the two blocks to R_L

    uint64_t finalResultOne = (R_1 << 32) ;
    uint64_t finalResult = finalResultOne | L_1;

    return finalResult;
}
/*********************************************************************************************/
std::vector<uint64_t> DES64Crypto::divideIntoLeftAndRight32BitHalves(uint64_t input) {
    uint64_t last32BitsOn = 4294967295;
    uint64_t leftPart = input >> 32u;
    uint64_t rightPart = (input & last32BitsOn);
    std::vector<uint64_t> result = {leftPart, rightPart};
    return result;
}
/*********************************************************************************************/
uint64_t DES64Crypto::finalPermutation(uint64_t & input) {
    uint64_t poResult = DES64Crypto::permutateUint64(input, PO);
    return poResult;
}
/*********************************************************************************************/
uint64_t DES64Crypto::encryptBlock(uint64_t& input64bitBlock, const uint64_t  & inputKey) {
    /**
     * Initial permutation of the data
     */
    uint64_t output = DES64Crypto::initialPermutation(input64bitBlock);

    /**
     * Encryption with 16 round keys
     */
    uint64_t keyEncryptionresult = DES64Crypto::keyEncryption(output, sixteenEncryptionKeys);

    uint64_t finalPermutation = DES64Crypto::finalPermutation(keyEncryptionresult);
    return finalPermutation;
}
/*********************************************************************************************/

uint64_t DES64Crypto::decryptBlock(uint64_t& input64bitBlock, const uint64_t & inputKey){
    /**
     * Initial permutation of the data
     */
    uint64_t output = DES64Crypto::initialPermutation(input64bitBlock);

    /**
     * Decryption with 16 round keys
     */
    uint64_t keyEncryptionresult = DES64Crypto::keyDecryption(output, sixteenEncryptionKeys);

    uint64_t reversePermutation = DES64Crypto::finalPermutation(keyEncryptionresult);

    return reversePermutation;
}
/*********************************************************************************************/
void DES64Crypto::encryptFileECB(const std::string& path, uint64_t key) {

    size_t outputSize;

    //setting pbar start value back to 0
    pBarVal = 0;

    emit updateTextField(QString("Loading file..."));
    std::vector<uint64_t> inputFileVector = IntoBits::turnFileIntoUint64tEnc(path, outputSize);
    (outputSize>INT_MAX)?(emit sizeOfBar(INT_MAX)):(emit sizeOfBar(outputSize));
    std::vector<uint64_t> encryptedFileVector(outputSize);
    emit updateTextField(QString("File loaded"));

    sixteenEncryptionKeys = sixteenSubKeysGeneration(this->cryptoKey);

    size_t maxNumOfThreads = std::thread::hardware_concurrency();

    std::mutex mutex;

    size_t numOfThreadsToSpawn = (outputSize>maxNumOfThreads)?(maxNumOfThreads):(outputSize);
    std::vector<std::thread*> threads(numOfThreadsToSpawn);

    size_t blocksForEachThread = outputSize/numOfThreadsToSpawn;

    emit updateTextField(QString("Encrypting..."));

    for (unsigned long long i = 0; i < numOfThreadsToSpawn; ++i){
        if (i == numOfThreadsToSpawn - 1){
            threads[i] = new std::thread(threadedEncryption, std::ref(inputFileVector), std::ref(encryptedFileVector), std::ref(key), (i*blocksForEachThread), outputSize, std::ref(pBarVal), std::ref(mutex));

        } else {
            threads[i] = new std::thread(threadedEncryption, std::ref(inputFileVector), std::ref(encryptedFileVector), std::ref(key), (i*blocksForEachThread), ((i*blocksForEachThread) + blocksForEachThread), std::ref(pBarVal), std::ref(mutex));
        }

    }

    while (pBarVal < outputSize){
        (outputSize>INT_MAX)?(emit valueChanged((pBarVal*INT_MAX)/outputSize)):(emit valueChanged(pBarVal));
        QCoreApplication::processEvents();

    }

    for (size_t i = 0; i < numOfThreadsToSpawn; ++i){
        if (threads[i]->joinable()){
            threads[i]->join();
            delete threads[i];
        }
    }

    emit updateTextField(QString("File data successfully encrypted"));

    /**
     * Turn the encrypted 64 bit blocks array back into bytes for write file operations
     */
    std::vector<char> encryptedFileAsBytes(outputSize*8);
    for (unsigned long long j = 0; j < outputSize; j++){
        for (int i = 0; i < 8; ++i){
            uint64_t tempInp = 255;
            auto move = static_cast<short>(i*8);
            uint64_t temp = tempInp << move;
            uint64_t output64 = 0;
            output64 = ((encryptedFileVector[j]) & temp) >> (i * 8);

            char output = static_cast<char>(output64);
            encryptedFileAsBytes[j * 8 + i] = output;
        }
    }

    /**
    * Open a stream to the desired file
    */
    emit updateTextField(QString("Writing to file..."));

    std::ofstream is(path, std::ios::out | std::ios::binary);
    if (is) {
        is.write(&encryptedFileAsBytes[0], (outputSize*8));
        is.close();
    }
    emit updateTextField(QString("Success!"));


}
/*********************************************************************************************/
void DES64Crypto::decryptFileECB (const std::string& path, uint64_t key){
    size_t outputSize;
    //setting pbar start value back to 0
    pBarVal = 0;

    emit updateTextField(QString("Loading file..."));

    //turn bytes of a file into an array of 64 bit blocks
    std::vector<uint64_t> inputFileVector = IntoBits::turnFileIntoUint64tDec(path, outputSize);
//    emit sizeOfBar(outputSize);
    (outputSize>INT_MAX)?(emit sizeOfBar(INT_MAX)):(emit sizeOfBar(outputSize));

    emit updateTextField(QString("File loaded"));

    std::vector<uint64_t> decryptedFileVector(outputSize);
    sixteenEncryptionKeys = sixteenSubKeysGeneration(this->cryptoKey);


    //get the max number of threads possible to spawn on this machine
    size_t maxNumOfThreads = std::thread::hardware_concurrency();

    std::mutex mutex;

    //calcualtes the number of threads to spawn for operations depending on the size of input file
    size_t numOfThreadsToSpawn = (outputSize>maxNumOfThreads)?(maxNumOfThreads):(outputSize);

    //create a vector of pointers to threads
    std::vector<std::thread*> threads(numOfThreadsToSpawn);

    //number of blocks destined for each thread to decrypt
    size_t blocksForEachThread = outputSize/numOfThreadsToSpawn;

    emit updateTextField(QString("Decrypting..."));

    //spawn threads
    for (unsigned long long i = 0; i < numOfThreadsToSpawn; ++i){

        //if its the last thread to be created make the decryption operation finish at an index equal to outputSize-1
        if (i == numOfThreadsToSpawn - 1){
            threads[i] = new std::thread(threadedDecryption, std::ref(inputFileVector), std::ref(decryptedFileVector), std::ref(key), (i*blocksForEachThread), outputSize, std::ref(pBarVal), std::ref(mutex));

        } else {
            threads[i] = new std::thread(threadedDecryption, std::ref(inputFileVector), std::ref(decryptedFileVector), std::ref(key), (i*blocksForEachThread), ((i*blocksForEachThread) + blocksForEachThread), std::ref(pBarVal), std::ref(mutex));
        }

    }
    // update the progress bar, the global pBarVal is updated in the method passed to the threads
    while (pBarVal < outputSize){
        (outputSize>INT_MAX)?(emit valueChanged((pBarVal*INT_MAX)/outputSize)):(emit valueChanged(pBarVal));
        QCoreApplication::processEvents();

    }

    //join all the spawned threads
    for (size_t i = 0; i < numOfThreadsToSpawn; ++i){
        if (threads[i]->joinable()){
            threads[i]->join();
            delete threads[i];
        }
    }

    emit updateTextField(QString("File data successfully decrypted"));

    auto remainderBytes = decryptedFileVector[0];
    auto outputFileSize = (outputSize - 2) * 8 + remainderBytes;
    std::vector<char> decryptedFileAsBytesVector(outputFileSize);

    for (unsigned long long j = 1; j < outputSize; j++){
        if (j != (outputSize - 1)){
            for (unsigned int i = 0; i < 8; ++i){
                uint64_t tempInp = 255;
                auto move = static_cast<short>(i*8);
                uint64_t temp = tempInp << move;
                uint64_t output64 = 0;
                output64 = ((decryptedFileVector[j]) & temp) >> (i * 8);
                char output = static_cast<char>(output64);
                decryptedFileAsBytesVector[j * 8 + i - 8] = output;
            }
        } else {
            for (unsigned int i = 0; i < remainderBytes; ++i){
                uint64_t tempInp = 255;
                auto move = static_cast<short>(i*8);
                uint64_t temp = tempInp << move;
                uint64_t output64 = 0;
                output64 = ((decryptedFileVector[j]) & temp) >> (i * 8);
                char output = static_cast<char>(output64);
                decryptedFileAsBytesVector[j * 8 + i - 8] = output;

            }
        }

    }
    /**
    * Open a stream to the desired file
    */
    emit updateTextField(QString("Writing to file..."));

    std::ofstream is(path, std::ios::out | std::ios::binary);
    if (is) {
        is.write(&decryptedFileAsBytesVector[0], outputFileSize);
        is.close();
    }
    emit updateTextField(QString("Success!"));

}
/*********************************************************************************************/
void DES64Crypto::threadedEncryption(std::vector<uint64_t> &inputVector,
                                     std::vector<uint64_t> &outputVector,
                                     uint64_t &key,
                                     unsigned long long startIndex,
                                     unsigned long long stopIndex,
                                     unsigned long long & pBarValue,
                                     std::mutex & mutex)
{

        for (unsigned long long i = startIndex; i < stopIndex; ++i) {
            uint64_t encryptedTemp = DES64Crypto::encryptBlock(inputVector[i], key);
            outputVector[i] = encryptedTemp;

            mutex.lock();
            pBarValue++;
            mutex.unlock();

        }

}
/*********************************************************************************************/
void DES64Crypto::threadedDecryption(std::vector<uint64_t> &inputVector,
                                     std::vector<uint64_t> &outputVector,
                                     uint64_t &key,
                                     unsigned long long startIndex,
                                     unsigned long long stopIndex,
                                     unsigned long long & pBarValue,
                                     std::mutex & mutex)
{

        for (unsigned long long i = startIndex; i < stopIndex; ++i) {
            uint64_t encryptedTemp = DES64Crypto::decryptBlock(inputVector[i], key);
            outputVector[i] = encryptedTemp;

            mutex.lock();
            pBarValue++;
            mutex.unlock();

        }

}

void DES64Crypto::bufferedFileEncryptionECB (const std::string& path, uint64_t key){

    emit updateTextField(QString("Loading file..."));
    pBarVal = 0;
    unsigned long long cumulativeBlockSize{};
    constexpr long long bufferSize = 32000000; //has to be dividable by 8
    std::ifstream is(path, std::ios::in | std::ios::binary);
    size_t dotIndexInPath = path.find(".");
    std::string writePath = path;
    writePath.insert(dotIndexInPath, "Enc");
    std::ofstream os(writePath, std::ios::out | std::ios::binary);
    sixteenEncryptionKeys = sixteenSubKeysGeneration(this->cryptoKey);
    is.seekg(0, std::ifstream::end);
    long long fileSize = is.tellg();
    if (fileSize < 0){
        throw WrongFileException();
    }
    is.seekg(0, std::ifstream::beg);
    long long maxBlockVectorSize = (fileSize/8) + 2;

    //set the pBar size
    int pBarSize = (maxBlockVectorSize>INT_MAX)?(INT_MAX):(maxBlockVectorSize);
    emit sizeOfBar(pBarSize);

    //get the last bytes of a file that are not enough to construct a full block
    uint64_t remainderBytes = fileSize%8;

    //var holding the read iterations, each with a buffer size, on the input file
    long long readIterations{};
    if (fileSize > bufferSize){
        readIterations = ((fileSize%bufferSize) == 0)?(fileSize/bufferSize):((fileSize/bufferSize) + 1);
    } else {
        readIterations = 1;
    }

    //create a vector with a greatest possible size for any iteration to be resized down when needed
    emit updateTextField(QString("Encrypting..."));
    qDebug()<<"No of read iterations = "<<readIterations;
    long long currIter = 0;

    //ktory z kolei bufor opracowujemy
    for(long long i = 0; i < readIterations; ++i){
        std::vector<uint64_t > outputBlockVector((bufferSize/8)+2);

        //if first and only iter
        if (currIter == 0 && readIterations <= 1){        //if first and only iter
            std::vector<char> buffer(fileSize);
            long long currentEncIter = 0;
            if (is){
                is.read(&buffer[0], fileSize);
            }

            uint64_t blockVectorSize = (fileSize/8) + 2;
            outputBlockVector.resize(blockVectorSize);
            outputBlockVector[0] = remainderBytes;
            /******************TURNING TO 64 BIT VECTOR*******************/
            for (unsigned long long i = 0; i < (blockVectorSize - 1); i++) {
                uint64_t temp = 0;
                if (i < blockVectorSize - 2) {
                    turnEightBytesToUint64_t(temp, i, buffer, 8);
                    outputBlockVector[i + 1] = temp;
                    temp = 0;
                } else {
                    turnEightBytesToUint64_t(temp, i, buffer, remainderBytes);
                    outputBlockVector[i + 1] = temp;
                    temp = 0;
                }
            }
            /****************************************************************/
            size_t maxNumOfThreads = std::thread::hardware_concurrency();
            std::mutex mutex;
            size_t numOfThreadsToSpawn = (blockVectorSize>maxNumOfThreads)?(maxNumOfThreads):(blockVectorSize);
            std::vector<std::thread*> threads(numOfThreadsToSpawn);
            unsigned long long blocksForEachThread = blockVectorSize/numOfThreadsToSpawn;
            std::vector<uint64_t> encryptedFileVector(blockVectorSize);

            for (unsigned long long i = 0; i < numOfThreadsToSpawn; ++i){
                if (i == numOfThreadsToSpawn - 1){
                    threads[i] = new std::thread(threadedEncryption, std::ref(outputBlockVector), std::ref(encryptedFileVector), std::ref(key), (i*blocksForEachThread), blockVectorSize, std::ref(pBarVal), std::ref(mutex));

                } else {
                    threads[i] = new std::thread(threadedEncryption, std::ref(outputBlockVector), std::ref(encryptedFileVector), std::ref(key), (i*blocksForEachThread), ((i*blocksForEachThread) + blocksForEachThread), std::ref(pBarVal), std::ref(mutex));
                }
            }

            while (pBarVal < blockVectorSize){
                (blockVectorSize>INT_MAX)?(emit valueChanged((pBarVal*INT_MAX)/blockVectorSize)):(emit valueChanged(pBarVal));
                QCoreApplication::processEvents();
            }

            for (size_t i = 0; i < numOfThreadsToSpawn; ++i){
                if (threads[i]->joinable()){
                    threads[i]->join();
                     delete threads[i];
                }
            }
            /**
             * Turn the encrypted 64 bit blocks array back into bytes for write file operations
             */
            std::vector<char> encryptedFileAsBytes(blockVectorSize*8);
            for (unsigned long long j = 0; j < blockVectorSize; j++){
                for (int i = 0; i < 8; ++i){
                    uint64_t tempInp = 255;
                    short move = static_cast<short>(i*8);
                    uint64_t temp = tempInp << move;
                    uint64_t output64 = 0;
                    output64 = ((encryptedFileVector[j]) & temp) >> (i * 8);
                    char output = static_cast<char>(output64);
                    encryptedFileAsBytes[j * 8 + i] = output;
                }
            }

            //Open a stream to the desired file

            emit updateTextField(QString("Writing to file..."));
            if (os) {
                os.write(&encryptedFileAsBytes[0], blockVectorSize*8);
            }
            emit updateTextField(QString("Success!"));

        } else if(currIter == 0 && readIterations > 1){     // if first iter of many
            std::vector<char> buffer(bufferSize);
            if (is){
                is.read(&buffer[0], bufferSize);
            }
            uint64_t blockVectorSize = (bufferSize/8) + 1;
            outputBlockVector.resize(blockVectorSize);
            outputBlockVector[0] = remainderBytes;
            /******************TURNING TO 64 BIT VECTOR*******************/
            for (unsigned long long i = 0; i < (blockVectorSize - 1); i ++) {
                uint64_t temp = 0;
                turnEightBytesToUint64_t(temp, i, buffer, 8);
                outputBlockVector[i + 1] = temp;
                temp = 0;

            }
            /****************************************************************/

            size_t maxNumOfThreads = std::thread::hardware_concurrency();
            std::mutex mutex;
            size_t numOfThreadsToSpawn = (blockVectorSize>maxNumOfThreads)?(maxNumOfThreads):(blockVectorSize);
            std::vector<std::thread*> threads(numOfThreadsToSpawn);
            unsigned long long blocksForEachThread = blockVectorSize/numOfThreadsToSpawn;
            std::vector<uint64_t> encryptedFileVector(blockVectorSize);

            for (unsigned long long i = 0; i < numOfThreadsToSpawn; ++i){
                if (i == numOfThreadsToSpawn - 1){
                    threads[i] = new std::thread(threadedEncryption, std::ref(outputBlockVector), std::ref(encryptedFileVector), std::ref(key), (i*blocksForEachThread), blockVectorSize, std::ref(pBarVal), std::ref(mutex));

                } else {
                    threads[i] = new std::thread(threadedEncryption, std::ref(outputBlockVector), std::ref(encryptedFileVector), std::ref(key), (i*blocksForEachThread), ((i*blocksForEachThread) + blocksForEachThread), std::ref(pBarVal), std::ref(mutex));
                }
            }
            cumulativeBlockSize = blockVectorSize;
            qDebug()<<"Iteration number: "<<i<<" Cumulative block size = "<<cumulativeBlockSize;
            while (pBarVal < cumulativeBlockSize){
                (blockVectorSize>INT_MAX)?(emit valueChanged((pBarVal*INT_MAX)/cumulativeBlockSize)):(emit valueChanged(pBarVal));
                QCoreApplication::processEvents();
            }

            for (size_t i = 0; i < numOfThreadsToSpawn; ++i){
                if (threads[i]->joinable()){
                    threads[i]->join();
                    delete threads[i];
                }
            }
            /**
             * Turn the encrypted 64 bit blocks array back into bytes for write file operations
             */
            std::vector<char> encryptedFileAsBytes(blockVectorSize*8);
            for (unsigned long long j = 0; j < blockVectorSize; j++){
                for (int i = 0; i < 8; ++i){
                    uint64_t tempInp = 255;
                    short move = static_cast<short>(i*8);
                    uint64_t temp = tempInp << move;
                    uint64_t output64 = 0;
                    output64 = ((encryptedFileVector[j]) & temp) >> (i * 8);

                    char output = static_cast<char>(output64);
                    encryptedFileAsBytes[j * 8 + i] = output;
                }
            }

            //Open a stream to the desired file

            if (os) {
                os.write(&encryptedFileAsBytes[0], blockVectorSize*8);
            }

        } else if((currIter != 0) && (currIter != (readIterations-1))){       //if regular iteration
            std::vector<char> buffer(bufferSize);
            if (is){
                is.read(&buffer[0], bufferSize);
            }
            uint64_t blockVectorSize = bufferSize/8;
            outputBlockVector.resize(blockVectorSize);
            /******************TURNING TO 64 BIT VECTOR*******************/
            for (unsigned long long i = 0; i < blockVectorSize; i ++) {
                uint64_t temp = 0;
                turnEightBytesToUint64_t(temp, i, buffer, 8);
                outputBlockVector[i] = temp;
                temp = 0;
            }
            /****************************************************************/

            size_t maxNumOfThreads = std::thread::hardware_concurrency();
            std::mutex mutex;
            size_t numOfThreadsToSpawn = (blockVectorSize>maxNumOfThreads)?(maxNumOfThreads):(blockVectorSize);
            std::vector<std::thread*> threads(numOfThreadsToSpawn);
            unsigned long long blocksForEachThread = blockVectorSize/numOfThreadsToSpawn;
            std::vector<uint64_t> encryptedFileVector(blockVectorSize);

            for (unsigned long long i = 0; i < numOfThreadsToSpawn; ++i){
                if (i == numOfThreadsToSpawn - 1){
                    threads[i] = new std::thread(threadedEncryption, std::ref(outputBlockVector), std::ref(encryptedFileVector), std::ref(key), (i*blocksForEachThread), blockVectorSize, std::ref(pBarVal), std::ref(mutex));
                } else {
                    threads[i] = new std::thread(threadedEncryption, std::ref(outputBlockVector), std::ref(encryptedFileVector), std::ref(key), (i*blocksForEachThread), ((i*blocksForEachThread) + blocksForEachThread), std::ref(pBarVal), std::ref(mutex));
                }
            }
            cumulativeBlockSize += blockVectorSize;
            qDebug()<<"Iteration number: "<<i<<" Cumulative block size = "<<cumulativeBlockSize;

            while (pBarVal < cumulativeBlockSize){
                (blockVectorSize>INT_MAX)?(emit valueChanged((pBarVal*INT_MAX)/cumulativeBlockSize)):(emit valueChanged(pBarVal));
                QCoreApplication::processEvents();
            }

            for (size_t i = 0; i < numOfThreadsToSpawn; ++i){
                if (threads[i]->joinable()){
                    threads[i]->join();
                    delete threads[i];
                }
            }

             //Turn the encrypted 64 bit blocks array back into bytes for write file operations

            std::vector<char> encryptedFileAsBytes(blockVectorSize*8);
            for (unsigned long long j = 0; j < blockVectorSize; j++){
                for (int i = 0; i < 8; ++i){
                    uint64_t tempInp = 255;
                    short move = static_cast<short>(i*8);
                    uint64_t temp = tempInp << move;
                    uint64_t output64 = 0;
                    output64 = ((encryptedFileVector[j]) & temp) >> (i * 8);

                    char output = static_cast<char>(output64);
                    encryptedFileAsBytes[j * 8 + i] = output;
                }
            }

            //Open a stream to the desired file
            if (os) {
                os.write(&encryptedFileAsBytes[0], blockVectorSize*8);
            }

        } else if((currIter == (readIterations - 1)) && (currIter != 0)){   //if las iter but not the only one
            long long lastIterBytes = fileSize%bufferSize;
            long long lastIterBlocks = (lastIterBytes/8) + 1;
            std::vector<char> buffer(lastIterBytes);

            if (is){
                is.read(&buffer[0], lastIterBytes);
            }
            uint64_t blockVectorSize = lastIterBlocks;
            outputBlockVector.resize(blockVectorSize);

            /******************TURNING TO 64 BIT VECTOR*******************/
            for (unsigned long long i = 0; i < blockVectorSize; i ++) {
                uint64_t temp = 0;

                if (i < blockVectorSize - 1) {
                    turnEightBytesToUint64_t(temp, i, buffer, 8);
                    outputBlockVector[i] = temp;
                    temp = 0;
                } else {
                    turnEightBytesToUint64_t(temp, i, buffer, remainderBytes);
                    outputBlockVector[i] = temp;
                    temp = 0;
                }
            }
            /****************************************************************/

            size_t maxNumOfThreads = std::thread::hardware_concurrency();
            std::mutex mutex;
            size_t numOfThreadsToSpawn = (blockVectorSize>maxNumOfThreads)?(maxNumOfThreads):(blockVectorSize);
            std::vector<std::thread*> threads(numOfThreadsToSpawn);
            unsigned long long blocksForEachThread = blockVectorSize/numOfThreadsToSpawn;
            std::vector<uint64_t> encryptedFileVector(blockVectorSize);

            for (unsigned long long i = 0; i < numOfThreadsToSpawn; ++i){
                if (i == numOfThreadsToSpawn - 1){
                    threads[i] = new std::thread(threadedEncryption, std::ref(outputBlockVector), std::ref(encryptedFileVector), std::ref(key), (i*blocksForEachThread), blockVectorSize, std::ref(pBarVal), std::ref(mutex));

                } else {
                    threads[i] = new std::thread(threadedEncryption, std::ref(outputBlockVector), std::ref(encryptedFileVector), std::ref(key), (i*blocksForEachThread), ((i*blocksForEachThread) + blocksForEachThread), std::ref(pBarVal), std::ref(mutex));
                }
            }

            cumulativeBlockSize += blockVectorSize;
            qDebug()<<"Iteration number: "<<i<<" Cumulative block size = "<<cumulativeBlockSize;

            while (pBarVal < cumulativeBlockSize){
                (blockVectorSize>INT_MAX)?(emit valueChanged((pBarVal*INT_MAX)/cumulativeBlockSize)):(emit valueChanged(pBarVal));
                QCoreApplication::processEvents();
            }

            for (size_t i = 0; i < numOfThreadsToSpawn; ++i){
                if (threads[i]->joinable()){
                    threads[i]->join();
                    delete threads[i];
                }
            }

            //Turn the encrypted 64 bit blocks array back into bytes for write file operations
            std::vector<char> encryptedFileAsBytes(blockVectorSize*8);
            for (unsigned long long j = 0; j < blockVectorSize; j++){
                for (int i = 0; i < 8; ++i){
                    uint64_t tempInp = 255;
                    auto move = static_cast<short>(i*8);
                    uint64_t temp = tempInp << move;
                    uint64_t output64 = 0;
                    output64 = ((encryptedFileVector[j]) & temp) >> (i * 8);

                    char output = static_cast<char>(output64);
                    encryptedFileAsBytes[j * 8 + i] = output;
                }
            }


            //Open a stream to the desired file
            emit updateTextField(QString("Writing to file..."));
            if (os) {
                os.write(&encryptedFileAsBytes[0], blockVectorSize*8);
            }
            emit updateTextField(QString("Success!"));
        }
        currIter++;
    }
    is.close();
    os.close();
}
void DES64Crypto::bufferedFileDecryptionECB (const std::string& path, uint64_t key){
    emit updateTextField(QString("Loading file..."));
    pBarVal = 0;
    unsigned long long cumulativeBlockSize{};
    constexpr long long bufferSize = 32000000; //has to be dividable by 8
    std::ifstream is(path, std::ios::in | std::ios::binary);
    size_t dotIndexInPath = path.find('.');
    std::string writePath = path;
    writePath.insert(dotIndexInPath, "Dec");
    std::ofstream os(writePath, std::ios::out | std::ios::binary);

    //generating 16 round keys for decryption
    sixteenEncryptionKeys = sixteenSubKeysGeneration(this->cryptoKey);
    is.seekg(0, std::ifstream::end);
    long long fileSize = is.tellg();
    if (fileSize%8 != 0){
        throw WrongFileException();
    }
    is.seekg(0, std::ifstream::beg);
    long long maxBlockVectorSize = (fileSize/8);

    //set the pBar size
    int pBarSize = (maxBlockVectorSize>INT_MAX)?(INT_MAX):(maxBlockVectorSize);
    emit sizeOfBar(pBarSize);
    //var holding the read iterations, each with a buffer size, on the input file
    long long readIterations{};
    if (fileSize > bufferSize){
        readIterations = ((fileSize%bufferSize) == 0)?(fileSize/bufferSize):((fileSize/bufferSize) + 1);
    } else {
        readIterations = 1;
    }

    //create a vector with a greatest possible size for any iteration to be resized down when needed
    emit updateTextField(QString("Encrypting..."));
    qDebug()<<"No of read iterations = "<<readIterations;
    long long currIter = 0;
    uint64_t remainderBytes = 0;

    //ktory z kolei bufor opracowujemy
    for(long long i = 0; i < readIterations; ++i){
        std::vector<uint64_t > outputBlockVector(bufferSize/8);

        if (currIter == 0 && readIterations <= 1){        //if first and only iter
            std::vector<char> buffer(fileSize);
            if (is){
                is.read(&buffer[0], fileSize);
            }
            //we do no tcheck if there is a remainder of dividing fileSize by 8, size files encrypted with this soft should always be
            uint64_t blockVectorSize = fileSize/8;
            outputBlockVector.resize(blockVectorSize);

            /******************TURNING TO 64 BIT VECTOR*******************/
            for (unsigned long long i = 0; i < blockVectorSize; i++) {
                uint64_t temp = 0;
                turnEightBytesToUint64_t(temp, i, buffer, 8);
                outputBlockVector[i] = temp;
                temp = 0;
            }
            /****************************************************************/
            size_t maxNumOfThreads = std::thread::hardware_concurrency();
            std::mutex mutex;
            size_t numOfThreadsToSpawn = (blockVectorSize>maxNumOfThreads)?(maxNumOfThreads):(blockVectorSize);
            std::vector<std::thread*> threads(numOfThreadsToSpawn);
            unsigned long long blocksForEachThread = blockVectorSize/numOfThreadsToSpawn;
            std::vector<uint64_t> decryptedFileVector(blockVectorSize);

            for (unsigned long long k = 0; k < numOfThreadsToSpawn; ++k){
                if (k == numOfThreadsToSpawn - 1){
                    threads[k] = new std::thread(threadedDecryption, std::ref(outputBlockVector), std::ref(decryptedFileVector), std::ref(key), (k*blocksForEachThread), blockVectorSize, std::ref(pBarVal), std::ref(mutex));

                } else {
                    threads[k] = new std::thread(threadedDecryption, std::ref(outputBlockVector), std::ref(decryptedFileVector), std::ref(key), (k*blocksForEachThread), ((k*blocksForEachThread) + blocksForEachThread), std::ref(pBarVal), std::ref(mutex));
                }
            }

            while (pBarVal < blockVectorSize){
                (blockVectorSize>INT_MAX)?(emit valueChanged((pBarVal*INT_MAX)/blockVectorSize)):(emit valueChanged(pBarVal));
                QCoreApplication::processEvents();
            }


            for (size_t l = 0; l < numOfThreadsToSpawn; ++l){
                if (threads[l]->joinable()){
                    threads[l]->join();
                    delete threads[l];
                }
            }
            /**
             * Turn the decrypted 64 bit blocks array back into bytes for write file operations
             */
            remainderBytes = decryptedFileVector[0];
            unsigned long long outputFileSize{};
            if (remainderBytes != 0){
                outputFileSize = (blockVectorSize - 2) * 8 + remainderBytes;
            } else {
                outputFileSize = (blockVectorSize - 1) * 8;
            }
            std::vector<char> decryptedFileAsBytesVector(outputFileSize);

            for (unsigned long long j = 1; j < blockVectorSize; j++) {
                if (j != (blockVectorSize - 1)) {
                    for (unsigned int m = 0; m < 8; ++m) {
                        uint64_t tempInp = 255;
                        auto move = static_cast<short>(m * 8);
                        uint64_t temp = tempInp << move;
                        uint64_t output64 = 0;
                        output64 = ((decryptedFileVector[j]) & temp) >> (m * 8);
                        char output = static_cast<char>(output64);
                        decryptedFileAsBytesVector[j * 8 + m - 8] = output;
                    }
                } else if (j == (blockVectorSize - 1) && remainderBytes > 0){
                    for (unsigned int n = 0; n < remainderBytes; ++n) {
                        uint64_t tempInp = 255;
                        auto move = static_cast<short>(n * 8);
                        uint64_t temp = tempInp << move;
                        uint64_t output64 = 0;
                        output64 = ((decryptedFileVector[j]) & temp) >> (n * 8);
                        char output = static_cast<char>(output64);
                        decryptedFileAsBytesVector[j * 8 + n - 8] = output;

                    }
                } else if (j == (blockVectorSize - 1) && remainderBytes == 0){
                    for (unsigned int o = 0; o < 8; ++o) {
                        uint64_t tempInp = 255;
                        auto move = static_cast<short>(o * 8);
                        uint64_t temp = tempInp << move;
                        uint64_t output64 = 0;
                        output64 = ((decryptedFileVector[j]) & temp) >> (o * 8);
                        char output = static_cast<char>(output64);
                        decryptedFileAsBytesVector[j * 8 + o - 8] = output;
                    }
                }
            }
            //Open a stream to the desired file
            emit updateTextField(QString("Writing to file..."));
            if (os) {
                os.write(&decryptedFileAsBytesVector[0], outputFileSize);
            }
            emit updateTextField(QString("Success!"));
        } else if(currIter == 0 && readIterations > 1){     // if first iter of many
            remainderBytes = 0;
            std::vector<char> buffer(bufferSize);
            if (is){
                is.read(&buffer[0], bufferSize);
            }
            uint64_t blockVectorSize = bufferSize/8;
            outputBlockVector.resize(blockVectorSize);

            /******************TURNING TO 64 BIT VECTOR*******************/
            for (unsigned long long i = 0; i < blockVectorSize; i++) {
                uint64_t temp = 0;
                turnEightBytesToUint64_t(temp, i, buffer, 8);
                outputBlockVector[i] = temp;
                temp = 0;
            }
            /****************************************************************/
            //calculating max no of threads to use and no of 64 bit block to be decrypted by each thread
            size_t maxNumOfThreads = std::thread::hardware_concurrency();
            std::mutex mutex;
            size_t numOfThreadsToSpawn = (blockVectorSize>maxNumOfThreads)?(maxNumOfThreads):(blockVectorSize);
            std::vector<std::thread*> threads(numOfThreadsToSpawn);
            unsigned long long blocksForEachThread = blockVectorSize/numOfThreadsToSpawn;
            std::vector<uint64_t> decryptedFileVector(blockVectorSize);

            //spawning threads
            for (unsigned long long i = 0; i < numOfThreadsToSpawn; ++i){
                if (i == numOfThreadsToSpawn - 1){
                    threads[i] = new std::thread(threadedDecryption, std::ref(outputBlockVector), std::ref(decryptedFileVector), std::ref(key), (i*blocksForEachThread), blockVectorSize, std::ref(pBarVal), std::ref(mutex));

                } else {
                    threads[i] = new std::thread(threadedDecryption, std::ref(outputBlockVector), std::ref(decryptedFileVector), std::ref(key), (i*blocksForEachThread), ((i*blocksForEachThread) + blocksForEachThread), std::ref(pBarVal), std::ref(mutex));
                }
            }
            //updating progress bar
            cumulativeBlockSize = blockVectorSize;
            qDebug()<<"Iteration number: "<<i<<" Cumulative block size = "<<cumulativeBlockSize;
            while (pBarVal < cumulativeBlockSize){
                (blockVectorSize>INT_MAX)?(emit valueChanged((pBarVal*INT_MAX)/cumulativeBlockSize)):(emit valueChanged(pBarVal));
                QCoreApplication::processEvents();
            }
            //joining and destroying threads
            for (size_t i = 0; i < numOfThreadsToSpawn; ++i){
                if (threads[i]->joinable()){
                    threads[i]->join();
                    delete threads[i];
                }
            }

             //Turn the decrypted 64 bit blocks array back into bytes for write file operations
            remainderBytes = decryptedFileVector[0];
            auto outputFileSize = (blockVectorSize - 1) * 8;
            std::vector<char> decryptedFileAsBytesVector(outputFileSize);

            for (unsigned long long j = 1; j < blockVectorSize; j++) {
                for (unsigned int i = 0; i < 8; ++i) {
                    uint64_t tempInp = 255;
                    auto move = static_cast<short>(i * 8);
                    uint64_t temp = tempInp << move;
                    uint64_t output64 = 0;
                    output64 = ((decryptedFileVector[j]) & temp) >> (i * 8);
                    char output = static_cast<char>(output64);
                    decryptedFileAsBytesVector[j * 8 + i - 8] = output;
                }
            }

            //Open a stream to the desired file
            if (os) {
                os.write(&decryptedFileAsBytesVector[0], outputFileSize);
            }

        } else if((currIter != 0) && (currIter != (readIterations-1))){       //if regular iteration

            std::vector<char> buffer(bufferSize);
            if (is){
                is.read(&buffer[0], bufferSize);
            }
            uint64_t blockVectorSize = bufferSize/8;
            outputBlockVector.resize(blockVectorSize);

            /******************TURNING TO 64 BIT VECTOR*******************/
            for (unsigned long long i = 0; i < blockVectorSize; i++) {
                uint64_t temp = 0;
                turnEightBytesToUint64_t(temp, i, buffer, 8);
                outputBlockVector[i] = temp;
                temp = 0;
            }
            /****************************************************************/

            //calculating max no of threads to use and no of 64 bit block to be decrypted by each thread
            size_t maxNumOfThreads = std::thread::hardware_concurrency();
            std::mutex mutex;
            size_t numOfThreadsToSpawn = (blockVectorSize>maxNumOfThreads)?(maxNumOfThreads):(blockVectorSize);
            std::vector<std::thread*> threads(numOfThreadsToSpawn);
            unsigned long long blocksForEachThread = blockVectorSize/numOfThreadsToSpawn;
            std::vector<uint64_t> decryptedFileVector(blockVectorSize);

            //spawning threads
            for (unsigned long long i = 0; i < numOfThreadsToSpawn; ++i){
                if (i == numOfThreadsToSpawn - 1){
                    threads[i] = new std::thread(threadedDecryption, std::ref(outputBlockVector), std::ref(decryptedFileVector), std::ref(key), (i*blocksForEachThread), blockVectorSize, std::ref(pBarVal), std::ref(mutex));

                } else {
                    threads[i] = new std::thread(threadedDecryption, std::ref(outputBlockVector), std::ref(decryptedFileVector), std::ref(key), (i*blocksForEachThread), ((i*blocksForEachThread) + blocksForEachThread), std::ref(pBarVal), std::ref(mutex));
                }
            }

            //updating progress bar
            cumulativeBlockSize += blockVectorSize;
            qDebug()<<"Iteration number: "<<i<<" Cumulative block size = "<<cumulativeBlockSize;

            while (pBarVal < cumulativeBlockSize){
                (blockVectorSize>INT_MAX)?(emit valueChanged((pBarVal*INT_MAX)/cumulativeBlockSize)):(emit valueChanged(pBarVal));
                QCoreApplication::processEvents();
            }

            //joining and destroying threads
            for (size_t i = 0; i < numOfThreadsToSpawn; ++i){
                if (threads[i]->joinable()){
                    threads[i]->join();
                    delete threads[i];
                }
            }

            //Turn the decrypted 64 bit blocks array back into bytes for write file operations
            auto outputFileSize = blockVectorSize * 8;
            std::vector<char> decryptedFileAsBytesVector(outputFileSize);

            for (unsigned long long j = 0; j < blockVectorSize; j++) {
                for (unsigned int i = 0; i < 8; ++i) {
                    uint64_t tempInp = 255;
                    auto move = static_cast<short>(i * 8);
                    uint64_t temp = tempInp << move;
                    uint64_t output64 = 0;
                    output64 = ((decryptedFileVector[j]) & temp) >> (i * 8);
                    char output = static_cast<char>(output64);
                    decryptedFileAsBytesVector[j * 8 + i] = output;
                }
            }

            //Open a stream to the desired file
            if (os) {
                os.write(&decryptedFileAsBytesVector[0], outputFileSize);
            }

        } else if((currIter == (readIterations - 1)) && (currIter != 0)){   //if las iter but not the only one
            //get the number of bytes to read fro the file in the last read iteration
            long long lastIterOfLastIterBytes = fileSize%bufferSize;
            //get the no of 64 bit blocks required to create
            long long lastIterBlocks = lastIterOfLastIterBytes/8;
            unsigned long long  outputFileSize = lastIterBlocks * 8;

            if (remainderBytes != 0){
                outputFileSize += remainderBytes;
                lastIterBlocks += 1;
            }
            std::vector<char> buffer(lastIterOfLastIterBytes);
            if (is){
                is.read(&buffer[0], lastIterOfLastIterBytes);
            }
            uint64_t blockVectorSize = lastIterBlocks;
            outputBlockVector.resize(blockVectorSize);

            /******************TURNING TO 64 BIT VECTOR*******************/
            for (unsigned long long i = 0; i < blockVectorSize; i++) {
                uint64_t temp = 0;
                turnEightBytesToUint64_t(temp, i, buffer, 8);
                outputBlockVector[i] = temp;
                temp = 0;
            }

            /****************************************************************/
            size_t maxNumOfThreads = std::thread::hardware_concurrency();
            std::mutex mutex;
            size_t numOfThreadsToSpawn = (blockVectorSize>maxNumOfThreads)?(maxNumOfThreads):(blockVectorSize);
            std::vector<std::thread*> threads(numOfThreadsToSpawn);
            unsigned long long blocksForEachThread = blockVectorSize/numOfThreadsToSpawn;
            std::vector<uint64_t> decryptedFileVector(blockVectorSize);

            for (unsigned long long k = 0; k < numOfThreadsToSpawn; ++k){
                if (k == numOfThreadsToSpawn - 1){
                    threads[k] = new std::thread(threadedDecryption, std::ref(outputBlockVector), std::ref(decryptedFileVector), std::ref(key), (k*blocksForEachThread), blockVectorSize, std::ref(pBarVal), std::ref(mutex));

                } else {
                    threads[k] = new std::thread(threadedDecryption, std::ref(outputBlockVector), std::ref(decryptedFileVector), std::ref(key), (k*blocksForEachThread), ((k*blocksForEachThread) + blocksForEachThread), std::ref(pBarVal), std::ref(mutex));
                }
            }

            cumulativeBlockSize += blockVectorSize;
            qDebug()<<"Iteration number: "<<i<<" Cumulative block size = "<<cumulativeBlockSize;

            while (pBarVal < cumulativeBlockSize){
                (blockVectorSize>INT_MAX)?(emit valueChanged((pBarVal*INT_MAX)/cumulativeBlockSize)):(emit valueChanged(pBarVal));
                QCoreApplication::processEvents();
            }

            for (size_t l = 0; l < numOfThreadsToSpawn; ++l){
                if (threads[l]->joinable()){
                    threads[l]->join();
                    delete threads[l];
                }
            }

            /**
             * Turn the decrypted 64 bit blocks array back into bytes for write file operations
             */

            std::vector<char> decryptedFileAsBytesVector(outputFileSize);
            for (unsigned long long j = 1; j < blockVectorSize; j++) {
                //if its any but last block to be transformed
                if (j != (blockVectorSize - 1)) {
                    for (unsigned int m = 0; m < 8; ++m) {
                        uint64_t tempInp = 255;
                        auto move = static_cast<short>(m * 8);
                        uint64_t temp = tempInp << move;
                        uint64_t output64 = 0;
                        output64 = ((decryptedFileVector[j]) & temp) >> (m * 8);
                        char output = static_cast<char>(output64);
                        decryptedFileAsBytesVector[j * 8 + m - 8] = output;
                    }

                //if its the last block but there are no remainder bytes to write
                } else if ((j == (blockVectorSize - 1)) && remainderBytes == 0){

                    for (unsigned int n = 0; n < 8; ++n) {
                        uint64_t tempInp = 255;
                        auto move = static_cast<short>(n * 8);
                        uint64_t temp = tempInp << move;
                        uint64_t output64 = 0;
                        output64 = ((decryptedFileVector[j]) & temp) >> (n * 8);
                        char output = static_cast<char>(output64);
                        decryptedFileAsBytesVector[j * 8 + n - 8] = output;

                    }

                    //if its the last block and there are remainder bytes to write
                }else if ((j == (blockVectorSize - 1)) && remainderBytes > 0){

                    for (unsigned int n = 0; n < remainderBytes; ++n) {
                        uint64_t tempInp = 255;
                        auto move = static_cast<short>(n * 8);
                        uint64_t temp = tempInp << move;
                        uint64_t output64 = 0;
                        output64 = ((decryptedFileVector[j]) & temp) >> (n * 8);
                        char output = static_cast<char>(output64);
                        decryptedFileAsBytesVector[j * 8 + n - 8] = output;

                    }
                }
            }
            //Open a stream to the desired file
            emit updateTextField(QString("Writing to file..."));
            if (os) {
                os.write(&decryptedFileAsBytesVector[0], outputFileSize);
            }
            emit updateTextField(QString("Success!"));
        }
        currIter++;
    }
    is.close();
    os.close();
}
void DES64Crypto::turnEightBytesToUint64_t(uint64_t & temp, unsigned long long i, std::vector<char> & buffer, int bytesToWriteInBlock){
    for (int j = 0; j < bytesToWriteInBlock; j++) {
        if (buffer[i * 8 + j] < 0) {
            auto sigToUnsig = static_cast<uint8_t >(buffer[i * 8 + j]);
            auto output = static_cast<uint64_t >(sigToUnsig);
            temp = temp | (output << j * 8);
        } else {
            auto curr = static_cast<uint64_t>(buffer[i * 8 + j]);
            temp = temp | (curr << j * 8);
        }
    }
}

#pragma clang diagnostic pop
