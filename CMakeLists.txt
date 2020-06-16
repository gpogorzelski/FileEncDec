cmake_minimum_required(VERSION 3.5)

project(DES64EncDec LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-pthread")
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-mwindows")
find_package(Qt5 REQUIRED COMPONENTS Core Widgets Gui)
add_executable(DES64EncDec
        src/main.cpp
        src/widget.cpp
        src/widget.h
        src/widget.ui
        src/IntoBits.cpp
        src/IntoBits.h
        src/DES64Crypto.cpp
        src/DES64Crypto.h
        src/AES256cipher.cpp
        src/AES256cipher.h
        )

target_link_libraries(DES64EncDec Qt5::Core Qt5::Widgets Qt5::Gui)

#
