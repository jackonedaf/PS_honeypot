cmake_minimum_required(VERSION 3.10)
project(honeypot C)

# Standard C
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Dodaj katalog z nagłówkami
include_directories(include)

# Wyszukaj wszystkie pliki .c w src/ i dodaj main.c
file(GLOB SRCS "src/*.c" "main.c")

# Utwórz plik wykonywalny z tych źródeł
add_executable(honeypot ${SRCS})
