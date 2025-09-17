cmake_minimum_required(VERSION 3.31)
project(THREAD_EXE_HIJACK C)

set(CMAKE_C_STANDARD 11)

add_executable(THREAD_EXE_HIJACK ntapi/main.c
        direct/main.c
        indirect/main.c
        winapi/main.c
        ntapi/main.h
        iathook/main.c)
