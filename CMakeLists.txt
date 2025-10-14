cmake_minimum_required(VERSION 3.31)
project(THREAD_EXE_HIJACK C)

set(CMAKE_C_STANDARD 11)


add_executable(THREAD_EXE_HIJACK direct/main.c direct/syscall.asm)
enable_language(C ASM_MASM)