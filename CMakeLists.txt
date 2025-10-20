cmake_minimum_required(VERSION 3.31)
project(THREAD_EXE_HIJACK C)

set(CMAKE_C_STANDARD 11)


add_executable(THREAD_EXE_HIJACK direct/main.c direct/syscall.asm "out/build (2)/x64-Release/CMakeFiles/3.31.6-msvc6/CompilerIdC/CMakeCCompilerId.c" "out/build (2)/x64-Release/CMakeFiles/ShowIncludes/foo.h" "out/build (2)/x64-Release/CMakeFiles/ShowIncludes/main.c")
enable_language(C ASM_MASM)