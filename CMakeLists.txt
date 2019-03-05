cmake_minimum_required(VERSION 3.13)
project(sshnopass C)

set(CMAKE_C_STANDARD 11)

add_definitions(-D_GNU_SOURCE)
add_executable(sshnopass
        main.c
        trace_context.c trace_context.h
        util.h
        strsyscall.c strsyscall.h
        otp.c otp.h
        base32.c base32.h)
target_link_libraries(sshnopass PUBLIC mbedcrypto)

