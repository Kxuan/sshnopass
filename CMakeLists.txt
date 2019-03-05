cmake_minimum_required(VERSION 3.13)
project(auto_ssh_auth C)

set(CMAKE_C_STANDARD 11)

add_definitions(-D_GNU_SOURCE)
add_executable(auto_ssh_auth
        main.c
        trace_context.c trace_context.h
        util.h
        strsyscall.c strsyscall.h
        )
