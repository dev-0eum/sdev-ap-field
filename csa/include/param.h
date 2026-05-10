#pragma once
#include <pch.h>

struct Param {
    std::string dev_ = "";          // 인터페이스
    std::string ap_mac_ = "";       // AP MAC
    std::string station_mac_ = "";  // Station MAC (기본값 브로드캐스트)

    static void usage();
    static bool parse(Param* param, int argc, char* argv[]);
    static void print_param(const Param& param);
};
