#include "param.h"

void Param::usage() {
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

bool Param::parse(Param* param, int argc, char* argv[]) {
    if (argc < 3 || argc > 4) { // 기존 코드의 argc > 5는 범위를 벗어나므로 4로 조정 제안
        Param::usage();
        return false;
    }

    param->dev_ = argv[1];
    param->ap_mac_ = argv[2];

    if (argc >= 4) {
        param->station_mac_ = argv[3];
    } else {
        param->station_mac_ = "ff:ff:ff:ff:ff:ff";
    }

    return true;
}

void Param::print_param(const Param& param) {
    printf("[Target Info]\n");
    printf("Interface   : %s\n", param.dev_.c_str());
    printf("AP MAC      : %s\n", param.ap_mac_.c_str());
    printf("Station MAC : %s\n", param.station_mac_.c_str());
}
