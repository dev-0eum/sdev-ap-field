#include "pch.h"
#include "utils.h"
#include "mac.h"
#include <ctime>
#include <fstream>
#include <sys/stat.h>

static std::ofstream g_log;

void log_init() {
    mkdir("logs", 0755);

    time_t now = time(nullptr);
    struct tm* t = localtime(&now);
    char fname[64];
    strftime(fname, sizeof(fname), "logs/csa_%Y%m%d_%H%M%S.log", t);
    g_log.open(fname, std::ios::out | std::ios::app);

    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
    g_log << "=== CSA Attack Log (" << ts << ") ===" << std::endl;
}

bool Mac_compare(const Mac& a, const Mac& b) {
    return memcmp(a.get_addr(), b.get_addr(), 6) == 0;
}

void log_write(const std::string& msg) {
    time_t now = time(nullptr);
    struct tm* t = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", t);
    std::string line = "[" + std::string(ts) + "] " + msg;
    printf("%s\n", line.c_str());
    if (g_log.is_open()) g_log << line << std::endl;
}
