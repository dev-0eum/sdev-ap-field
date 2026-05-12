#pragma once
#include <string>
#include "mac.h"

void log_init();
void log_write(const std::string& msg);
bool Mac_compare(const Mac& a, const Mac& b);
