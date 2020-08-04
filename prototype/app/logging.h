#include <log4cxx/logger.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifndef APP_LOG_H
#define APP_LOG_H

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef NDEBUG
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_INFO
#else
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#endif
#include "spdlog/spdlog.h"

namespace global {
    void inline init_logging(spdlog::level::level_enum level)
    {
        spdlog::set_pattern("[%D-%T] [%^%l%$] (%s:%#) %v");
        spdlog::set_level(level);

        SPDLOG_INFO("logger initialized");
    }
}

// ocalls
#ifdef __cplusplus
extern "C" {
#endif
void ocall_logging(int, const char*, int, const char*);
#ifdef __cplusplus
}
#endif

#endif  // APP_LOG_H