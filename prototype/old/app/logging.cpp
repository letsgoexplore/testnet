#include "logging.h"

char log_buffer[BUFSIZ] = {'\0'};

#define OCALL_LOGGING_ADAPTOR(FUNC)                \
  {                                                \
    do {                                           \
      logger->FUNC("[{}:{}] {}", file, line, msg); \
    } while (false);                               \
  }

/*!
 *
 * @param level: to be consistent with
 *
 * LOG_LVL_CRITICAL,    // 0
 * LOG_LVL_WARNING,     // 1
 * LOG_LVL_NOTICE,      // 2
 * LOG_LVL_DEBUG,       // 3
 *
 * @param file
 * @param line
 * @param msg
 */
void ocall_logging(int level, const char* file, int line, const char* msg)
{
  auto logger = spdlog::get("Enclave");
  switch (level) {
    case 0:
      OCALL_LOGGING_ADAPTOR(error);
      break;
    case 1:
      OCALL_LOGGING_ADAPTOR(warn)
      break;
    case 2:
      OCALL_LOGGING_ADAPTOR(info)
      break;
    case 3:
      OCALL_LOGGING_ADAPTOR(debug)
      break;
    default:
      return;
  }
}
