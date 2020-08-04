#include <sgx_tseal.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <iostream>
#include <string>

#include "Enclave_u.h"
#include "app/logging.h"

int ocall_print_string(const char *str)
{
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  int ret = printf("%s", str);
  fflush(stdout);
  return ret;
}
