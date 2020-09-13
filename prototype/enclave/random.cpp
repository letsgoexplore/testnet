#include "random.h"

#include <openssl/bn.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>

#include <limits>

double get_coin()
{
  uint32_t coin;
  sgx_read_rand((unsigned char*)&coin, sizeof(coin));
  return coin / std::numeric_limits<uint32_t>::max();
}

uint32_t get_rand(size_t max)
{
  uint32_t coin;
  sgx_read_rand((unsigned char*)&coin, sizeof(coin));

  // FIXME: there is a small non-zero bias because coin may not be divided
  // evenly by max
  return coin % max;
}