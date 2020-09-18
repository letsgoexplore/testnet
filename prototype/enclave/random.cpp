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

  // FIXME: a small but non-zero bias when are not divided evenly by max
  return coin % max;
}

#include <string>
std::string random_binstr(size_t len)
{
  std::string r;
  r.resize(len);
  std::string charset("01");
  for (char& b : r) {
    b = charset.at(get_rand(2));
  }
  return r;
}