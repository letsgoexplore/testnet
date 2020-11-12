#ifndef SGX_DC_NETS_RANDOM_H
#define SGX_DC_NETS_RANDOM_H

#include <openssl/rand.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>

//! \return a random real number in [0, 1)
double get_coin();

////! \return a random integer in [0, max) (ie [0, max-1])
uint32_t get_rand(size_t max);

template <typename I>
I pick_randomly(I begin, I end)
{
  auto d = std::distance(begin, end);
  auto rand_i = get_rand(d);
  return begin + rand_i;
}

template <typename T>
T pick_randomly(const std::vector<T>& v)
{
  return v.at(get_rand(v.size()));
}

std::string random_binstr(size_t len);

#endif  // SGX_DC_NETS_RANDOM_H
