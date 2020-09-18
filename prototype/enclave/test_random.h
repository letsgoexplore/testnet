//
// Created by fanz on 9/18/20.
//

#ifndef SGX_DC_NETS_TEST_RANDOM_H
#define SGX_DC_NETS_TEST_RANDOM_H

#include "random.h"

void test_random_binstr()
{
  LL_INFO("starting %s", __FUNCTION__);
  for (int i = 0; i < 10; i++) {
    auto rand_len = get_rand(10) + 100;
    auto r = random_binstr(rand_len);
    assert(r.size() == rand_len);
    LL_INFO("GOOD");
    LL_INFO("looks random?: %s", r.c_str());
  }
}

#endif  // SGX_DC_NETS_TEST_RANDOM_H
