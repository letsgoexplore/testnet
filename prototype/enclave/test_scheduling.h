#ifndef SGX_DC_NETS_TEST_SCHEDULING_H
#define SGX_DC_NETS_TEST_SCHEDULING_H

#include "random.h"
#include "scheduler.h"

void test_marshal_sched_messages()
{
  LL_INFO("starting %s", __FUNCTION__);
  auto ranbin = random_binstr(constants::SchedMessageFixedBitLen);
  assert(ranbin.size() == constants::SchedMessageFixedBitLen);
  LL_INFO("GOOD");

  FootprintsForAllSlots ffa(ranbin);
  FootprintsForAllSlots_C bin;
  ffa.marshal(&bin);
  LL_INFO("marshal GOOD");

  FootprintsForAllSlots ffa2(&bin);
  LL_INFO("GOOD");

  assert(ffa.to_string() == ffa2.to_string());
  LL_INFO("GOOD");

  SchedulingState st;
  st.round = 100;
  st.final = false;
  st.footprints = ffa;

  SchedulingState_C st_bin;
  st.marshal(&st_bin);
  LL_INFO("marshal GOOD");

  SchedulingState st2(&st_bin);

  assert(st2.to_string() == st.to_string());
  LL_INFO("GOOD");
}

void test_sched_message()
{
  LL_INFO("starting %s", __FUNCTION__);
  auto binstr = random_binstr(constants::SchedMessageFixedBitLen);
  SchedulingMessage from_binstr(binstr);
  assert(from_binstr.to_string() == binstr);
  LL_INFO("GOOD");
}

#endif  // SGX_DC_NETS_TEST_SCHEDULING_H
