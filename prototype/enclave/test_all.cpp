#include "test_aggregate.h"
#include "test_random.h"
#include "test_scheduling.h"

void test_all()
{
  try {
    test_aggregator();
    test_marshal_sched_messages();
    test_sched_message();
  } catch (const std::exception& e) {
    LL_CRITICAL("E: %s", e.what());
  }

  //  test_random_binstr();
}