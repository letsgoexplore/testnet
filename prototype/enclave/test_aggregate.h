#ifndef SGX_DC_NETS_AGGREGATE_TEST_H
#define SGX_DC_NETS_AGGREGATE_TEST_H

#include "../common/interface_structs.h"
#include "../common/messages.hpp"
#include "log.h"

inline void test_marshal_aggregated_msg()
{
  AggregatedMessage msg;
  msg.aggregated_ids.emplace_back("Alice");
  msg.aggregated_ids.emplace_back("Bob");

  AggregatedMessage_C msg_bin;
  msg.marshal(&msg_bin);

  AggregatedMessage msg2(&msg_bin);

  assert(msg.aggregated_ids.size() == msg2.aggregated_ids.size());
  LL_INFO("GOOD");
  for (size_t i = 0; i < msg.aggregated_ids.size(); i++) {
    assert(msg.aggregated_ids[i]._id == msg2.aggregated_ids[i]._id);
    LL_INFO("GOOD");
  }
  assert(msg.current_aggregated_value._msg ==
         msg2.current_aggregated_value._msg);
  LL_INFO("GOOD");

  assert(msg.sig._sig == msg2.sig._sig);
  LL_INFO("GOOD");
}

inline void test_marshal_user_message()
{
  DCNetSubmission msg;
  msg._round = 1;
  msg._user_id = "123";
  std::string big_sig(SIG_LEN, 'c');
  msg.sig = Signature(big_sig);

  DCNetSubmission_C msg_bin;
  msg.marshal(&msg_bin);

  DCNetSubmission msg2(&msg_bin);

  assert(msg._user_id._id == msg2._user_id._id);
  LL_INFO("GOOD");

  assert(msg._round == msg2._round);
  LL_INFO("GOOD");

  assert(msg._msg._msg == msg2._msg._msg);
  LL_INFO("GOOD");

  assert(msg.sig._sig == msg2.sig._sig);
  LL_INFO("GOOD");
}

inline void test_aggregator()
{
  try {
    test_marshal_aggregated_msg();
    LL_INFO("testing test_marshal_user_message");
    test_marshal_user_message();
  } catch (const std::exception& e) {
    LL_CRITICAL("E: %s", e.what());
  }
}

#endif  // SGX_DC_NETS_AGGREGATE_TEST_H
