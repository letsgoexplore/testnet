#include "../common/messages.hpp"
#include "ecalls.h"
#include "log.h"

//! TODO: no-op if user is already in aggregation
//! \param _message
//! \param _cur_agg
//! \param _new_agg
//! \return
int ecall_aggregate(const UserMessage_C* _message,
                    const AggregatedMessage_C* _cur_agg,
                    AggregatedMessage_C* _new_agg)
{
  // unmarshal
  UserMessage user_msg(_message);
  AggregatedMessage cur_agg(_cur_agg);

  LL_DEBUG("old agg: %s", cur_agg.to_string().c_str());

  AggregatedMessage new_agg;

  if (_message == nullptr || _cur_agg == nullptr || _new_agg == nullptr) {
    LL_CRITICAL("null ptr");
    return INVALID_INPUT;
  }

  try {
    if (cur_agg.verify()) {
      new_agg.aggregated_ids = cur_agg.aggregated_ids;
      new_agg.current_aggregated_value = cur_agg.current_aggregated_value;
      new_agg.aggregate_in(&user_msg);

      // new agg
      LL_DEBUG("new agg in enclave: %s", new_agg.to_string().c_str());

      // marshal
      new_agg.marshal(_new_agg);
      return 0;
    } else {
      return INVALID_INPUT;
    }
  } catch (const std::exception& e) {
    LL_CRITICAL("%s", e.what());
    return EXCEPT_CAUGHT;
  }
}

static void test_marshal_aggregated_msg()
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

static void test_marshal_user_message()
{
  UserMessage msg;
  msg._round = 1;
  msg._user_id = "123";
  std::string big_sig(SIG_LEN, 'c');
  msg.sig = Signature(big_sig);

  LL_INFO("%s", msg.to_string().c_str());

  UserMessage_C msg_bin;
  msg.marshal(&msg_bin);

  UserMessage msg2(&msg_bin);

  assert(msg._user_id._id == msg2._user_id._id);
  LL_INFO("GOOD");

  assert(msg._round == msg2._round);
  LL_INFO("GOOD");

  assert(msg._msg._msg == msg2._msg._msg);
  LL_INFO("GOOD");

  assert(msg.sig._sig == msg2.sig._sig);
  LL_INFO("GOOD");
}

void test_aggregator()
{
  try {
    test_marshal_aggregated_msg();
    LL_INFO("testing test_marshal_user_message");
    test_marshal_user_message();
  } catch (const std::exception& e) {
    LL_CRITICAL("E: %s", e.what());
  }
}