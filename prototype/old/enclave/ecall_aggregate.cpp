#include "../common/messages.hpp"
#include "ecalls.h"
#include "log.h"

//! TODO: no-op if user is already in aggregation
//! \param _message
//! \param _cur_agg
//! \param _new_agg
//! \return
int ecall_aggregate(const SignedUserMessage_C* _message,
                    const AggregatedMessage_C* _cur_agg,
                    AggregatedMessage_C* _new_agg)
{
  // unmarshal
  SignedUserMessage user_msg(_message);
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