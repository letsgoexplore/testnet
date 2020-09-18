#include "log.h"
#include "scheduler.h"

int ecall_scheduling(const SchedulingMessage_C* _prev_msg,
                     SchedulingState_C* _state,
                     SchedulingMessage_C* _new_msg)
{
  if (_prev_msg == nullptr || _state == nullptr || _new_msg == nullptr) {
    return INVALID_INPUT;
  }

  SchedulingMessage prev_msg(_prev_msg);
  SchedulingMessage new_msg;

  SchedulingState state(_state);

  try {
    if (state.round == 0) {
      LL_DEBUG("first round");
      InitScheduled(&state, &new_msg);
    } else {
      ScheduleOneRound(prev_msg, &state, &new_msg);
    }

    // marshal back
    state.marshal(_state);
    new_msg.marshal(_new_msg);

    return GOOD;
  } catch (const std::exception& e) {
    LL_CRITICAL("except: %s", e.what());
    return EXCEPT_CAUGHT;
  }
}