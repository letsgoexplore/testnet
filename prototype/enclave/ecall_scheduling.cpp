#include "log.h"
#include "scheduler.h"

int ecall_scheduling(const void* _prev_msg, void* _state, void* _new_msg)
{
  if (_prev_msg == nullptr || _state == nullptr || _new_msg == nullptr) {
    return SCHEDULE_INVALID_INPUT;
  }

  const auto* prev_msg = (const SchedulingMessage*)_prev_msg;
  auto* state = (SchedulingState*)_state;
  auto* new_msg = (SchedulingMessage*)_new_msg;

  try {
    if (state->round == 0) {
      LL_DEBUG("init");
      InitScheduled(state, new_msg);
      return SCHEDULE_CONTINUE;
    } else {
      LL_DEBUG("round %d", state->round);

      auto next_step = ScheduleOneRound(*prev_msg, state, new_msg);
      if (next_step == Continue) {
        return SCHEDULE_CONTINUE;
      } else if (next_step == Done) {
        return SCHEDULE_DONE;
      } else {
        return SCHEDULE_INVALID_INPUT;
      }
    }
  } catch (const std::exception& e) {
    LL_CRITICAL("except: %s", e.what());
    return SCHEDULE_EXCEPT_CAUGHT;
  }
}