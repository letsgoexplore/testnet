#ifndef SGX_DC_NETS_SCHEDULER_H
#define SGX_DC_NETS_SCHEDULER_H

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>

#include "../common/messages.hpp"

#ifdef __cplusplus
extern "C" {
#endif

void TestScheduling();

#ifdef __cplusplus
};
#endif

void InitScheduled(SchedulingState* new_state, SchedulingMessage* new_message);

void ScheduleOneRound(const SchedulingMessage& prev_msg,
                      SchedulingState* state,
                      SchedulingMessage* new_message);

#endif  // SGX_DC_NETS_SCHEDULER_H
