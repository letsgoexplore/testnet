#ifndef SGX_DC_NETS_SCHEDULER_H
#define SGX_DC_NETS_SCHEDULER_H

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>

constexpr size_t N_SLOTS = 32;
constexpr size_t FOOTPRINT_SIZE = 3;
constexpr size_t N_PARTICIPANTS = 10000;
constexpr size_t N_SCHEDULE_ROUNDS = 15;  // log(N)

using Footprint = std::bitset<FOOTPRINT_SIZE>;
using SlotBitmap = std::bitset<N_SLOTS>;
using SlotFootprint = std::array<Footprint, N_SLOTS>;

class SchedulingMessage
{
 public:
  std::array<Footprint, N_SLOTS> message;
  SchedulingMessage()
  {
    // set message to all zeroes
    for (auto& i : message) {
      i.reset();
    }
  }

  std::string to_string() const
  {
    std::string s;
    for (const Footprint& fp : message) {
      s += fp.to_string();
    }

    return s;
  }
};

class SchedulingState
{
 public:
  uint16_t round;
  SlotBitmap reservation;
  SlotFootprint footprints;

  SchedulingState() : round(0 /**/) {}
};

enum Instruction {
  Continue,
  Done,
  Failed,
};

void InitScheduled(SchedulingState* new_state, SchedulingMessage* new_message);

Instruction ScheduleOneRound(const SchedulingMessage& prev_msg,
                             SchedulingState& state,
                             SchedulingMessage* new_message);

#ifdef __cplusplus
extern "C" {
void TestScheduling();
#endif

#ifdef __cplusplus
};
#endif

#endif  // SGX_DC_NETS_SCHEDULER_H
