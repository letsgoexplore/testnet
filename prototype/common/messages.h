#include <bitset>
#include <cstddef>
#include <cstdint>
#include <vector>

#ifndef SGX_DC_NETS_MESSAGES_H
#define SGX_DC_NETS_MESSAGES_H

const int SCHEDULE_INVALID_INPUT = -0x0001;
const int SCHEDULE_EXCEPT_CAUGHT = -0x0002;
const int SCHEDULE_FAILED = -0xFFFF;
const int SCHEDULE_CONTINUE = 1;
const int SCHEDULE_DONE = 0;

constexpr size_t N_SLOTS = 32;
constexpr size_t FOOTPRINT_SIZE = 3;
constexpr size_t N_PARTICIPANTS = 10000;
constexpr size_t N_SCHEDULE_ROUNDS = 15;  // should be log(N)

using Footprint = std::bitset<FOOTPRINT_SIZE>;
using SlotBitmap = std::bitset<N_SLOTS>;
using SlotFootprint = std::array<Footprint, N_SLOTS>;

template <typename Iter>
SlotFootprint FootprintsFromString(Iter begin, Iter end)
{
  SlotFootprint sp;

  assert(std::distance(begin, end) == N_SLOTS);

  for (size_t i = 0; i < N_SLOTS; i++) {
    auto s = *begin;
    assert(s.size() == FOOTPRINT_SIZE);
    for (size_t j = 0; j < FOOTPRINT_SIZE; j++) {
      sp[i].set(j, s[j] == '1');
    }

    begin++;
  }

  return sp;
}

class SchedulingMessage
{
 public:
  SlotFootprint message;
  SchedulingMessage()
  {
    // set message to all zeroes
    for (auto& i : message) {
      i.reset();
    }
  }

  SchedulingMessage(const std::vector<std::string>& vec_str)
      : message(FootprintsFromString(vec_str.begin(), vec_str.end()))
  {
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

  SchedulingState() : round(0 /**/)
  {
    reservation.reset();
    for (Footprint& fp : footprints) {
      fp.reset();
    }
  }
};

enum Instruction {
  Continue,
  Done,
  Failed,
};

#endif  // SGX_DC_NETS_MESSAGES_H
