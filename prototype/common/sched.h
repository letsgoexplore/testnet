#ifndef SGX_DC_NETS_SCHEDULE_MESSAGE_H
#define SGX_DC_NETS_SCHEDULE_MESSAGE_H

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <vector>

constexpr size_t N_SLOTS = 32;
constexpr size_t FOOTPRINT_SIZE = 3;
constexpr size_t N_PARTICIPANTS = 10000;
constexpr size_t N_SCHEDULE_ROUNDS = 15;  // should be log(N)

// TODO: create proper classes
using Footprint = std::bitset<FOOTPRINT_SIZE>;
using SlotBitmap = std::bitset<N_SLOTS>;
using SlotFootprint = std::array<Footprint, N_SLOTS>;

template <typename Iter>
SlotFootprint FootprintsFromString(Iter begin, Iter end)
{
  SlotFootprint sp;

  if (std::distance(begin, end) != N_SLOTS) {
    throw std::invalid_argument("std::distance(begin, end) != N_SLOTS");
  }

  for (size_t i = 0; i < N_SLOTS; i++) {
    auto s = *begin;
    if (s.size() != FOOTPRINT_SIZE) {
      throw std::invalid_argument("s.size() != FOOTPRINT_SIZE");
    }
    sp[i] = std::bitset<FOOTPRINT_SIZE>(s);

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

  std::string to_string()
  {
    auto s = "round=" + std::to_string(round) +
             "; rsvmap=" + reservation.to_string() + "; footprints=";

    std::string ss = "[";
    for (const auto& fp : footprints) {
      ss += fp.to_string();
      ss += ",";
    }
    ss += "]";
    return s + ss;
  }
};

enum SchedulingInstruction {
  Continue,
  Done,
  Failed,
};

#endif