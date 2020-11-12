#ifndef SGX_DC_NETS_SCHEDULE_MESSAGE_H
#define SGX_DC_NETS_SCHEDULE_MESSAGE_H

#include <algorithm>
#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "interface_structs.h"
#include "sig.h"

// TODO: create proper classes
using Footprint = std::bitset<constants::FOOTPRINT_SIZE>;
// using SlotBitmap = std::bitset<constants::N_SLOTS>;
// using SlotFootprint = std::array<Footprint, constants::N_SLOTS>;

using SlotBitset = std::bitset<constants::N_SLOTS>;

class SlotBitmap : public SlotBitset
{
 public:
  SlotBitmap() { SlotBitset::reset(); }
  explicit SlotBitmap(const char* in)
      : SlotBitmap(std::string(in, constants::N_SLOTS))
  {
  }
  explicit SlotBitmap(std::string binstr) : SlotBitset(binstr)
  {
    if (binstr.size() != this->size()) {
      throw std::invalid_argument("binstr len");
    }
  }

  void marshal(char* out) const
  {
    auto s = this->to_string();
    if (s.size() != this->size()) {
      throw std::runtime_error("s.size");
    }

    std::copy(s.begin(), s.end(), out);
  }
};

class FootprintsForAllSlots
{
 private:
  std::array<Footprint, constants::N_SLOTS> footprints;

 public:
  FootprintsForAllSlots()
  {
    for (Footprint& fp : footprints) {
      fp.reset();
    }
  }
  explicit FootprintsForAllSlots(const FootprintsForAllSlots_C* in)
      : FootprintsForAllSlots(
            std::string(in->bitmsg, constants::SchedMessageFixedBitLen))
  {
  }

  explicit FootprintsForAllSlots(std::string binstr)
  {
    if (binstr.size() != constants::SchedMessageFixedBitLen) {
      throw std::invalid_argument("binstr len " +
                                  std::to_string(binstr.size()));
    }
    for (size_t i = 0; i < constants::N_SLOTS; i++) {
      this->footprints[i] = Footprint(binstr.substr(
          i * constants::FOOTPRINT_SIZE, (i + 1) * constants::FOOTPRINT_SIZE));
    }
  }

  template <typename Iter>
  FootprintsForAllSlots(Iter begin, Iter end)
  {
    if (std::distance(begin, end) != constants::N_SLOTS) {
      throw std::invalid_argument("std::distance(begin, end) != N_SLOTS");
    }

    for (size_t i = 0; i < constants::N_SLOTS; i++) {
      auto s = *begin;
      if (s.size() != constants::FOOTPRINT_SIZE) {
        throw std::invalid_argument("s.size() != FOOTPRINT_SIZE");
      }
      footprints[i] = Footprint(s);

      begin++;
    }
  }

  void set(size_t i, const Footprint& fp)
  {
    if (i < 0 || i > this->footprints.size()) {
      throw std::invalid_argument("i");
    }

    this->footprints[i] = fp;
  }

  Footprint get(size_t i) const
  {
    if (i < 0 || i > this->footprints.size()) {
      throw std::invalid_argument("i");
    }

    return this->footprints[i];
  }

  void marshal(FootprintsForAllSlots_C* out) const
  {
    std::string bin;
    for (size_t i = 0; i < this->footprints.size(); i++) {
      bin += this->footprints.at(i).to_string();
    }

    if (bin.size() != constants::SchedMessageFixedBitLen) {
      throw std::runtime_error("bin size");
    }

    std::copy(bin.begin(), bin.end(), out->bitmsg);
  }

  std::string to_string(const char* delimiter = nullptr) const
  {
    std::string s;
    for (const Footprint& fp : this->footprints) {
      s += fp.to_string();
      if (delimiter) {
        s += std::string(delimiter);
      }
    }

    return s;
  }
};

// they are the same thing
using SchedulingMessage = FootprintsForAllSlots;

class SchedulingState : public Verifiable
{
 public:
  uint16_t round = 0;
  SlotBitmap reservation;
  FootprintsForAllSlots footprints;
  bool final = false;

  SchedulingState() = default;

  // unmarshal
  explicit SchedulingState(const SchedulingState_C* in);

  void marshal(SchedulingState_C* out) const;

  // TODO: implement me
  bool verify() const override { return true; }
  void sign(const SK& sk) override {}

  std::string to_string()
  {
    auto s = "round=" + std::to_string(round) +
             "; rsvmap=" + reservation.to_string() +
             "; footprints=" + footprints.to_string() +
             "; final=" + std::to_string(final);
    return s;
  }
};

#endif