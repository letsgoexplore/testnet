//
// Created by fanz on 9/18/20.
//

#include "sched.h"

#if IN_ENCLAVE
#include "../enclave/log.h"
#endif

SchedulingState::SchedulingState(const SchedulingState_C *in)
{
  if (in == nullptr) {
    throw std::invalid_argument("null");
  }
  this->round = in->round;
  this->reservation = SlotBitmap(in->reservation);
  this->footprints = FootprintsForAllSlots(&in->footprints);

  switch (in->final) {
    case '0':
      this->final = false;
      break;
    case '1':
      this->final = true;
      break;
    default:
      throw std::invalid_argument("in->final got " + std::to_string(in->final));
  }
}

void SchedulingState::marshal(SchedulingState_C *out) const
{
  out->round = round;
  this->reservation.marshal(out->reservation);
  this->footprints.marshal(&out->footprints);
  out->final = final ? '1' : '0';
}