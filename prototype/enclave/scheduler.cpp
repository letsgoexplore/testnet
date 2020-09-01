#include "scheduler.h"

#include <sgx_trts.h>

#include <vector>

#include "log.h"

//! make a scheduling message to be broadcast to the DC net
//! \param map
//! \param footprints
//! \param msg
void makeScheduleMessage(const SlotBitmap& map,
                         const SlotFootprint& footprints,
                         SchedulingMessage* msg)
{
  for (size_t i = 0; i < map.size(); i++) {
    if (map.test(i)) {
      msg->message[i] = footprints[i];
    }
  }
}

void makeFreshFootprints(SlotFootprint* fps)
{
  size_t msg_len_bytes = (N_SLOTS * FOOTPRINT_SIZE + 7) / 8;  // bits to bytes
  unsigned char random[msg_len_bytes];
  sgx_status_t ret = sgx_read_rand(random, msg_len_bytes);
  if (ret != SGX_SUCCESS) {
    throw std::runtime_error("SGX random failed with " + std::to_string(ret));
  }

  for (size_t i = 0; i < fps->size(); i++) {
    auto& fp = fps->at(i);
    for (size_t j = 0; j < fp.size(); j++) {
      unsigned int bit_index = j + i * 3;
      // take out the bit_index (th) bit of random
      if ((1U << (bit_index % 8)) & (random[bit_index / 8])) {
        fp.set(j, true);
      } else {
        fp.set(j, false);
      }
    }
  }
}

void InitScheduled(SchedulingState* new_state, SchedulingMessage* new_message)
{
  // round # starts with zero
  new_state->round = 0;

  // set all bits to 1 (trying to scheduling all slots)
  new_state->reservation.set();

  // generate random initial footprint
  makeFreshFootprints(&new_state->footprints);

  // generate scheduling message
  makeScheduleMessage(
      new_state->reservation, new_state->footprints, new_message);

  new_state->round++;
}

double get_coin()
{
  uint32_t coin;
  sgx_read_rand((unsigned char*)&coin, sizeof(coin));
  return coin / std::numeric_limits<uint32_t>::max();
}

uint32_t get_rand(size_t max)
{
  uint32_t coin;
  sgx_read_rand((unsigned char*)&coin, sizeof(coin));

  return coin % max;
}

//! one round of footprint scheduling
//! \param prev_msg
//! \param state
//! \param new_message
//! \return {Continue, Abort, Done}. If Done returned, state.reservation is the
//! final results.
Instruction ScheduleOneRound(const SchedulingMessage& prev_msg,
                             SchedulingState* state,
                             SchedulingMessage* new_message)
{
  if (state->round == 0 || state->round > N_SCHEDULE_ROUNDS - 1) {
    throw std::invalid_argument("invalid round # " +
                                std::to_string(state->round));
  }

  // for everything between the first and the last rounds
  if (state->round > 0 && state->round < N_SCHEDULE_ROUNDS - 1) {
    for (size_t i = 0; i < N_SLOTS; i++) {
      if (!state->reservation.test(i)) {
        // do nothing if i did not schedule for slot i
        continue;
      }

      // detect collision
      if (prev_msg.message[i] != state->footprints[i]) {
        if (get_coin() < 0.7) {
          // with .7 probability, backoff
          state->reservation.reset(i);
        } else {
          // with .3 probability, backoff not
          bool coin2 = get_coin() < 0.5;
          if (coin2) {
            // try the same slot again
          } else {
            // pick a random empty slot
            std::vector<size_t> empty_slots;
            for (size_t s = 0; s < state->reservation.size(); s++) {
              if (state->reservation[s]) {
                empty_slots.push_back(s);
              }
            }

            // try to schedule a random empty slot
            if (!empty_slots.empty()) {
              auto a_random_slot = empty_slots.at(get_rand(empty_slots.size()));
              state->reservation.set(a_random_slot, true);
            }
          }
        }
      }
    }

    // get fresh footprints
    makeFreshFootprints(&state->footprints);
    makeScheduleMessage(state->reservation, state->footprints, new_message);

    // advance to the next round
    state->round++;
    return Continue;
  }

  if (state->round == N_SCHEDULE_ROUNDS - 1) {
    for (size_t s = 0; s < N_SLOTS; s++) {
      // give up on conflicts
      if (prev_msg.message[s] != state->footprints[s]) {
        state->reservation.reset(s);
      }
    }

    // get fresh footprints
    makeFreshFootprints(&state->footprints);
    makeScheduleMessage(state->reservation, state->footprints, new_message);
    return Done;
  }

  return Failed;
}

void TestScheduling()
{
  SchedulingState state;
  SchedulingMessage msg;

  try {
    InitScheduled(&state, &msg);
    Instruction st = Continue;
    while (st != Done) {
      LL_DEBUG("sched round %02d: %s", state.round, msg.to_string().c_str());

      SchedulingMessage new_msg;
      st = ScheduleOneRound(msg, &state, &new_msg);
      msg = new_msg;
    }
  } catch (const std::exception& e) {
    LL_CRITICAL("caught: %s", e.what());
  }
}
