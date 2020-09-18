#include "scheduler.h"

#include <sgx_trts.h>

#include <vector>

#include "log.h"
#include "random.h"

// Function to generate all binary strings
static void generateAllBinaryStrings(std::vector<Footprint>& out,
                                     size_t current_len,
                                     Footprint& fp)
{
  if (current_len == constants::FOOTPRINT_SIZE) {
    out.push_back(fp);
    return;
  }

  fp.set(current_len);
  generateAllBinaryStrings(out, current_len + 1, fp);

  fp.reset(current_len);
  generateAllBinaryStrings(out, current_len + 1, fp);
}

static std::vector<Footprint> generateAllPossibleFootprints()
{
  std::vector<Footprint> all_possible_fps;
  Footprint fp;
  generateAllBinaryStrings(all_possible_fps, 0, fp);

  // last one is always 000..0
  all_possible_fps.erase(all_possible_fps.end() - 1);
  return all_possible_fps;
}

// all possible footprints
const std::vector<Footprint> ALL_FOOTPRINTS = generateAllPossibleFootprints();

//! write to fps a fresh randomly generated footprints
//! \param fps
static void makeFreshFootprints(FootprintsForAllSlots* fps)
{
  for (size_t i = 0; i < constants::N_SLOTS; i++) {
    fps->set(i, pick_randomly(ALL_FOOTPRINTS));
  }
}

//! make a scheduling message to be broadcast to the DC net.
//! this simply put footprints in the slots to be reserved
//! \param map
//! \param footprints
//! \param msg
static void makeScheduleMessage(const SlotBitmap& map,
                                const FootprintsForAllSlots& footprints,
                                SchedulingMessage* msg)
{
  for (size_t i = 0; i < constants::N_SLOTS; i++) {
    if (map.test(i)) {
      msg->set(i, footprints.get(i));
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

//! one round of footprint scheduling
//! \param prev_msg
//! \param state
//! \param new_message
void ScheduleOneRound(const SchedulingMessage& prev_msg,
                                       SchedulingState* state,
                                       SchedulingMessage* new_message)
{
  // for everything between the first and the last rounds
  if (state->round > 0 && state->round < constants::N_SCHEDULE_ROUNDS - 1) {
    for (size_t i = 0; i < constants::N_SLOTS; i++) {
      if (!state->reservation.test(i)) {
        // do nothing if i did not schedule for slot i
        LL_DEBUG("not reserving slot %zu. skipping...", i);
        continue;
      }

      // detect collision
      if (prev_msg.get(i) != state->footprints.get(i)) {
        if (get_coin() < 0.7) {
          // with .7 probability, backoff
          state->reservation.reset(i);
        } else {
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
    return;
  } else if (state->round == constants::N_SCHEDULE_ROUNDS - 1) {
    // give up on conflicts
    for (size_t s = 0; s < constants::N_SLOTS; s++) {
      if (prev_msg.get(s) != state->footprints.get(s)) {
        state->reservation.reset(s);
      }
    }

    // get fresh footprints
    makeFreshFootprints(&state->footprints);
    makeScheduleMessage(state->reservation, state->footprints, new_message);

    state->round++;  // TODO: this is not used
    state->final = true;
    return;
  } else {
      throw std::invalid_argument("invalid round # " +
                                  std::to_string(state->round));
  }
}

static void simulate_scheduling()
{
  SchedulingState state;
  SchedulingMessage msg;

  try {
    InitScheduled(&state, &msg);
    while (!state.final) {
      LL_DEBUG("sched round %02d: %s", state.round, msg.to_string().c_str());

      SchedulingMessage new_msg;
      ScheduleOneRound(msg, &state, &new_msg);
      msg = new_msg;
    }
  } catch (const std::exception& e) {
    LL_CRITICAL("caught: %s", e.what());
  }
}

static void test_generate_all()
{
  auto fps = generateAllPossibleFootprints();
  assert(fps.size() == (2U << constants::FOOTPRINT_SIZE) - 1);
  for (uint32_t i = 0; i < fps.size(); i++) {
    LL_DEBUG("all possible footprint #%d=%s", i, fps[i].to_string().c_str());
  }
}

void TestScheduling() { test_generate_all(); }
