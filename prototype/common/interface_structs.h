#ifndef SGX_DC_NETS_INTERFACE_STRUCTS_H
#define SGX_DC_NETS_INTERFACE_STRUCTS_H

#define DC_NET_MESSAGE_LEN 1024
#define SIG_LEN 64
#define USER_ID_LEN 1024
#define MAX_USER_N 100

#define N_SLOTS_C 32
#define FOOTPRINT_SIZE_C 3
#define N_PARTICIPANTS_C 10000
#define N_SCHEDULE_ROUNDS_C 15  // should be log(N)

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
#else
#include <stddef.h>
#include <stdint.h>
#endif

#ifdef __cplusplus
namespace constants
{
constexpr size_t N_SLOTS = N_SLOTS_C;
constexpr size_t FOOTPRINT_SIZE = FOOTPRINT_SIZE_C;
constexpr size_t N_PARTICIPANTS = N_PARTICIPANTS_C;
constexpr size_t N_SCHEDULE_ROUNDS = N_SCHEDULE_ROUNDS_C;
constexpr size_t SchedMessageFixedBitLen = FOOTPRINT_SIZE * N_SLOTS;
}  // namespace constants

#endif

typedef struct _FootprintsForAllSlots {
  char bitmsg[N_SLOTS_C * FOOTPRINT_SIZE_C];
} FootprintsForAllSlots_C;

typedef FootprintsForAllSlots_C SchedulingMessage_C;

typedef struct _SchedulingState_C {
  uint16_t round;
  char reservation[N_SLOTS_C];
  FootprintsForAllSlots_C footprints;
  char final;
} SchedulingState_C;

typedef struct _AggregatedMessage_C {
  char user_ids[MAX_USER_N * USER_ID_LEN];
  char dc_msg[DC_NET_MESSAGE_LEN];
  char sig[SIG_LEN];
} AggregatedMessage_C;

typedef struct _UserMessage_C {
  uint32_t round;
  char user_id[USER_ID_LEN];
  char dc_msg[DC_NET_MESSAGE_LEN];
  char sig[SIG_LEN];
} DCNetSubmission_C;

#endif  // SGX_DC_NETS_INTERFACE_STRUCTS_H
