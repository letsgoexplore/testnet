#ifndef SGX_DC_NETS_INTERFACE_STRUCTS_H
#define SGX_DC_NETS_INTERFACE_STRUCTS_H

#define DC_NET_MESSAGE_LEN 1024
#define SIG_LEN 64
#define USER_ID_LEN 1024
#define MAX_USER_N 100

typedef struct _AggregatedMessage_C {
  char user_ids[MAX_USER_N * USER_ID_LEN];
  char dc_msg[DC_NET_MESSAGE_LEN];
  char sig[SIG_LEN];
} AggregatedMessage_C;


typedef struct _UserMessage_C  {
  uint32_t round;
  char user_id[USER_ID_LEN];
  char dc_msg[DC_NET_MESSAGE_LEN];
  char sig[SIG_LEN];
} UserMessage_C;

#endif  // SGX_DC_NETS_INTERFACE_STRUCTS_H
