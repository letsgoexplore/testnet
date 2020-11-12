//
// Created by fanz on 10/28/20.
//

#ifndef SGX_DC_NETS_DCNET_H
#define SGX_DC_NETS_DCNET_H

#include <vector>
#include "messages.hpp"

struct ServerKey {

};

class EnclaveKey {

};

class SendRequest {
  Message msg;
  uint32_t round;
  std::vector<ServerKey> keys;
  std::vector<unsigned char> sealed_enclave_key;

  SchedulingState ticket;
  SignedUserMessage verifyAndSign() noexcept(false);
};


#endif  // SGX_DC_NETS_DCNET_H
