//
// Created by fanz on 10/28/20.
//

#include "dcnet.h"

SignedUserMessage SendRequest::verifyAndSign() noexcept(false) {
  // verify the ticket
  if (!this->ticket.verify() || !ticket.final || this->round != ticket.round) {
    throw std::invalid_argument("invalid ticket");
  }



  SignedUserMessage signed_msg;

  return signed_msg;
}
