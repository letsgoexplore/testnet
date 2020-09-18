#include "messages.hpp"
#ifdef IN_ENCLAVE
#include "../enclave/log.h"
#else
#include "../app/logging.h"
#endif

DCMessage::DCMessage(const std::string &bin_str)
{
  if (bin_str.size() != DCMessage::FixedLen) {
    throw std::invalid_argument("bin_str len " +
                                std::to_string(bin_str.size()) +
                                "  != " + std::to_string(DCMessage::FixedLen));
  }
  this->_msg = std::bitset<DCMessage::FixedLen>(bin_str);
}

DCMessage DCMessage::operator^(const DCMessage &other)
{
  DCMessage out;
  for (size_t i = 0; i < DCMessage::FixedLen; i++) {
    out._msg[i] = (this->_msg[i] ^ other._msg[i]);
  }

  return out;
}

void DCMessage::operator^=(const DCMessage &other)
{
  for (size_t i = 0; i < DCMessage::FixedLen; i++) {
    this->_msg[i] = (this->_msg[i] ^ other._msg[i]);
  }
}

void DCMessage::marshal(char *out) const
{
  auto str = this->_msg.to_string();
  for (size_t i = 0; i < DCMessage::FixedLen; i++) {
    out[i] = str[i];
  }
}

DCNetSubmission::DCNetSubmission(const DCNetSubmission_C *bin)
    : _round(bin->round), _user_id(bin->user_id), _msg(bin->dc_msg)
{
  sig = Signature(bin->sig);
}

void DCNetSubmission::sign(const SK &) {}

bool DCNetSubmission::verify() const
{
  (void)this->sig;
  return true;
}

void DCNetSubmission::marshal(DCNetSubmission_C *out) const
{
  out->round = this->_round;
  this->_user_id.marshal(out->user_id);
  this->_msg.marshal(out->dc_msg);
  this->sig.marshal(out->sig);
}

std::string DCNetSubmission::to_string() const
{
  return this->_user_id._id + " says " +
         std::to_string(this->_msg._msg.size()) + " bits. " +
         this->_msg._msg.to_string() + " with sig " + this->sig._sig;
}

void AggregatedMessage::sign(const SK &) {}

bool AggregatedMessage::verify() const
{
  (void)this->sig;
  return true;
}

AggregatedMessage::AggregatedMessage(const AggregatedMessage_C *bin)
    : current_aggregated_value(bin->dc_msg)
{
  // split userids with ":"
  // and populate the array
  std::string userids(bin->user_ids);
  if (userids.empty()) {
    return;
  }

  std::string delim = ":";
  std::size_t current, previous = 0;

  current = userids.find(delim);
  while (current != std::string::npos) {
    this->aggregated_ids.emplace_back(
        userids.substr(previous, current - previous));
    previous = current + 1;
    current = userids.find(delim, previous);
  }
  this->aggregated_ids.emplace_back(
      userids.substr(previous, current - previous));

  // deserialize sig
  this->sig = Signature(bin->sig);
}

void AggregatedMessage::aggregate_in(const DCNetSubmission *msg)
{
  if (msg->verify()) {
    this->aggregated_ids.push_back(msg->_user_id);
    this->current_aggregated_value ^= msg->_msg;
  } else {
    throw std::invalid_argument("can''t verify sig");
  }
}

#include <cstring>

void AggregatedMessage::marshal(AggregatedMessage_C *out)
{
  // concat all user ids
  std::string all_user_ids;
  for (size_t i = 0; i < this->aggregated_ids.size(); i++) {
    all_user_ids += this->aggregated_ids[i]._id;
    if (i != this->aggregated_ids.size() - 1) {
      all_user_ids += ":";  // delimiter
    }
  }

  std::strncpy(out->user_ids, all_user_ids.c_str(), sizeof out->user_ids);

  // copy curr agg
  assert(sizeof out->dc_msg >= DCMessage::FixedLen);
  this->current_aggregated_value.marshal(out->dc_msg);

  // copy sig
  this->sig.marshal(out->sig);
}

std::string AggregatedMessage::to_string() const
{
  std::string r = "agg: " + this->current_aggregated_value._msg.to_string();
  r += ", user_ids: ";
  for (const auto &uid : this->aggregated_ids) {
    r += uid._id;
    r += ", ";
  }
  return r;
}