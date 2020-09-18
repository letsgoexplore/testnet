#ifndef SGX_DC_NETS_MESSAGES_HPP
#define SGX_DC_NETS_MESSAGES_HPP

#include <array>
#include <bitset>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "error_code.h"
#include "interface_structs.h"
#include "sched.h"
#include "sig.h"

struct UserId {
  std::string _id;
  UserId() = default;
  UserId(std::string id) : _id(id) {}
  UserId(const char* bin) : _id(bin) {}
  void marshal(char* out) const { std::strncpy(out, _id.c_str(), _id.size()); }
};

struct DCMessage {
  const static size_t FixedLen = DC_NET_MESSAGE_LEN;
  std::bitset<FixedLen> _msg;
  DCMessage() = default;
  DCMessage(const char* buf) : DCMessage(std::string(buf, FixedLen)) {}
  DCMessage(const std::string& bin_str);
  DCMessage operator^(const DCMessage& other);
  void operator^=(const DCMessage& other);
  void marshal(char[]) const;
};

struct UserMessage : Verifiable {
  uint32_t _round;
  UserId _user_id;
  DCMessage _msg;

  UserMessage() = default;

  // unmarshal
  UserMessage(const UserMessage_C*);

  void sign(const SK&) override;
  bool verify() const override;

  void marshal(UserMessage_C*) const;
  std::string to_string() const;
};

class AggregatedMessage : public Verifiable
{
 public:
  std::vector<UserId> aggregated_ids;
  DCMessage current_aggregated_value;

  AggregatedMessage() = default;

  // unmarshal
  AggregatedMessage(const AggregatedMessage_C* bin);

  void aggregate_in(const UserMessage*);
  void sign(const SK&) override;
  bool verify() const override;

  void marshal(AggregatedMessage_C* out);
  std::string to_string() const;
};

#endif  // SGX_DC_NETS_MESSAGES_HPP
