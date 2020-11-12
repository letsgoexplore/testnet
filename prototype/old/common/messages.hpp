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
  explicit UserId(std::string id) : _id(std::move(id)) {}
  explicit UserId(const char* bin) : _id(bin) {}
  void marshal(char* out) const { std::strncpy(out, _id.c_str(), _id.size()); }
};

// a wrapper around bit string
struct Message {
  const static size_t FixedLen = DC_NET_MESSAGE_LEN;
  std::bitset<FixedLen> _msg;
  Message() = default;
  explicit Message(const char* buf) : Message(std::string(buf, FixedLen)) {}
  explicit Message(const std::string& bin_str);
  Message operator^(const Message& other);
  void operator^=(const Message& other);
  void marshal(char[]) const;
};

class SignedUserMessage : public Verifiable {
 public:
  uint32_t _round {};
  UserId _user_id;
  Message _msg;

  SignedUserMessage() = default;

  // unmarshal
  explicit SignedUserMessage(const SignedUserMessage_C*);

  void sign(const SK&) override;
  bool verify() const override;

  void marshal(SignedUserMessage_C*) const;
  std::string to_string() const;
};

class AggregatedMessage : public Verifiable
{
 public:
  std::vector<UserId> aggregated_ids;
  Message current_aggregated_value;

  AggregatedMessage() = default;

  // unmarshal
  explicit AggregatedMessage(const AggregatedMessage_C* bin);

  void aggregate_in(const SignedUserMessage*);
  void sign(const SK&) override;
  bool verify() const override;

  void marshal(AggregatedMessage_C* out);
  std::string to_string() const;
};
#endif  // SGX_DC_NETS_MESSAGES_HPP
