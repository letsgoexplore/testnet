#ifndef SGX_DC_NETS_RPC_TYPES_H
#define SGX_DC_NETS_RPC_TYPES_H

inline void rpc_type_to_enclave_type(AggregatedMessage& new_agg,
                                     const rpc::Aggregation& agg)
{
  new_agg.current_aggregated_value = DCMessage{agg.current_aggregated_value()};
  new_agg.aggregated_ids.clear();

  for (const auto& uid : agg.user_id_in_aggregation()) {
    new_agg.aggregated_ids.emplace_back(uid);
  }

  new_agg.sig = Signature{agg.sig()};
}

inline void enclave_type_to_rpc_type(rpc::Aggregation* agg,
                                     const AggregatedMessage& agg_msg)
{
  agg->set_current_aggregated_value(
      agg_msg.current_aggregated_value._msg.to_string());

  for (const auto& uid : agg_msg.aggregated_ids) {
    agg->add_user_id_in_aggregation(uid._id);
  }

  agg->set_sig(agg_msg.sig._sig);
}

inline void rpc_type_to_enclave_type(UserMessage& new_msg,
                                     const rpc::UserMessage& msg)
{
  new_msg._round = msg.round();
  new_msg._user_id = UserId{msg.user_id()};
  new_msg._msg = DCMessage{msg.user_message()};
  new_msg.sig = Signature{msg.sig()};
}

#endif  // SGX_DC_NETS_RPC_TYPES_H
