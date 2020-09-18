#ifndef SGX_DC_NETS_RPC_TYPES_H
#define SGX_DC_NETS_RPC_TYPES_H


inline void rpc_type_to_enclave_type(SchedulingState& state,
                                     const rpc::SchedulingState& rpc_sched_state)
{
    state.round = rpc_sched_state.round();

    // we don't use any of the fields for the first round
    if (state.round == 0)
      return;

    const auto& rmap = rpc_sched_state.reservation_map();
    const auto& fps = rpc_sched_state.footprints();

    if (rmap.size() != constants::N_SLOTS || fps.size() != constants::N_SLOTS) {
      throw std::invalid_argument("rmap.size() != N_SLOTS || fps.size() != N_SLOTS");
    }

    for (size_t i = 0; i < constants::N_SLOTS; i++) {
        state.reservation.set(i, rmap[i]);
    }

    state.footprints = FootprintsForAllSlots(fps.begin(), fps.end());
    state.final = rpc_sched_state.final();
}

inline void enclave_type_to_rpc_type(rpc::SchedulingState* out, const SchedulingState& in) {
  out->set_round(in.round);
  out->set_final(in.final);
  out->set_sig(in.sig._sig);

  for (size_t i = 0; i < constants::N_SLOTS; i++) {
    out->add_reservation_map(in.reservation.test(i));
    out->add_footprints(in.footprints.get(i).to_string());
  }
}

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

inline void rpc_type_to_enclave_type(DCNetSubmission& new_msg,
                                     const rpc::DCNetSubmission& msg)
{
  new_msg._round = msg.round();
  new_msg._user_id = UserId{msg.user_id()};
  new_msg._msg = DCMessage{msg.message()};
  new_msg.sig = Signature{msg.sig()};
}

#endif  // SGX_DC_NETS_RPC_TYPES_H
