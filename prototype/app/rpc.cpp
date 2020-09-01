#include "rpc.h"

#include "../common/messages.h"
#include "Enclave_u.h"
#include "logging.h"

SchedulingState set_state(const rpc::SchedulingState& rpc_sched_state)
{
  SchedulingState state;

  state.round = rpc_sched_state.round();

  const auto& rmap = rpc_sched_state.reservation_map();
  const auto& fps = rpc_sched_state.footprints();
  assert(rmap.size() == N_SLOTS);
  assert(fps.size() == N_SLOTS);
  for (size_t i = 0; i < N_SLOTS; i++) {
    state.reservation.set(i, rmap[i]);
  }

  state.footprints = FootprintsFromString(fps.begin(), fps.end());

  return state;
}

grpc::Status RpcServer::schedule(::grpc::ServerContext* context,
                                 const ::rpc::SchedulingRequest* request,
                                 ::rpc::SchedulingResponse* response)
{
  int ret;

  // build state
  SchedulingState state = set_state(request->cur_state());
  SchedulingMessage prev_message;
  if (state.round > 0) {
    // prev_message is not set for the first round
    prev_message.message =
        FootprintsFromString(request->cur_state().footprints().begin(),
                             request->cur_state().footprints().end());
  }

  SchedulingMessage new_message;

  sgx_status_t ecall_status =
      ecall_scheduling(eid, &ret, &prev_message, &state, &new_message);
  if (ecall_status != SGX_SUCCESS) {
    return grpc::Status(grpc::StatusCode::UNKNOWN, "ecall failure");
  }

  if (ret == SCHEDULE_CONTINUE || ret == SCHEDULE_DONE) {
    SPDLOG_DEBUG("ret = {}", ret);
    rpc::SchedulingState new_st;
    new_st.set_round(state.round);

    for (size_t i = 0; i < N_SLOTS; i++) {
      // TODO: check this does not mess up the orders
      new_st.add_reservation_map(state.reservation.test(i));
      new_st.add_footprints(state.footprints[i].to_string());
    }

    // build response
    response->set_allocated_new_state(&new_st);
    response->set_new_dc_message(new_message.to_string());
    response->set_final(ret == SCHEDULE_DONE);
    return grpc::Status::OK;
  }

  SPDLOG_ERROR("sched failed {}", ret);
  return grpc::Status(grpc::StatusCode::UNKNOWN,
                      fmt::format("sched failure {}", ret));
}
