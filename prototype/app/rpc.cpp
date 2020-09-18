#include "rpc.h"

#include "../common/converter.h"
#include "../common/interface_structs.h"
#include "../common/messages.hpp"
#include "Enclave_u.h"
#include "logging.h"
#include "rpc_types.h"

grpc::Status ecall_failure(sgx_status_t st, int ret)
{
  return grpc::Status(grpc::StatusCode::INTERNAL,
                      fmt::format("ecall failure {} {}", st, ret));
}

grpc::Status RpcServer::schedule(::grpc::ServerContext* context,
                                 const ::rpc::SchedulingRequest* request,
                                 ::rpc::SchedulingResponse* response)
{
  try {
    int ret;

    // build state
    SchedulingState current_state;
    rpc_type_to_enclave_type(current_state, request->cur_state());

    SchedulingMessage prev_message;
    if (current_state.round > 0) {
      // prev_message is not set for the first round
      if (request->cur_dc_message().empty()) {
        throw std::invalid_argument("empty dc message");
      }
      prev_message = SchedulingMessage(request->cur_dc_message());
    }

    // log
    SPDLOG_INFO("received state: {}", current_state.to_string());
    SPDLOG_INFO("received dc message: {}", prev_message.to_string());

    // marshal
    SchedulingMessage_C prev_message_C, new_message_C;
    SchedulingState_C curr_state_C;

    prev_message.marshal(&prev_message_C);
    current_state.marshal(&curr_state_C);

    sgx_status_t ecall_status = ecall_scheduling(
        eid, &ret, &prev_message_C, &curr_state_C, &new_message_C);
    if (ecall_status != SGX_SUCCESS || ret != GOOD) {
      return ecall_failure(ecall_status, ret);
    }

    // unmarshal
    SchedulingMessage new_message(&new_message_C);
    SchedulingState new_state(&curr_state_C);

    SPDLOG_INFO("new state: {}", new_state.to_string());
    SPDLOG_INFO("new message: {}", new_message.to_string());

    auto* new_st = new rpc::SchedulingState;
    enclave_type_to_rpc_type(new_st, new_state);

    response->set_allocated_new_state(new_st);
    response->set_sched_msg(new_message.to_string());
    return grpc::Status::OK;

  } catch (const std::exception& e) {
    SPDLOG_CRITICAL("E: {}", e.what());
    return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
  }
}

grpc::Status RpcServer::aggregate(::grpc::ServerContext* context,
                                  const ::rpc::AggregateRequest* request,
                                  ::rpc::AggregateResponse* response)
{
  try {
    AggregatedMessage cur_agg;
    rpc_type_to_enclave_type(cur_agg, request->current_agg());

    DCNetSubmission user_msg;
    rpc_type_to_enclave_type(user_msg, request->submission());

    // marshal
    AggregatedMessage_C cur_agg_bin, new_agg_bin;
    DCNetSubmission_C user_msg_bin;
    cur_agg.marshal(&cur_agg_bin);
    user_msg.marshal(&user_msg_bin);

    int ret;
    sgx_status_t st = ecall_aggregate(
        this->eid, &ret, &user_msg_bin, &cur_agg_bin, &new_agg_bin);
    if (st != SGX_SUCCESS || ret != GOOD) {
      SPDLOG_ERROR("ecall_aggregate failed with {} {}", st, ret);
      return ecall_failure(st, ret);
    }

    AggregatedMessage new_agg(&new_agg_bin);
    auto* new_agg_rpc = new rpc::Aggregation{};

    SPDLOG_INFO("new agg: {}", new_agg.to_string());

    enclave_type_to_rpc_type(new_agg_rpc, new_agg);
    response->set_allocated_new_agg(new_agg_rpc);

    return grpc::Status::OK;
  } catch (const std::exception& e) {
    SPDLOG_CRITICAL("E: {}", e.what());
    return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
  }
}
