
// SGX headers
#include <sgx_uae_service.h>

// system headers
#include <grpcpp/server_builder.h>

#include <atomic>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <chrono>
#include <csignal>
#include <iostream>
#include <string>
#include <thread>
#include <utility>

// app headers
#include "app/Enclave_u.h"
#include "app/config.h"
#include "app/logging.h"
#include "app/rpc.h"
#include "app/utils.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

using namespace std;

int main(int argc, const char *argv[])
{
  global::init_logging(spdlog::level::debug);

  app::Config config(argc, argv);

  sgx_enclave_id_t eid;
  sgx_status_t ret = initialize_enclave(config.get_enclave_path().c_str(), &eid);
  if (ret != SGX_SUCCESS) {
    SPDLOG_ERROR("Failed to initialize the enclave");
    std::exit(-1);
  } else {
    SPDLOG_INFO("Enclave {} created", eid);
  }

  // starting the backend RPC server
  RpcServer tc_service(eid);
  std::string server_address(fmt::format("0.0.0.0:{}", config.get_rpc_port()));
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&tc_service);

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  SPDLOG_INFO("TC service listening on {}", server_address);

  server->Wait();
  sgx_destroy_enclave(eid);
  SPDLOG_INFO("all enclave closed successfully");
}
