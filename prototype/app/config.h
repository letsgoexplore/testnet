#ifndef SRC_APP_CONFIG_H_
#define SRC_APP_CONFIG_H_

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <string>

using std::string;

namespace po = boost::program_options;
namespace fs = boost::filesystem;

namespace app
{
class Config
{
 private:
  po::variables_map vm;
  uint32_t rpc_port;
  string enclave_path;

 public:
  uint32_t get_rpc_port() const { return rpc_port; }

  const string& get_enclave_path() const { return enclave_path; }
  Config(int argc, const char* argv[]);
};

}  // namespace app

#endif  // SRC_APP_CONFIG_H_
