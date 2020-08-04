#include "app/config.h"

#include <boost/program_options.hpp>
#include <iostream>

using namespace std;

app::Config::Config(int argc, const char **argv)
{
  try {
    po::options_description desc("Allowed options");
    desc.add_options()("help,h", "print this message");
    desc.add_options()(
        "rpcport", po::value(&rpc_port)->default_value(12345), "RPC port");
    desc.add_options()(
        "enclave",
        po::value(&enclave_path)->default_value("enclave.debug.so"),
        "path to the enclave so file");
    po::store(po::parse_command_line(argc, argv, desc), vm);

    if (vm.count("help")) {
      cerr << desc;
      cerr.flush();
      exit(0);
    }
    po::notify(vm);
  } catch (po::required_option &e) {
    cerr << e.what() << endl;
    exit(-1);
  } catch (exception &e) {
    cerr << e.what() << endl;
    exit(-1);
  } catch (...) {
    cerr << "Unknown error!" << endl;
    exit(-1);
  }
}
