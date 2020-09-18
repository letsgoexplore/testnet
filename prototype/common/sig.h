#ifndef SGX_DC_NETS_SIG_H
#define SGX_DC_NETS_SIG_H

#include <string>

struct Signature {
  const static size_t FixedLen = 64;
  std::string _sig;

  Signature() {
    _sig.resize(FixedLen, 0);
  }
  explicit Signature(std::string sig): _sig(sig) {}
  explicit Signature(const char* bin): Signature() {
    std::copy(bin, bin + FixedLen, _sig.begin());
  }

  void marshal(char*out) const {
    std::copy(this->_sig.begin(),
              this->_sig.begin() + FixedLen,
              out);
  }
};

class PK {

};

class SK {

};

struct Verifiable {
  Signature sig;
  virtual void sign(const SK&) = 0;
  virtual bool verify() const = 0;
};

#endif  // SGX_DC_NETS_SIG_H
