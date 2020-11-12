FIND_PATH(SGXSSL_INCLUDE_DIRS
        sgx_tsgxssl.edl
        HINTS ${SGX_SSL_PATH}/include
        NO_DEFAULT_PATH)

FIND_PATH(SGXSSL_LIBRARY_DIRS libsgx_tsgxssl.a ${SGX_SSL_PATH}/lib64)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SGXSSL
        DEFAULT_MSG
        SGXSSL_INCLUDE_DIRS
        SGXSSL_LIBRARY_DIRS)