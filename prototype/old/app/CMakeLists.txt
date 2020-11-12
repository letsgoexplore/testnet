set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c
        COMMAND ${SGX_EDGER8R} --untrusted ${CMAKE_SOURCE_DIR}/enclave/Enclave.edl
        --search-path ${CMAKE_SOURCE_DIR}/enclave
        --search-path ${SGX_SDK}/include
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

###############################
#### dependencies
###############################

# Boost
find_package(Boost QUIET REQUIRED COMPONENTS program_options filesystem system)

# gRPC
list(APPEND CMAKE_PREFIX_PATH ${GRPC_PREFIX})

# search for protobuf
find_package(Protobuf CONFIG REQUIRED)
message(STATUS "Using protobuf ${protobuf_VERSION}")

set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_REFLECTION gRPC::grpc++_reflection)
if (CMAKE_CROSSCOMPILING)
    find_program(_PROTOBUF_PROTOC protoc)
else ()
    set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
endif ()

# Find gRPC installation
# Looks for gRPCConfig.cmake file installed by gRPC's cmake installation.
find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")

set(_GRPC_GRPCPP gRPC::grpc++)
if (CMAKE_CROSSCOMPILING)
    find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
else ()
    set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)
endif ()

# Proto file
get_filename_component(enclave_proto "../services/enclave.proto" ABSOLUTE)
get_filename_component(enclave_proto_path "${enclave_proto}" PATH)

# Generated sources
set(enclave_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/enclave.pb.cc")
set(enclave_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/enclave.pb.h")
set(enclave_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/enclave.grpc.pb.cc")
set(enclave_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/enclave.grpc.pb.h")

add_custom_command(
        OUTPUT "${enclave_proto_srcs}" "${enclave_proto_hdrs}" "${enclave_grpc_srcs}" "${enclave_grpc_hdrs}"
        COMMAND ${_PROTOBUF_PROTOC}
        ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${enclave_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${enclave_proto}"
        DEPENDS "${enclave_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

find_package(Threads REQUIRED)


set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")

###############################
#### targets
###############################

add_executable(main
        main.cpp
        Enclave_u.c
        ocalls.cpp
        rpc.cpp
        logging.cpp
        config.cpp
        utils.cpp
        ${enclave_proto_srcs}
        ${enclave_grpc_srcs}
        ${PROTO_SRCS}
        ${GRPC_SRCS} ../common/message.cpp ../common/sched.cpp)

include_directories(
        ${Boost_INCLUDE_DIRS}
        ${SGXSDK_INCLUDE_DIRS}
        third_party/spdlog/include
        ${PROTO_OUTDIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(main
        ${Boost_LIBRARIES}
        ${SGX_URTS_LIBRARY}
        ${SGX_USVC_LIBRARY}
        gRPC::grpc++
        #        protobuf::libprotobuf
        -Wl,-rpath=${GRPC_PREFIX}/lib # hardcode rpath for now.
        -lpthread -ldl)

add_dependencies(main enclave)

###############################
#### Output & Installtation
###############################
install(FILES
        ${CMAKE_SOURCE_DIR}/src/logging.conf
        DESTINATION conf)