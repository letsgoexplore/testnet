import logging
import grpc
import python.enclave_pb2_grpc as enclave_grpc
import python.enclave_pb2 as enclave

channel = grpc.insecure_channel('localhost:12345')
stub = enclave_grpc.enclaveStub(channel)

req = enclave.SchedulingRequest(round=0)
resp = stub.schedule(req)