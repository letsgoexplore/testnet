import logging
import grpc
import enclave_pb2_grpc as enclave_grpc
import enclave_pb2 as enclave

N_SLOT = 32

channel = grpc.insecure_channel('localhost:12345')
stub = enclave_grpc.enclaveStub(channel)

state = enclave.SchedulingState(round=0,
        reservation_map=[False]*N_SLOT,
        footprints=['000']*N_SLOT)


req = enclave.SchedulingRequest(cur_state=state)
resp = stub.schedule(req)

print (resp)