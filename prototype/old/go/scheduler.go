package user

import (
	"context"
	"github.com/bl4ck5un/sgx-dc-nets/prototype/go/rpc"
)

const NSlots = 32

type Scheduler interface {
	OneRound(ctx context.Context, request *rpc.SchedulingRequest) (*rpc.SchedulingResponse, error)
}

type EnclaveScheduler struct {
	enclave *EnclaveOverRpc
}

func (e EnclaveScheduler) OneRound(ctx context.Context, request *rpc.SchedulingRequest) (*rpc.SchedulingResponse, error) {
	return e.enclave.rpc.Schedule(ctx, request)
}

func NewEnclaveScheduler(enclave *EnclaveOverRpc) Scheduler {
	return EnclaveScheduler{enclave: enclave}
}
