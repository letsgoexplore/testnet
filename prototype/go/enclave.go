package user

import (
	"github.com/bl4ck5un/sgx-dc-nets/prototype/go/rpc"
	"google.golang.org/grpc"
	"sync"
)

type EnclaveOverRpc struct {
	mutex sync.Mutex
	conn *grpc.ClientConn
	rpc rpc.EnclaveClient
}

func (e *EnclaveOverRpc) Close() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	return e.conn.Close()
}

func NewEnclaveOverRpc(address string) (EnclaveOverRpc, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return EnclaveOverRpc{}, err
	}

	enclave := rpc.NewEnclaveClient(conn)
	return EnclaveOverRpc{
		conn:          conn,
		rpc: enclave,
	}, nil
}
