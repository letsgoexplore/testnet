package user

import (
	"github.com/bl4ck5un/sgx-dc-nets/prototype/go/rpc"
	"google.golang.org/grpc"
)

func NewRpcClient() rpc.EnclaveClient {
	conn, err := grpc.Dial("localhost:12345", grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	return rpc.NewEnclaveClient(conn)
}