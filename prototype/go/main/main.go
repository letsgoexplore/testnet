package main

import (
	"context"
	"fmt"
	"github.com/bl4ck5un/sgx-dc-nets/prototype/go/rpc"
	"google.golang.org/grpc"
)

const N_SLOTS = 32

func handleResponse(resp *rpc.SchedulingResponse) {
	fmt.Println("Got resp:")
	fmt.Println("new state: ", resp.GetNewState().ToString())
	fmt.Println("new message: ", resp.GetMessageToBroadcast())

	if resp.GetFinal() {
		fmt.Println("Done")
	} else {
		fmt.Println("Continue")
	}
}

func main() {
	conn, err := grpc.Dial("localhost:12345", grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := rpc.NewEnclaveClient(conn)

	// build initial request
	reservationMap := [N_SLOTS]bool{false}
	var footprints [N_SLOTS]string
	for i := 0; i < N_SLOTS; i++ {
		footprints[i] = "000"
	}

	state := rpc.SchedulingState{
		Round:          0,
		ReservationMap: reservationMap[:],
		Footprints:     footprints[:],
	}

	req := rpc.SchedulingRequest{
		CurState: &state,
	}

	resp, err := client.Schedule(context.Background(), &req)
	if err != nil {
		panic(err)
	}

	handleResponse(resp)

	done := false
	for !done {
		req = rpc.SchedulingRequest{
			CurState:     resp.GetNewState(),
            // TODO: this message should be the one from DC net.
            // so here we assume DC net returns the same message
			CurDcMessage: resp.GetMessageToBroadcast(),
		}

		resp, err = client.Schedule(context.Background(), &req)
		if err != nil {
			panic(err)
		}

		handleResponse(resp)
		done = resp.GetFinal()
	}
}
