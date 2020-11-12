package user

import (
	"context"
	"github.com/bl4ck5un/sgx-dc-nets/prototype/go/rpc"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestEnclaveScheduler_UntilDone(t *testing.T) {
	enclave, err := NewEnclaveOverRpc("localhost:12345")
	require.NoError(t, err)
	defer enclave.Close()

	scheduler := NewEnclaveScheduler(&enclave)

	// build initial request
	state := rpc.SchedulingState{
		Round: 0,
	}

	req := rpc.SchedulingRequest{
		CurState: &state,
	}

	var resp *rpc.SchedulingResponse
	resp, err = scheduler.OneRound(context.Background(), &req)
	initialMap := resp.NewState.ReservationMap
	require.NoError(t, err)

	for {
		resp, err = scheduler.OneRound(context.Background(), &rpc.SchedulingRequest{
			CurState:     resp.NewState,
			CurDcMessage: resp.SchedMsg, // simulating a DC without others
		})
		require.NoError(t, err)

		if resp.NewState.Final {
			break
		}
	}

	require.Equal(t, resp.NewState.ReservationMap, initialMap)
}

func TestEnclaveScheduler_TwoRounds(t *testing.T) {
	enclave, err := NewEnclaveOverRpc("localhost:12345")
	require.NoError(t, err)
	defer enclave.Close()

	scheduler := NewEnclaveScheduler(&enclave)

	// build initial request
	state := rpc.SchedulingState{
		Round: 0,
	}

	req := rpc.SchedulingRequest{
		CurState: &state,
	}

	resp, err := scheduler.OneRound(context.Background(), &req)
	require.NoError(t, err)

	require.Equal(t, resp.NewState.Round, uint32(1))
	require.Equal(t, resp.SchedMsg, strings.Join(resp.NewState.Footprints, ""))

	oldMap := resp.NewState.ReservationMap

	resp, err = scheduler.OneRound(context.Background(), &rpc.SchedulingRequest{
		CurState:     resp.NewState,
		CurDcMessage: resp.SchedMsg, // simulating a DC without others
	})
	require.NoError(t, err)

	require.Equal(t, resp.NewState.Round, uint32(2))
	require.Equal(t, resp.NewState.ReservationMap, oldMap)
}

func TestEnclaveScheduler_OneRounds(t *testing.T) {
	enclave, err := NewEnclaveOverRpc("localhost:12345")
	require.NoError(t, err)
	defer enclave.Close()

	scheduler := NewEnclaveScheduler(&enclave)

	// build initial request
	round := uint32(0)

	state := rpc.SchedulingState{
		Round: round,
	}

	req := rpc.SchedulingRequest{
		CurState: &state,
	}

	resp, err := scheduler.OneRound(context.Background(), &req)
	require.NoError(t, err)

	t.Log(resp.ToString())
	require.Equal(t, resp.NewState.Round, round+1)
	require.Equal(t, resp.SchedMsg, strings.Join(resp.NewState.Footprints, ""))
}
