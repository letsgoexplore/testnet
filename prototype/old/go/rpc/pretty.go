//go:generate protoc -I../../services --go_out=. --go-grpc_out=. ../../services/enclave.proto

package rpc

import "fmt"

func (state *SchedulingState) ToString() string {
	rsvMap := ""
	for _, b := range state.GetReservationMap() {
		if b {
			rsvMap += "1"
		} else {
			rsvMap += "0"
		}
	}

	footprints := "["
	for _, fp := range state.GetFootprints() {
		footprints += fp
		footprints += ","
	}
	footprints += "]"

	return fmt.Sprintf("round=%d, map=%s, fps=%s, done=%v", state.GetRound(), rsvMap, footprints, state.Final)

}

func (x *SchedulingResponse) ToString() string {
	return fmt.Sprintf("new state=%s, new message=%v", x.GetNewState().ToString(), x.GetSchedMsg())
}