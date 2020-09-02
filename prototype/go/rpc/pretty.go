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

	return fmt.Sprintf("round=%d, map=%s, fps=%s", state.GetRound(), rsvMap, footprints)

}