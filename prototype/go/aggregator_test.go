package user

import (
	"context"
	"errors"
	"fmt"
	"github.com/bl4ck5un/sgx-dc-nets/prototype/go/rpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func assertBinary(s string) error {
	for _, c := range s {
		if c != '0' && c != '1' {
			return errors.New(fmt.Sprint(s, " is not binary"))
		}
	}
	return nil
}

func xor(a string, b string) (c string, err error) {
	if err = assertBinary(a); err != nil {
		return
	}
	if err = assertBinary(b); err != nil {
		return
	}

	lenStr := len(a)
	if len(b) < lenStr {
		lenStr = len(b)
	}

	for i := 0; i < lenStr; i++ {
		aa := a[i] == '1'
		bb := b[i] == '1'

		// this is XOR in Go
		cc := aa != bb
		if cc {
			c += string('1')
		} else {
			c += string('0')
		}
	}

	return
}

func TestXor(t *testing.T) {
	a := "00000001"
	b := "11111111"

	c, err := xor(a, b)
	require.NoError(t, err)

	require.Equal(t, c, "11111110")
}

func randomBinaryString(len int) string {
	charset := "01"
	r := make([]byte, len)
	for i := range r {
		r[i] = charset[rand.Intn(2)]
	}

	return string(r)
}

func TestRandomBinString(t *testing.T) {
	i := 0
	for i < 20 {
		s := randomBinaryString(100 + i)
		require.NoError(t, assertBinary(s))

		i += 1
	}
}

func TestAggregator(t *testing.T) {
	conn, err := grpc.Dial("localhost:12345", grpc.WithInsecure())
	require.NoError(t, err)
	defer conn.Close()

	enclave := rpc.NewEnclaveClient(conn)

	allZeroString := strings.Repeat("0", DCMessageFixedLen)

	var currAggMessage = allZeroString
	var currUserLists []string

	const MaxRun = 10
	i := 0

	for i < MaxRun {
		userName := "alice"
		userMessage := randomBinaryString(DCMessageFixedLen)

		t.Log(currAggMessage)
		t.Log(userMessage)

		request := rpc.AggregateRequest{
			Submission: &rpc.DCNetSubmission{
				Round:       0,
				UserId:      userName,
				Message: userMessage,
				Sig:         "sig",
			},
			CurrentAgg: &rpc.Aggregation{
				UserIdInAggregation:    currUserLists,
				CurrentAggregatedValue: currAggMessage,
				Sig:                    "sig",
			},
		}

		// compute references
		refUserIds := append(currUserLists, userName)
		refMessage, err := xor(currAggMessage, userMessage)
		require.NoError(t, err)

		resp, err := enclave.Aggregate(context.Background(), &request)
		require.NoError(t, err)

		require.ElementsMatch(t, resp.NewAgg.UserIdInAggregation, refUserIds)
		require.Equal(t, resp.NewAgg.CurrentAggregatedValue, refMessage)

		currUserLists = append(currUserLists, userName)
		currAggMessage = resp.NewAgg.CurrentAggregatedValue

		i += 1
		time.Sleep(1 * time.Second)
	}

}
