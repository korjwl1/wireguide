package app

import (
	"fmt"
	"math/rand/v2"
	"testing"
)

func TestEpochTotalsAreIndependentOfDeliveryOrder(t *testing.T) {
	var packets []counterSample
	var wantRx, wantTx int64
	for i := int64(1); i <= 32; i++ {
		epoch := fmt.Sprintf("helper-%d/engine-%d", i/7, i)
		rx, tx := i*101, i*73
		wantRx += rx
		wantTx += tx
		packets = append(packets,
			counterSample{epoch: epoch},
			counterSample{epoch: epoch, rx: rx / 2, tx: tx / 3},
			counterSample{epoch: epoch, rx: rx, tx: tx},
			counterSample{epoch: epoch, rx: rx, tx: tx},
			counterSample{},
		)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for iteration := 0; iteration < 100; iteration++ {
		rng.Shuffle(len(packets), func(i, j int) { packets[i], packets[j] = packets[j], packets[i] })
		var st lastKnownTunnelStats
		for _, packet := range packets {
			st = st.mergeEpoch(packet.rx, packet.tx, packet.epoch)
		}
		if st.rx != wantRx || st.tx != wantTx {
			t.Fatalf("delivery order %d changed the observed total: got %d/%d, want %d/%d", iteration, st.rx, st.tx, wantRx, wantTx)
		}
	}
}
