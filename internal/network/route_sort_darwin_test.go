package network

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSortAllowedIPsPreservesEqualPrefixOrder(t *testing.T) {
	input := []string{"0.0.0.0/0", "192.0.2.0/24", "2001:db8::1", "198.51.100.0/24", "192.0.2.1"}
	before := append([]string(nil), input...)
	want := []string{"2001:db8::1", "192.0.2.1", "192.0.2.0/24", "198.51.100.0/24", "0.0.0.0/0"}
	if got := sortAllowedIPs(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("sort: %v, want %v", got, want)
	}
	if !reflect.DeepEqual(input, before) {
		t.Fatal("sort mutated the caller's route policy")
	}
}

func BenchmarkSortAllowedIPs(b *testing.B) {
	for _, n := range []int{8, 512} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			input := make([]string, n)
			for i := range input {
				input[i] = fmt.Sprintf("10.%d.%d.0/%d", i/256, i%256, (i*17)%33)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sortAllowedIPs(input)
			}
		})
	}
}
