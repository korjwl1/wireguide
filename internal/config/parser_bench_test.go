package config

import "testing"

func BenchmarkParseTypicalConfig(b *testing.B) {
	const content = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(content); err != nil {
			b.Fatal(err)
		}
	}
}
