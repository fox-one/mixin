package sm

import (
	"testing"
)

func BenchmarkSignature(b *testing.B) {
	b.ResetTimer()
	var raw = []byte("just a test")
	for i := 0; i < b.N; i++ {
		p := randomKey()
		pub, err := PublicKeyFromKey(p.Public().Key())
		if err != nil {
			b.Fatal(err)
		}
		sig, err := p.Sign(raw)
		if err != nil {
			b.Fatal(err)
		}
		if !pub.Verify(raw, sig) {
			b.Fatal("verify signature failed")
		}
	}
}
