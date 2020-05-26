package sm

import (
	"testing"
)

func BenchmarkSignature(b *testing.B) {
	b.ResetTimer()
	var raw = []byte("just a test")
	for i := 0; i < b.N; i++ {
		p := randomKey()
		pub, _ := PublicKeyFromKey(p.Public().Key())
		sig, _ := p.Sign(raw)
		pub.Verify(raw, sig)
	}
}
