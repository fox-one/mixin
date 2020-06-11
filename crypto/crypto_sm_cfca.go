// +build sm,custom_alg,cfca

package crypto

import (
	"fmt"

	"github.com/fox-one/crypto/sm/cfca"
)

func init() {
	if result := cfca.Load("/license/cfca.license"); result != 0 {
		panic(fmt.Errorf("loading cfca failed, result: %d", result))
	}
}
