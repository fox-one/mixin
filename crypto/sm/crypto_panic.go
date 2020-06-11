// +build !sm,!custom_alg

package sm

func Load() {
	panic("must use the tag \"sm,custom_alg\"")
}
