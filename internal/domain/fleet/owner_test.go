package fleet

import "testing"

func TestOwnerAddressesRejectAliasesAndLocalTargets(t *testing.T) {
	for _, address := range []string{"10.2.3.4", "192.168.2.3", "fd00::4", "2001:db8::4"} {
		if !OwnerAddress(address) {
			t.Error("canonical Pod address rejected", address)
		}
	}
	for _, address := range []string{"", "owner.example.invalid", "10.02.3.4", "127.0.0.1", "::1", "0.0.0.0", "::", "169.254.169.254", "fe80::1", "fe80::1%eth0", "224.0.0.1", "ff02::1", "::ffff:10.2.3.4", "FD00::4", "fd00:0:0:0:0:0:0:4", "10.2.3.4:9443"} {
		if OwnerAddress(address) {
			t.Error("unsafe or ambiguous address accepted", address)
		}
	}
}
