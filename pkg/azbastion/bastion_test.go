package azbastion

import (
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
)

func TestNewFromDnsName(t *testing.T) {
	b, err := NewFromDnsName(nil, "sub", "group", "bastion.example.com")
	if err != nil {
		t.Fatalf("NewFromDnsName() error = %v", err)
	}

	if b.subscription != "sub" || b.group != "group" || b.bastionDns != "bastion.example.com" {
		t.Fatalf("NewFromDnsName() returned unexpected bastion: %#v", b)
	}
}

func TestNewTunnelSessionReturnsErrorWhenIPConnectDisabled(t *testing.T) {
	disabled := false
	b := &Bastion{
		bastionArm: &armnetwork.BastionHost{
			Properties: &armnetwork.BastionHostPropertiesFormat{
				EnableIPConnect: &disabled,
			},
		},
	}

	_, err := b.NewTunnelSession("127.0.0.1", 22, "scope")
	if err == nil || !strings.Contains(err.Error(), "IP Connect is not enabled") {
		t.Fatalf("NewTunnelSession() error = %v, want IP Connect disabled error", err)
	}
}

func TestNewTunnelSessionReturnsErrorWhenTunnelingDisabled(t *testing.T) {
	enabled := true
	disabled := false
	b := &Bastion{
		bastionArm: &armnetwork.BastionHost{
			Properties: &armnetwork.BastionHostPropertiesFormat{
				EnableIPConnect: &enabled,
				EnableTunneling: &disabled,
			},
		},
	}

	_, err := b.NewTunnelSession("127.0.0.1", 22, "scope")
	if err == nil || !strings.Contains(err.Error(), "tunneling is not enabled") {
		t.Fatalf("NewTunnelSession() error = %v, want tunneling disabled error", err)
	}
}
