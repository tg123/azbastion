package azbastion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"nhooyr.io/websocket"
)

type Bastion struct {
	cred         azcore.TokenCredential
	bastionDns   string
	subscription string
	group        string
	bastionArm   *armnetwork.BastionHost
}

func NewFromDnsName(cred azcore.TokenCredential, subscriptionID string, resourceGroupName string, bastionHostDnsName string) (*Bastion, error) {
	return &Bastion{
		cred:         cred,
		bastionDns:   bastionHostDnsName,
		subscription: subscriptionID,
		group:        resourceGroupName,
	}, nil
}

func NewFromArm(cred azcore.TokenCredential, subscriptionID string, resourceGroupName string, bastionHostName string, azureClientOptions *azcore.ClientOptions) (*Bastion, error) {
	clientFactory, err := armnetwork.NewClientFactory(subscriptionID, cred, &arm.ClientOptions{ClientOptions: *azureClientOptions})
	if err != nil {
		return nil, err
	}

	res, err := clientFactory.NewBastionHostsClient().Get(context.Background(), resourceGroupName, bastionHostName, nil)
	if err != nil {
		return nil, err
	}

	return &Bastion{
		cred:         cred,
		bastionDns:   *res.Properties.DNSName,
		subscription: subscriptionID,
		group:        resourceGroupName,
		bastionArm:   &res.BastionHost,
	}, nil
}

type TunnelSession struct {
	bastion *Bastion
	ws      *websocket.Conn
	session *sessionToken
}

func (t *TunnelSession) Close() error {
	_ = t.ws.Close(websocket.StatusNormalClosure, "")

	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://%v/api/tokens/%v", t.bastion.bastionDns, t.session.AuthToken), nil)
	if err != nil {
		return err
	}

	req.Header.Add("X-Node-Id", t.session.NodeID)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == 404 {
		return nil
	}

	if resp.StatusCode != 204 {
		return fmt.Errorf("unexpected status code: %v", resp.StatusCode)
	}

	return nil
}

func (b *Bastion) NewTunnelSession(targetHost string, port uint16, scope string) (*TunnelSession, error) {

	if b.bastionArm != nil {
		if b.bastionArm.Properties != nil {
			if b.bastionArm.Properties.EnableIPConnect != nil {
				if !*b.bastionArm.Properties.EnableIPConnect {
					return nil, fmt.Errorf("IP Connect is not enabled on the bastion host")
				}
			}

			if b.bastionArm.Properties.EnableTunneling != nil {
				if !*b.bastionArm.Properties.EnableTunneling {
					return nil, fmt.Errorf("tunneling is not enabled on the bastion host")
				}
			}
		}
	}

	s, err := b.newSessionToken(targetHost, port, scope)
	if err != nil {
		return nil, err
	}

	wsUrl := fmt.Sprintf("wss://%v/webtunnelv2/%v?X-Node-Id=%v", b.bastionDns, s.WebsocketToken, s.NodeID)
	ws, _, err := websocket.Dial(context.Background(), wsUrl, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}

	return &TunnelSession{
		bastion: b,
		ws:      ws,
		session: s,
	}, nil
}

type sessionToken struct {
	AuthToken            string   `json:"authToken"`
	Username             string   `json:"username"`
	DataSource           string   `json:"dataSource"`
	NodeID               string   `json:"nodeId"`
	AvailableDataSources []string `json:"availableDataSources"`
	WebsocketToken       string   `json:"websocketToken"`
}

func (b *Bastion) newSessionToken(targetHost string, port uint16, scope string) (*sessionToken, error) {

	token, err := b.cred.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{scope},
	})

	if err != nil {
		return nil, err
	}

	apiUrl := fmt.Sprintf("https://%v/api/tokens", b.bastionDns)

	// target_resource_id = f"/subscriptions/{get_subscription_id(cmd.cli_ctx)}/resourceGroups/{resource_group_name}/providers/Microsoft.Network/bh-hostConnect/{target_ip_address}"
	data := url.Values{}
	data.Set("resourceId", fmt.Sprintf("/subscriptions/%v/resourceGroups/%v/providers/Microsoft.Network/bh-hostConnect/%v", b.subscription, b.group, targetHost))
	data.Set("protocol", "tcptunnel")
	data.Set("workloadHostPort", fmt.Sprintf("%v", port))
	data.Set("aztoken", token.Token)
	data.Set("hostname", targetHost)

	req, err := http.NewRequest("POST", apiUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req) // TODO client settings
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error creating tunnel: %v", resp.Status)
	}

	var response sessionToken

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return &response, nil
}

func (t *TunnelSession) Pipe(conn net.Conn) error {

	defer t.Close()
	defer conn.Close()

	done := make(chan error, 2)

	go func() {
		for {
			_, data, err := t.ws.Read(context.Background())
			if err != nil {
				done <- err
				return
			}

			if _, err := io.Copy(conn, bytes.NewReader(data)); err != nil {
				done <- err
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 4096) // 4096 is copy from az cli bastion code

		for {

			n, err := conn.Read(buf)
			if err != nil {
				done <- err
				return
			}

			if err := t.ws.Write(context.Background(), websocket.MessageBinary, buf[:n]); err != nil {
				done <- err
				return
			}
		}
	}()

	return <-done
}
