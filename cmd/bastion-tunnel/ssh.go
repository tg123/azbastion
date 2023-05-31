package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/azbastion/pkg/azbastion"
	"github.com/tg123/azkeyvault/v2"
	"golang.org/x/crypto/ssh"
)

func keyFromKeyVault(credential azcore.TokenCredential, keyvaultUrl string, keyvaultKeyName string, keytype string) (ssh.Signer, error) {

	switch keytype {
	case "secret":
		return keyFromKeyVaultSecret(credential, keyvaultUrl, keyvaultKeyName)
	case "key":
		return keyFromKeyVaultKey(credential, keyvaultUrl, keyvaultKeyName)
	default:
		return nil, fmt.Errorf("unknown key type: %s", keytype)
	}
}

func keyFromKeyVaultSecret(credential azcore.TokenCredential, keyvaultUrl string, keyvaultKeyName string) (ssh.Signer, error) {
	client, err := azsecrets.NewClient(keyvaultUrl, credential, nil)

	if err != nil {
		return nil, err
	}

	secret, err := client.GetSecret(context.Background(), keyvaultKeyName, "", nil)
	if err != nil {
		return nil, err
	}

	if secret.Value == nil {
		return nil, fmt.Errorf("secret value is nil")
	}

	v := *secret.Value
	block, _ := pem.Decode([]byte(v))

	if block != nil {
		return ssh.ParsePrivateKey([]byte(v))
	}

	if strings.Contains(v, "-----") {
		v = strings.ReplaceAll(v, " ", "")
		v = regexp.MustCompile(`-----(.*?)KEY-----`).ReplaceAllString(v, "")
	}

	k, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}

	// guess key type
	for _, f := range []func([]byte) (any, error){
		func(b []byte) (any, error) { return x509.ParsePKCS1PrivateKey(b) },
		func(b []byte) (any, error) { return x509.ParseECPrivateKey(b) },
		func(b []byte) (any, error) { return x509.ParsePKCS8PrivateKey(b) },
		func(b []byte) (any, error) { return ssh.ParseDSAPrivateKey(b) },
	} {
		if key, err := f(k); err == nil {
			return ssh.NewSignerFromKey(key)
		}
	}

	return nil, fmt.Errorf("unable to detect key type")
}

func keyFromKeyVaultKey(credential azcore.TokenCredential, keyvaultUrl string, keyvaultKeyName string) (ssh.Signer, error) {
	keyClient, err := azkeys.NewClient(keyvaultUrl, credential, nil)
	if err != nil {
		return nil, err
	}

	kv, err := azkeyvault.NewSigner(keyClient, keyvaultKeyName, "")
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromSigner(kv)
}

func pipeSshConn(conn net.Conn, t *azbastion.TunnelSession, targetaddr string, signer ssh.Signer) error {

	done := make(chan error, 2)

	connToSsh, connToSshReverse := net.Pipe()
	go func() {
		done <- t.Pipe(connToSsh)
	}()

	sshconfig := &ssh.PiperConfig{
		NextAuthMethods: func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) ([]string, error) {
			return []string{"none"}, nil
		},

		NoClientAuthCallback: func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
			return &ssh.Upstream{
				Conn:    connToSshReverse,
				Address: targetaddr,
				ClientConfig: ssh.ClientConfig{
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Auth: []ssh.AuthMethod{
						ssh.PublicKeys(signer),
					},
				},
			}, nil
		},

		UpstreamAuthFailureCallback: func(_ ssh.ConnMetadata, _ string, err error, _ ssh.ChallengeContext) {
			_ = conn.Close()
			log.Errorf("upstream auth failure: %v", err)
		},
	}

	sshconfig.SetDefaults()
	sshconfig.AddHostKey(signer)

	p, err := ssh.NewSSHPiperConn(conn, sshconfig)
	if err != nil {
		return err
	}

	defer p.Close()

	go func() {
		done <- p.Wait()
	}()

	return <-done
}
