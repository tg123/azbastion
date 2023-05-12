package main

import (
	"context"
	"fmt"
	"net"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/azbastion/pkg/azbastion"
	"github.com/tg123/azkeyvault"
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

	return ssh.ParsePrivateKey([]byte(*secret.Value))
}

func keyFromKeyVaultKey(credential azcore.TokenCredential, keyvaultUrl string, keyvaultKeyName string) (ssh.Signer, error) {

	certClient, err := azcertificates.NewClient(keyvaultUrl, credential, nil)
	if err != nil {
		return nil, err
	}

	kv, err := azkeyvault.NewSigner(keyClient, certClient, keyvaultKeyName, "")
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
	}

	sshconfig.SetDefaults()
	sshconfig.AddHostKey(signer)

	p, err := ssh.NewSSHPiperConn(conn, sshconfig)
	if err != nil {
		log.Warnf("error creating ssh piper connection: %v", err)
		return err
	}

	defer p.Close()

	go func() {
		done <- p.Wait()
	}()

	return <-done
}
