package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/azbastion/pkg/azbastion"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

var _ azcore.TokenCredential = &staticTokenCredential{}

type staticTokenCredential struct {
	token string
}

func (s *staticTokenCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     s.token,
		ExpiresOn: time.Now().Add(time.Hour),
	}, nil
}

func main() {
	var config struct {
		subscription string
		group        string
		name         string

		targetAddr string
		targetPort uint

		localAddr string
		localPort uint

		token string

		keyvaultUrl     string
		keyvaultKeyName string
	}

	app := &cli.App{
		Name:  "bastion-tunnel",
		Usage: "create tcp tunnel via azure bastion",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "subscription",
				Usage:       "subscription id",
				EnvVars:     []string{"AZURE_SUBSCRIPTION_ID"},
				Destination: &config.subscription,
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "group",
				Usage:       "bastion resource group",
				EnvVars:     []string{"AZURE_RESOURCE_GROUP"},
				Destination: &config.group,
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "name",
				Usage:       "bastion name",
				EnvVars:     []string{"AZURE_BASTION_NAME"},
				Destination: &config.name,
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "target-addr",
				Usage:       "target address",
				EnvVars:     []string{"TARGET_ADDR"},
				Destination: &config.targetAddr,
				Required:    true,
			},
			&cli.UintFlag{
				Name:        "target-port",
				Usage:       "target port",
				EnvVars:     []string{"TARGET_PORT"},
				Destination: &config.targetPort,
				Required:    true,
			},

			&cli.StringFlag{
				Name:        "local-addr",
				Usage:       "local address",
				EnvVars:     []string{"LOCAL_ADDR"},
				Destination: &config.localAddr,
				Value:       "127.0.0.1",
			},
			&cli.UintFlag{
				Name:        "local-port",
				Usage:       "local port",
				EnvVars:     []string{"LOCAL_PORT"},
				Destination: &config.localPort,
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "token",
				Usage:       "azure access token",
				EnvVars:     []string{"AZURE_TOKEN"},
				Destination: &config.token,
				Required:    false,
			},
			&cli.StringFlag{
				Name:        "ssh-keyvault-url",
				Usage:       "azure keyvault url for ssh private key",
				EnvVars:     []string{"SSH_KEYVAULT_URL"},
				Destination: &config.keyvaultUrl,
				Required:    false,
			},
			&cli.StringFlag{
				Name:        "ssh-keyvault-keyname",
				Usage:       "azure keyvault key name for ssh private key",
				EnvVars:     []string{"SSH_KEYVAULT_KEY_NAME"},
				Destination: &config.keyvaultKeyName,
				Required:    false,
			},
		},
		Action: func(c *cli.Context) error {

			var creds []azcore.TokenCredential

			{
				if config.token != "" {
					creds = append(creds, &staticTokenCredential{config.token})
				}
			}

			{
				cred, err := azidentity.NewAzureCLICredential(nil)
				if err == nil {
					creds = append(creds, cred)
				}
			}

			{

				cred, err := azidentity.NewInteractiveBrowserCredential(nil)
				if err == nil {
					creds = append(creds, cred)
				}
			}

			{
				cred, err := azidentity.NewDeviceCodeCredential(nil)
				if err == nil {
					creds = append(creds, cred)
				}
			}

			if len(creds) == 0 {
				return fmt.Errorf("no credential found")
			}

			cred, err := azidentity.NewChainedTokenCredential(creds, nil)
			if err != nil {
				return err
			}

			var signer ssh.Signer
			if config.keyvaultUrl != "" && config.keyvaultKeyName != "" {
				signer, err = keyFromKeyVault(cred, config.keyvaultUrl, config.keyvaultKeyName)
				if err != nil {
					return err
				}
			}

			if signer != nil {
				fmt.Printf("using ssh public key: %s\n", strings.Trim(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "\n"))
			}

			log.Printf("querying bastion %s/%s/%s", config.subscription, config.group, config.name)
			b, err := azbastion.NewFromArm(cred, config.subscription, config.group, config.name)
			if err != nil {
				return err
			}

			addr := net.JoinHostPort(config.localAddr, fmt.Sprintf("%d", config.localPort))
			log.Printf("listening at %v", addr)
			l, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}

			for {
				c, err := l.Accept()
				if err != nil {
					log.Warnf("error accepting connection: %v", err)
					continue
				}

				log.Printf("accepted connection: %v", c.RemoteAddr())

				go func(conn net.Conn) {
					defer conn.Close()
					t, err := b.NewTunnelSession(config.targetAddr, uint16(config.targetPort))
					if err != nil {
						log.Errorf("error creating tunnel session: %v", err)
						return
					}

					targetaddr := net.JoinHostPort(config.targetAddr, fmt.Sprintf("%d", uint16(config.targetPort)))
					log.Printf("tunnel session created: %v -> %v", addr, targetaddr)

					defer t.Close()

					if signer != nil {

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

						p, err := ssh.NewSSHPiperConn(c, sshconfig)
						if err != nil {
							log.Warnf("error creating ssh piper connection: %v", err)
							return
						}

						defer p.Close()

						go func() {
							done <- p.Wait()
						}()

						if err := <-done; err != nil {
							log.Warnf("error piping connection: %v", err)
						}

					} else {

						if err := t.Pipe(conn); err != nil {
							log.Warnf("error piping connection: %v", err)
						}
					}
				}(c)
			}
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
