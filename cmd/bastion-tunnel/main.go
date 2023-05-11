package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/azbastion/pkg/azbastion"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
	"golang.org/x/crypto/ssh"
)

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

	flags := []cli.Flag{
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "subscription",
			Usage:       "subscription id",
			EnvVars:     []string{"AZURE_SUBSCRIPTION_ID"},
			Destination: &config.subscription,
			// Required:    true,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "group",
			Usage:       "bastion resource group",
			EnvVars:     []string{"AZURE_RESOURCE_GROUP"},
			Destination: &config.group,
			// Required:    true,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "name",
			Usage:       "bastion name",
			EnvVars:     []string{"AZURE_BASTION_NAME"},
			Destination: &config.name,
			// Required:    true,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "target-addr",
			Usage:       "target address",
			EnvVars:     []string{"TARGET_ADDR"},
			Destination: &config.targetAddr,
			// Required:    true,
		}),
		altsrc.NewUintFlag(&cli.UintFlag{
			Name:        "target-port",
			Usage:       "target port",
			EnvVars:     []string{"TARGET_PORT"},
			Destination: &config.targetPort,
			// Required:    true,
		}),

		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "local-addr",
			Usage:       "local address",
			EnvVars:     []string{"LOCAL_ADDR"},
			Destination: &config.localAddr,
			Value:       "127.0.0.1",
		}),
		altsrc.NewUintFlag(&cli.UintFlag{
			Name:        "local-port",
			Usage:       "local port",
			EnvVars:     []string{"LOCAL_PORT"},
			Destination: &config.localPort,
			// Required:    true,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "token",
			Usage:       "azure access token",
			EnvVars:     []string{"AZURE_TOKEN"},
			Destination: &config.token,
			Required:    false,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "ssh-keyvault-url",
			Usage:       "azure keyvault url for ssh private key",
			EnvVars:     []string{"SSH_KEYVAULT_URL"},
			Destination: &config.keyvaultUrl,
			Required:    false,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "ssh-keyvault-keyname",
			Usage:       "azure keyvault key name for ssh private key",
			EnvVars:     []string{"SSH_KEYVAULT_KEY_NAME"},
			Destination: &config.keyvaultKeyName,
			Required:    false,
		}),
		&cli.StringFlag{
			Name:  "config",
			Usage: "config yaml file path",
			Value: fmt.Sprintf("%v.yaml", strings.TrimSuffix(os.Args[0], ".exe")),
		},
	}

	requiredflags := []string{
		"subscription",
		"group",
		"name",
		"target-addr",
		"target-port",
		"local-port",
	}

	app := &cli.App{
		Name:  "bastion-tunnel",
		Usage: "create tcp tunnel via azure bastion",
		Flags: flags,
		Before: altsrc.InitInputSourceWithContext(flags, func(cCtx *cli.Context) (altsrc.InputSourceContext, error) {
			if filePath := cCtx.String("config"); filePath != "" {
				if _, err := os.Stat(filePath); err == nil {
					log.Printf("loading config from %v", filePath)
					return altsrc.NewYamlSourceFromFile(filePath)
				}
			}

			return &altsrc.MapInputSource{}, nil
		}),
		Action: func(c *cli.Context) error {

			// check required flags
			for _, f := range requiredflags {
				if !c.IsSet(f) {
					return fmt.Errorf("missing required flag: %s", f)
				}
			}

			cred, err := createCred(config.token)
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

					if err := pipeConn(conn, t, targetaddr, signer); err != nil {
						log.Warnf("error piping connection: %v", err)
					}

				}(c)
			}
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func pipeConn(conn net.Conn, t *azbastion.TunnelSession, targetaddr string, signer ssh.Signer) error {
	if signer != nil {
		return pipeSshConn(conn, t, targetaddr, signer)
	}

	return t.Pipe(conn)
}
