package main

import (
	"fmt"
	"net"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/azbastion/pkg/azbastion"
	"github.com/urfave/cli/v2"
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
		},
		Action: func(c *cli.Context) error {
			cred, err := azidentity.NewDefaultAzureCredential(nil)

			if err != nil {
				return err
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
					t, err := b.NewTunnelSession(config.targetAddr, uint16(config.targetPort))
					if err != nil {
						log.Errorf("error creating tunnel session: %v", err)
						return
					}

					log.Printf("tunnel session created: %v -> %v", addr, net.JoinHostPort(config.targetAddr, fmt.Sprintf("%d", uint16(config.targetPort))))

					defer t.Close()

					if err := t.Pipe(conn); err != nil {
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
