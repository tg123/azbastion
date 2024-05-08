package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/azbastion/pkg/azbastion"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
	"golang.org/x/crypto/ssh"
)

var mainver string = "(devel)"

func version() string {

	var v = mainver

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}

	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			v = fmt.Sprintf("%v, %v", v, s.Value[:9])
		case "vcs.time":
			v = fmt.Sprintf("%v, %v", v, s.Value)
		}
	}

	v = fmt.Sprintf("%v, %v", v, bi.GoVersion)

	return v
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
		keyvaultKeyType string

		runssh       bool
		sshcmdline   string
		sshuser      string
		sshkeypath   string
		sshextraargs string
	}

	flags := []cli.Flag{
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "subscription",
			Usage:       "subscription id",
			EnvVars:     []string{"AZURE_SUBSCRIPTION_ID"},
			Destination: &config.subscription,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "group",
			Usage:       "bastion resource group",
			EnvVars:     []string{"AZURE_RESOURCE_GROUP"},
			Destination: &config.group,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "name",
			Usage:       "bastion name",
			EnvVars:     []string{"AZURE_BASTION_NAME"},
			Destination: &config.name,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "target-addr",
			Usage:       "target address",
			EnvVars:     []string{"TARGET_ADDR"},
			Destination: &config.targetAddr,
		}),
		altsrc.NewUintFlag(&cli.UintFlag{
			Name:        "target-port",
			Usage:       "target port",
			EnvVars:     []string{"TARGET_PORT"},
			Destination: &config.targetPort,
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
			Usage:       "local port, use random port if not specified",
			EnvVars:     []string{"LOCAL_PORT"},
			Destination: &config.localPort,
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
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "ssh-keyvault-keytype",
			Usage:       "azure keyvault key type for ssh private key, allow values: key, secret default: key",
			EnvVars:     []string{"SSH_KEYVAULT_KEY_TYPE"},
			Destination: &config.keyvaultKeyType,
			Required:    false,
			Value:       "key",
		}),
		altsrc.NewBoolFlag(&cli.BoolFlag{
			Name:        "run-ssh",
			Usage:       "run ssh after tunnel established",
			EnvVars:     []string{"RUN_SSH"},
			Destination: &config.runssh,
			Required:    false,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "ssh-user",
			Usage:       "ssh user",
			EnvVars:     []string{"SSH_USER"},
			Destination: &config.sshuser,
			Required:    false,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "ssh-keypath",
			Usage:       "ssh private key path",
			EnvVars:     []string{"SSH_KEYPATH"},
			Destination: &config.sshkeypath,
			Required:    false,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "ssh-cmdline",
			Usage:       "ssh command line template, %P = port %L = local address",
			EnvVars:     []string{"SSH_CMDLINE"},
			Destination: &config.sshcmdline,
			Value:       "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=" + os.DevNull + " %L -p %P",
			Required:    false,
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:        "ssh-extra-args",
			Usage:       "extra args for ssh command line",
			EnvVars:     []string{"SSH_EXTRA_ARGS"},
			Destination: &config.sshextraargs,
			Required:    false,
		}),
		&cli.StringFlag{
			Name:  "config",
			Usage: "config yaml file path",
			Value: fmt.Sprintf("%v.yaml", strings.TrimSuffix(os.Args[0], ".exe")),
		},
	}

	azureOpts := azcore.ClientOptions{
		Cloud: cloud.AzurePublic,
	}

	requiredflags := []string{
		"subscription",
		"group",
		"name",
		"target-addr",
		"target-port",
	}

	app := &cli.App{
		Name:    "bastion-tunnel",
		Usage:   "create tcp tunnel via azure bastion",
		Version: version(),
		Flags:   flags,
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

			if config.localPort == 0 {
				p := uint(nextAvaliablePort())
				config.localPort = p
			}

			if config.runssh {
				if !c.IsSet("target-port") {
					c.Set("target-port", "22")
				}
			}

			// check required flags
			for _, f := range requiredflags {
				if !c.IsSet(f) {
					return fmt.Errorf("missing required flag: %s", f)
				}
			}

			cred, err := createCred(config.token, &azureOpts)
			if err != nil {
				return err
			}

			var signer ssh.Signer
			if config.keyvaultUrl != "" && config.keyvaultKeyName != "" {
				signer, err = keyFromKeyVault(cred, config.keyvaultUrl, config.keyvaultKeyName, config.keyvaultKeyType)
				if err != nil {
					return err
				}
			}

			if signer != nil {
				fmt.Printf("using ssh public key: %s\n", strings.Trim(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "\n"))
			}

			log.Printf("querying bastion %s/%s/%s", config.subscription, config.group, config.name)
			b, err := azbastion.NewFromArm(cred, config.subscription, config.group, config.name, &azureOpts)
			if err != nil {
				return err
			}

			localaddr := net.JoinHostPort(config.localAddr, fmt.Sprintf("%d", config.localPort))
			log.Printf("listening at %v", localaddr)
			l, err := net.Listen("tcp", localaddr)
			if err != nil {
				return err
			}

			done := make(chan error, 1)
			defer l.Close()

			go func() {

				for {
					c, err := l.Accept()
					if err != nil {
						if ne, ok := err.(net.Error); ok && ne.Temporary() {
							continue
						}

						log.Warnf("error accepting connection: %v", err)
						break
					}

					log.Printf("accepted connection: %v", c.RemoteAddr())

					go func(conn net.Conn) {
						defer conn.Close()
						t, err := b.NewTunnelSession(config.targetAddr, uint16(config.targetPort), fmt.Sprintf("%s/.default", azureOpts.Cloud.Services[cloud.ResourceManager].Endpoint))
						if err != nil {
							log.Errorf("error creating tunnel session: %v", err)
							return
						}

						targetaddr := net.JoinHostPort(config.targetAddr, fmt.Sprintf("%d", uint16(config.targetPort)))
						log.Printf("tunnel session created: %v -> %v", localaddr, targetaddr)

						defer t.Close()

						if err := pipeConn(conn, t, targetaddr, signer); err != nil {
							log.Warnf("error piping connection: %v", err)
						}

					}(c)
				}
			}()

			if config.runssh {
				cmdline := strings.ReplaceAll(config.sshcmdline, "%P", fmt.Sprintf("%d", config.localPort))
				cmdline = strings.ReplaceAll(cmdline, "%L", config.localAddr)
				parts := strings.Split(cmdline, " ")
				exe := parts[0]
				args := parts[1:]
				if config.sshuser != "" {
					args = append(args, "-l", config.sshuser)
				}

				if config.sshkeypath != "" {
					args = append(args, "-i", config.sshkeypath)
				}

				if config.sshextraargs != "" {
					args = append(args, strings.Split(config.sshextraargs, " ")...)
				}

				cmd := exec.Command(exe, args...)
				log.Printf("running ssh: %v", cmd)
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				done <- cmd.Run()
			}

			return <-done
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

func nextAvaliablePort() int {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
