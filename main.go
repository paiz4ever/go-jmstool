package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var (
	supportedCiphers = []string{
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"arcfour256", "arcfour128", "arcfour",
		"aes128-cbc", "3des-cbc"}

	supportedKexAlgos = []string{
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group14-sha1", "ecdh-sha2-nistp256", "ecdh-sha2-nistp521",
		"ecdh-sha2-nistp384", "curve25519-sha256@libssh.org"}

	supportedHostKeyAlgos = []string{
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"ssh-rsa", "ssh-dss", "ssh-ed25519"}
)

func WatchWindowSize(sigwinchCh chan os.Signal) {
	signal.Notify(sigwinchCh, syscall.SIGWINCH)
}

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "JMS ssh tool",
	Long: `JMS ssh tool
For example:
jmstool ssh -H <hostname>
`,
	Run: func(cmd *cobra.Command, args []string) {
		var hostName string
		if flagHostName, err := cmd.PersistentFlags().GetString("hostname"); err == nil {
			hostName = flagHostName
		}
		if strings.TrimSpace(hostName) == "" {
			fmt.Print("请输入主机名 (-H): ")
			_, err := fmt.Scanln(&hostName)
			if err != nil || strings.TrimSpace(hostName) == "" {
				fmt.Println("未输入主机名，程序终止。")
				os.Exit(1)
			}
		}
		client := GetClient()
		assetResp, err := client.R().
			SetQueryParam("name", hostName).
			Execute(http.MethodGet, "/api/v1/assets/assets/suggestions/")
		if err != nil {
			log.Fatalf("请求资源失败: %v", err)
		} else if assetResp.IsError() {
			log.Fatalf("请求资源失败: %v", assetResp.String())
		}
		tokenResp, err := client.R().
			SetBody(map[string]interface{}{
				"account":        "ecs-user",
				"asset":          gjson.GetBytes(assetResp.Body(), "0.id").String(),
				"connect_method": "ssh_guide",
				"protocol":       "ssh",
			}).
			Execute(http.MethodPost, "/api/v1/authentication/connection-token/")
		if err != nil {
			log.Fatalf("请求token失败: %v", err)
		} else if assetResp.IsError() {
			log.Fatalf("请求token失败: %v", tokenResp.String())
		}
		tokenBody := tokenResp.Body()
		username := fmt.Sprintf("JMS-%s", gjson.GetBytes(tokenBody, "id").String())
		host := config.SSH.Host
		port := "2222"
		password := gjson.GetBytes(tokenBody, "value").String()

		config := &gossh.ClientConfig{
			User: username,
			Auth: []gossh.AuthMethod{
				gossh.Password(password),
			},
			HostKeyCallback:   gossh.InsecureIgnoreHostKey(),
			Config:            gossh.Config{Ciphers: supportedCiphers, KeyExchanges: supportedKexAlgos},
			Timeout:           30 * time.Second,
			HostKeyAlgorithms: supportedHostKeyAlgos,
		}
		sshClient, err := gossh.Dial("tcp", net.JoinHostPort(host, port), config)
		if err != nil {
			log.Fatalf("dial err: %s", err)
		}
		defer sshClient.Close()
		sess, err := sshClient.NewSession()
		if err != nil {
			log.Fatalf("Session err: %s", err)
		}
		modes := gossh.TerminalModes{
			gossh.ECHO:          1,
			gossh.TTY_OP_ISPEED: 14400,
			gossh.TTY_OP_OSPEED: 14400,
		}
		xterm := os.Getenv("xterm")
		if xterm == "" {
			xterm = "xterm-256color"
		}
		fd := int(os.Stdin.Fd())
		w, h, _ := term.GetSize(fd)
		err = sess.RequestPty(xterm, h, w, modes)
		if err != nil {
			log.Fatalf("RequestPty err: %s", err)
		}
		in, err := sess.StdinPipe()
		if err != nil {
			log.Fatalf("StdinPipe err: %s", err)
		}
		out, err := sess.StdoutPipe()
		if err != nil {
			log.Fatalf("StdoutPipe err: %s", err)
		}
		state, err := term.MakeRaw(fd)
		if err != nil {
			log.Fatalf("MakeRaw err: %s", err)
		}
		defer term.Restore(fd, state)
		go io.Copy(in, os.Stdin)
		go io.Copy(os.Stdout, out)
		sigwinchCh := make(chan os.Signal, 1)
		WatchWindowSize(sigwinchCh)
		sigChan := make(chan struct{}, 1)
		err = sess.Shell()
		if err != nil {
			log.Fatalf("Shell err: %s", err)
		}
		go func() {
			for {
				select {
				case <-sigChan:
					return
				case sigwinch := <-sigwinchCh:
					if sigwinch == nil {
						return
					}
					w, h, err := term.GetSize(fd)
					if err != nil {
						log.Printf("Unable to send window-change reqest: %s. \n", err)
						continue
					}
					if err := sess.WindowChange(h, w); err != nil {
						log.Println("Window change err: ", err)
					}
				}
			}
		}()
		err = sess.Wait()
		sigChan <- struct{}{}
		if err != nil {
			log.Fatalf("Wait err: %s", err)
		}
	},
}

func init() {
	sshCmd.PersistentFlags().StringP("hostname", "H", "", "主机名")
}

func main() {
	if err := InitConfig(); err != nil {
		log.Fatalf("初始化配置失败: %v", err)
	}
	if err := sshCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
