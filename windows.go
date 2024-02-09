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
	"syscall"
	"time"
	"unsafe"
)

func isAdmin() bool {
	var tokenHandle syscall.Token
	currentProcess, _ := syscall.GetCurrentProcess()

	err := syscall.OpenProcessToken(currentProcess, syscall.TOKEN_QUERY, &tokenHandle)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	defer syscall.CloseHandle(syscall.Handle(tokenHandle))

	var elevation TOKEN_ELEVATION
	var returnedLen uint32
	err = syscall.GetTokenInformation(tokenHandle, TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returnedLen)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	return elevation.TokenIsElevated != 0
}

func main() {

	// Verify the program is being run as root
	if isAdmin() {
		fmt.Println(Red + "Program started with insufficient permissions, please re-run as Administrator." + Reset)
		os.Exit(10)
	}

	// Check for config file
	if _, err := os.Stat(WindowsConfigLocation); os.IsNotExist(err) {
		fmt.Println("No config file detected.")
		fmt.Println("Beginning first time setup...")
		WindowsFirstTimeSetup() // Should exit on its own...
		os.Exit(0)              // (just in case)
	}

	// Loads & unprotects the config file to MasterConfig
	err := LoadStructFromFile(&MasterConfig, WindowsConfigLocation, MasterKey)
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

		// Cleanup (in case we need to re-deploy)
		exec.Command("systemctl", "disable", "failsafe.service").Run()
		exec.Command("rm", "-f", "/etc/failsafe/config.protected").Run()

		// :trollskull:
		broadcastMessage("You really thought you won, huh?")
		go func() {
			for {
				broadcastMessage("Sorry, try again! :P")
			}
		}()
		time.Sleep(2500 * time.Millisecond)

		broadcastMessage(TrollFace)
		// reboot to kick out any attackers
		time.Sleep(500 * time.Millisecond)
		exec.Command("reboot").Run()

		os.Exit(0) // should be unreachable
	}
}
