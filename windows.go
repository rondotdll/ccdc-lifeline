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
	"syscall"
	"time"
	"unsafe"
)

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

		// decrypt backup password from ACTIVATE file
		DecryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &MasterConfig.Protector, blob, nil)
		password := strings.TrimSpace(string(DecryptedBytes)) // convert raw bytes to string
		fmt.Println("Found password", password)

		// Get all AD users
		fmt.Println("Getting all AD users...") // DEBUGGER
		users, err := ExecPowerShell(`Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName`)
		handle(err)

		fmt.Println("Found ", len(strings.Split(users, "\n")), " users.") // DEBUGGER
		// Recursively change each user's password
		for _, user := range strings.Split(users, "\n") {
			user = strings.TrimSpace(user)
			if user == "" {
				continue
			}

			fmt.Println(`Changing "` + user + `"'s password to "` + password + `"...`) // DEBUGGER

			_, err = ExecPowerShell(`Set-ADAccountPassword -Identity "` + user + `" -NewPassword (ConvertTo-SecureString -AsPlainText "` + password + `" -Force)`)
			handle(err)
		}

		// Finished changing passwords
		fmt.Println(Green, "Finished changing passwords.", Reset) // DEBUGGER

		// :trollskull:
		WindowsBroadcast("In the digital night, where shadows blend,\nA band of blackhats met their end.\nWindows Server 2016, a fortress so grand,\nRepelled their efforts, they couldn't stand.\n\nLearn from this, your foiled scheme,\nNot every hack's a cyber dream.\nIn the game of codes, where you dared to play,\nThe server stood strong, you lost your way.\n\n- Shakespear (probably)")
		// reboot to kick out any attackers
		time.Sleep(2500 * time.Millisecond)
		ExecPowerShell("Restart-Computer -Force")

		os.Exit(0) // should be unreachable
	}
}
