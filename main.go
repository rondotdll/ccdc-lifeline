package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Config struct {
	RepoUrl   string
	Protector rsa.PrivateKey
}

const (

	// standard ansii codes

	TrollFace = `░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░
░░░░░█░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░▀▀▄░░░░
░░░░█░░░▒▒▒▒▒▒░░░░░░░░▒▒▒░░█░░░
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█░░
░▄▀▒▄▄▄▒░█▀▀▀▀▄▄█░░░██▄▄█░░░░█░
█░▒█▒▄░▀▄▄▄▀░░░░░░░░█░░░▒▒▒▒▒░█
█░▒█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄▒█
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█░
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█░░
░░░█░░░░██░░▀█▄▄▄█▄▄█▄████░█░░░
░░░░█░░░░▀▀▄░█░░░█░█▀██████░█░░
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█░░
░░░░░░░▀▄▄░▒▒▒▒░░░░░░░░░░▒░░░█░
░░░░░░░░░░▀▀▄▄░▒▒▒▒▒▒▒▒▒▒░░░░█░
░░░░░░░░░░░░░░▀▄▄▄▄▄░░░░░░░░█░░`

	Reset = "\033[0m"
	Red   = "\033[31m"
	Green = "\033[92m"
	//Yellow   = "\033[33m"	// Unused colors
	//Blue     = "\033[34m"	// Unused colors
	//Purple   = "\033[35m"	// Unused colors
	//Cyan     = "\033[36m"	// Unused colors
	//Gray     = "\033[37m" // Unused colors
	White = "\033[97m"

	systemd_service = `[Unit]
Description=Lockout FailSafe
After=network.target

[Service]
ExecStart=/usr/local/bin/failsafe
User=root
Restart=on-failure
RestartPreventExitStatus=10
StandardOutput=/var/log/failsafe.log
StandardError=/var/log/failsafe.log
Type=simple

[Install]
WantedBy=multi-user.target`
)

var (
	MasterConfig Config
	key          = []byte{
		0x24, 0xad, 0xcc, 0x33, 0xad, 0x83, 0x3e, 0x9f,
		0x5a, 0x01, 0xb1, 0x95, 0x3b, 0x21, 0x82, 0xa5,
		0x9d, 0xee, 0x8e, 0x70, 0x3a, 0xf4, 0x5e, 0xf1,
		0x3d, 0xf7, 0xc0, 0x82, 0x68, 0x70, 0x1c, 0x22,
	}
)

func handle(e error) {
	if e != nil {
		fmt.Println(Red + "PANIC: Something internal went wrong, this text should never be visible!!!")
		fmt.Println(Reset, e)
		os.Exit(-1)
	}
}

func firstTimeSetup() {
	var err error
	var resp *http.Response
	PrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048) // returns pointer

	ghUrl := "0"
	ghUrl_confirm := "1"

	// Basic input validation for the GitHub URL
	for ghUrl != ghUrl_confirm {
		fmt.Print("Enter the URL of the GitHub to search for backups: ")
		fmt.Scanln(&ghUrl)
		fmt.Print("Re-type GitHub URL: ")
		fmt.Scanln(&ghUrl_confirm)
		if ghUrl != ghUrl_confirm {
			fmt.Println(Red + "URLs do not match, please try again." + Reset)
		}
	}

	// Ensure the URL is in the correct format
	ghUrl = "https://" + strings.TrimPrefix(strings.TrimPrefix(ghUrl, "http://"), "https://")

	fmt.Println("Contacting repository...")
	// Attempt to make a GET request to the repository
	resp, err = http.Get(ghUrl)
	_ = resp.Body.Close()
	handle(err) // universal internal error handling (this should realistically never trigger)
	if resp.StatusCode != 200 {
		// if the repository returned 404, it's unreachable (either private or non-existent)
		fmt.Println(Red + "Failed to read repository:" + Reset)
		fmt.Println(Red+"Status Code", resp.StatusCode, Reset)
		os.Exit(-1)
	}

	// Validate the repository doesn't already contain an "ACTIVATE" file
	// this is useful in case we need to redeploy our failsafe,
	// we can generate a brand-new config file and RSA key
	fmt.Println("Validating repository...")

	// Format the github repo url into the direct download link to the ACTIVATE file
	temp := strings.Split(ghUrl, "github.com/")
	temp = strings.Split(temp[1], "/")

	ghUrl = "https://raw.githubusercontent.com/" + temp[0] + "/" + temp[1] + "/main/ACTIVATE"

	resp, err = http.Get(ghUrl) // attempt to download the ACTIVATE file
	defer resp.Body.Close()
	handle(err)
	if resp.StatusCode != 404 {
		fmt.Println(Red + "Misconfigured Repository." + Reset)
		fmt.Println(Red+"Make sure there is no file called 'ACTIVATE'", resp.StatusCode, Reset)
		os.Exit(-1)
	}

	MasterConfig.RepoUrl = ghUrl
	MasterConfig.Protector = *PrivateKey // dereference the pointer (low level memory manipulation crap)

	fmt.Println("Generating config file...")
	err = DumpStructToFile(MasterConfig, "/etc/failsafe/config.protected")
	handle(err)

	fmt.Println("Config file generated successfully.")
	fmt.Println("Adding process to systemd...")

	// Create the systemd service file
	// This is necessary to ensure the failsafe keeps listening even if we reboot the system.
	err = os.WriteFile("/etc/systemd/system/failsafe.service", []byte(systemd_service), 0644)
	handle(err)

	fmt.Println("Copying binary to /usr/local/bin...")
	// Copy the binary to /usr/local/bin so it can be run as a service
	thisPath, _ := os.Executable()
	exec.Command("cp", thisPath, "/usr/local/bin/failsafe").Run()
	exec.Command("chmod", "+x", "/usr/local/bin/failsafe").Run()

	fmt.Println("Enabling process...")
	// Enable the failsafe service to run at boot
	cmd := exec.Command("systemctl", "enable", "failsafe.service")
	err = cmd.Run()
	handle(err)
	output, _ := cmd.Output()
	println(White + string(output))

	// Export the RSA public key as a PEM string (readable format)
	PEMObj := ExportRsaPublicKeyAsPemStr(&PrivateKey.PublicKey)
	os.Stdout.WriteString(Green + PEMObj)

	os.WriteFile("PEM_STRING.txt", []byte(PEMObj), 0644)

	fmt.Println(Red + "\nSTORE THE ABOVE SOMEWHERE SAFE, YOU WILL NEED IT TO ACTIVATE THE FAILSAFE!" + Reset)
	fmt.Println("         ***** (INCLUDING THE HEADER AND FOOTER LINES) *****\n\n")
	fmt.Println("Done.")
	fmt.Println("Use " + White + "sudo systemctl start failsafe.service" + Reset + " or reboot to finalize install.")
	os.Exit(0)
}

// Save our config struct to an encrypted binary file
func DumpStructToFile(data any, filename string) error {
	// Encode the data using gob
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(data)
	if err != nil {
		return err
	}

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Generate a new IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Pad the data to ensure it is a multiple of the block size
	originalData := buffer.Bytes()
	padding := aes.BlockSize - len(originalData)%aes.BlockSize
	paddedData := append(originalData, bytes.Repeat([]byte{byte(padding)}, padding)...)

	// Encrypt the data
	encryptedData := make([]byte, aes.BlockSize+len(paddedData))
	copy(encryptedData[:aes.BlockSize], iv)
	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(encryptedData[aes.BlockSize:], paddedData)

	// Open the file to write
	os.Mkdir("/etc/failsafe", 0755)
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	println("creating file")
	defer file.Close()

	// Write the encrypted data to file
	_, err = file.Write(encryptedData)
	return err

}

// Load our config to the "MasterConfig" struct from an encrypted binary file
func LoadStructFromFile(data any, filename string) error {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read the encrypted data from file
	encryptedData, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Check for data length
	if len(encryptedData) < aes.BlockSize {
		return errors.New("ciphertext too short")
	}

	// IV is at the beginning of the file
	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]

	// Decrypt the data
	stream := cipher.NewCBCDecrypter(block, iv)
	stream.CryptBlocks(encryptedData, encryptedData)

	// Remove padding
	paddingLen := int(encryptedData[len(encryptedData)-1])
	if paddingLen > aes.BlockSize || paddingLen == 0 {
		return errors.New("invalid padding size")
	}
	decryptedData := encryptedData[:len(encryptedData)-paddingLen]

	// Decode the gob
	decoder := gob.NewDecoder(bytes.NewReader(decryptedData))
	err = decoder.Decode(data)
	return err

}

// Allows us to save the RSA public key in a somewhat human-readable format
func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) string {
	pubAsn1, _ := x509.MarshalPKIXPublicKey(pubkey)

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubAsn1,
	})

	return string(pubBytes)
}

// Broadcasts a message to all users (who says we can't have some fun back with the red team?)
func broadcastMessage(message string) error {
	cmd := exec.Command("wall", "-n")
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	go func() {
		defer stdinPipe.Close()
		stdinPipe.Write([]byte(message))
	}()

	return cmd.Run()
}

func main() {

	// Verify the program is being run as root
	if os.Geteuid() != 0 {
		fmt.Println(Red + "Program started with insufficient permissions, please re-run as root." + Reset)
		os.Exit(10)
	}

	// Check for config file
	if _, err := os.Stat("/etc/failsafe/config.protected"); os.IsNotExist(err) {
		fmt.Println("No config file detected.")
		fmt.Println("Beginning first time setup...")
		firstTimeSetup() // Should exit on its own...
		os.Exit(0)       // (just in case)
	}

	// Loads & unprotects the config file to MasterConfig
	err := LoadStructFromFile(&MasterConfig, "/etc/failsafe/config.protected")
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
