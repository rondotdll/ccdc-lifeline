package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// Save our config struct to an encrypted binary file
func DumpStructToFile(data any, filename string, key []byte) error {
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

// Basic error handler to satisfy the linter
func handle(e error) {
	if e != nil {
		fmt.Println(Red + "PANIC: Something internal went wrong, this text should never be visible!!!")
		fmt.Println(Reset, e)
		os.Exit(-1)
	}
}

// Create and store out config file
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