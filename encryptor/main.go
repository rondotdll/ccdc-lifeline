package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func encryptWithPublicKeyOAEP(msg string, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha256.New()
	return rsa.EncryptOAEP(hash, rand.Reader, pub, []byte(msg), nil)
}

func parseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("not an RSA public key")
	}
}

var (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Yellow = "\033[33m"
	Green  = "\033[92m"
)

/* Sample PEM string for testing

-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5WYFS4M+Z5g5gR7XCoW
I3lptyl3fzpPm+lnP0jWf3Mc++0/OAEUQRHogsk0EWCpCPUee3CNR19u7LAVpwGc
V19EarpSXRQaoJgzXd4iWND0pzQ6wkwRqFzbeWpYfigHYhuAVaJ06Fommgnu4xuJ
ctnkjyYWT8z1IfLYbDP0V4giQlrpQHY1hcsb5Rz3mA2vS4E4cs8TB6dm/WiSuEL2
s7HDDZ15VhS24XrjEMMLL65+GXJYPGEZErkT9eRNZUujCnsJNDkVQY1aLLBFA7tZ
C1eWjsOmTgBsaWSgeRvfvo6SpSGPSkX+75We3fc+ejUWyYmXHnREAlTZyFRS1YMZ
pQIDAQAB
-----END RSA PUBLIC KEY-----

*/

// LoadFromTermbin fetches the text from the given termbin URL.
func LoadFromTermbin(url string) string {
	// Make a GET request to the termbin URL
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	return string(body)
}

// Example usage
func main() {
	println(Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the password to reset the machine to > ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)
	if strings.Contains(password, "$") {
		println("Warning: Password contains a '$' character, which is invalid in windows.")
		fmt.Print("Re-Enter the password to reset the machine to (confirmation) > ")
		password, _ = reader.ReadString('\n')
	}

	fmt.Print("Please enter your recovery code > ")
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)

	PEMSTRING := LoadFromTermbin("https://termbin.com/" + code)

	key, err := parseRsaPublicKeyFromPemStr(PEMSTRING)
	if err != nil {
		panic(err)
	}

	blob, err := encryptWithPublicKeyOAEP(password, key)
	if err != nil {
		fmt.Println(Red + "Invalid PEM string, Please try again." + Reset)
	}

	os.WriteFile("ACTIVATE", blob, 0644)

	fmt.Println("Encrypted password written to file 'ACTIVATE'")
}
