# DO NOT DEPLOY IN A PROFESSIONAL ENVIRONMENT!!!
LifeLine is an experimental project, and is thus **VERY** insecure. It was not designed to be deployed in a professional environment as an actual backup system, so don't do that. Thanks! :)

> note to/from [rondotdll](https://github.com/rondotdll):
> 
> You wrote this code when you were really tired, I verified that everything compiles correctly but I have not had a chance to verify everything functions entirely as intended. if you're feeling unsafe about this, roll back through the commit logs and use an older version. However, I really haven't touched any of the old code, merely added to it in a non-destructive way. Good Luck to you and your team!
> 
> - 11:32pm [rondotdll](https://github.com/rondotdll) from last night.

# ccdc-lifeline <sup>experimental</sup>
## Project Overview
LifeLine is an experimental project tailored for use in the [CCDC](https://www.nationalccdc.org/), and is designed to prevent a complete system lockout by running in the background waiting for a user to upload an activation file to a repository configured at setup. Upon detection of said activation file, LifeLine will recursively reset all user account passwords on Linux, Windows, and Active Directory to a user-provided string.

* [Windows Installation](#windows)
* [Linux Installation (Debian / RHEL)](#linux)

## Installation & Setup
### Windows
#### THERE IS NO RELEASE FOR WINDOWS!
This was intentional! Due to Windows Defender slowly becoming more capable at actually protecting our devices, by default it will automatically block most executables from doing anything in privilleged execution mode. Because of this, the auto-configuration mode requires a crap ton of extra firewall exclusions and rules that unnecessarily overcomplicate things.

#### Compiling from source:
1. Make sure you have at least go 1.21 installed and configured properly (can be found [here](https://go.dev/doc/install)).  
```sh
go version
```
2. If you don't have git installed, you can [download this repo as a zip](https://github.com/rondotdll/ccdc-lifeline/archive/refs/heads/main.zip). Otherwise:
```sh
git clone https://github.com/rondotdll/ccdc-lifeline
```
3. If you downloaded the zip, make sure to unzip the archive. Then cd into the root of the repo and compile:
> **Local Accounts:**
> ```sh
> go generate ;; go build -o lifeline.exe
> ```

> **Domain Joined:**
> ```sh
> go generate ;; go build -tags "ad" -o lifeline.exe
> ``
4. Run "lifeline.exe" to begin initial setup

### Linux
#### From Releases:
1. Head over to the [Releases](https://github.com/rondotdll/ccdc-lifeline/releases) page and download the latest linux release
2. Unzip the release file
3. Make binaries executable
```sh
chmod +x activate && chmod +x setup
```
4. Run the initial setup wizard in sudo
```sh
sudo ./setup
```

#### Compiling from source:
1. Install snap & git from your package manager 

> **Ubuntu / Debian:**
> ```sh
> sudo apt update && sudo apt install snap git
> ```

> **Fedora / CentOS:**
> ```sh
> sudo pacman -Syy && sudo pacman -S snap git
> ```
2. Download / Update go
```sh
sudo snap install go --classic
```
3. Clone this repository
```sh
git clone https://github.com/rondotdll/ccdc-lifeline
```
4. Cd into repo folder and compile
```sh
cd ccdc-lifeline
go generate && go build -o lifeline
```
5. Make binary executable and run setup **\*in sudo**
```sh
chmod +x lifeline && sudo lifeline
```


## How It Works
The concept is pretty simple, it just waits for a file to be uploaded to github containing an encrypted string to reset all passwords on a device to. The most difficult task of this project was designing it in a way that even if it remains open-sourced, it would still be protective enough for our use case. During the setup process, we generate a config file ([GOB](https://go.dev/blog/gob)'d struct) that stores a link to the **GitHub repository\*** to check for an activation file at, and an RSA Private Key. The corresponding public key is then uploaded in a PEM string to [termbin.com](https://termbin.com/), which then returns a 4-5 letter code that can be easily written down for later use. **I know, this isn't very secure. __*DO NOT STORE RSA PUBLIC KEYS IN PUBLIC DATA REPOS!!!*__** Once the setup completes, the user (you) will be prompted to start the background daemon to begin periodically (every 5-sec) checking the GitHub repository for the Activate file.
> **\*For your convenience**, I have implemented numerous checks to verify your repository is configured correctly, and that you don't accidentally reuse an old repository already containing an `ACTIVATE` file.
> (you're welcome)

Included with the actual protection binary, is also an activator binary which takes the code returned by termbin (referred to as a "recovery code") and a user-inputed password. After inputting both of these pieces of data, it pulls the RSA public key from termbin and uses it to encrypt the user-inputed password. This is what is actually stored in the outputed `ACTIVATE` file: the raw binary output of the RSA encryption.

Once the `ACTIVATE` file is uploaded to the repository specified at setup, the background daemon should pick it up in 5-10 seconds (depending on rate limits). The daemon will then decrypt the raw binary using the locally-stored private key and recursively change the passwords to each account on the system.

## Experimental Nature
Again, please note that this repository is experimental. The code and functionalities demonstrated should be used with caution and primarily for educational purposes.

## Contribution
Contributions to LifeLine are welcome. Whether you're fixing bugs, adding new features, or improving the documentation, your help is appreciated. Please feel free to fork the repository and submit pull requests.

#### ToDo List:
- [X] Add support for local Windows NT accounts
- [X] Add active directory account enabling / disabling
- [ ] Add automated intrusion detection
- [X] Add auto backup accounts

## License
LifeLine is released under the MIT License. See the LICENSE file in the repository for more details.

> *This README was AI auto-generated, and Human edited*
