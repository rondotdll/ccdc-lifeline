package main

import "crypto/rsa"

/*
	IMMUTABLE VARIABLES
*/

const (
	TokenElevation        = 20
	LinuxConfigLocation   = "/etc/project-one/config.protected"
	WindowsConfigLocation = "C:\\Users\\Administrator\\AppData\\Local\\project-one\\config.protected"

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

	// standard ansii codes

	Reset = "\033[0m"
	Red   = "\033[31m"
	Green = "\033[92m"
	//Yellow   = "\033[33m"	// Unused colors
	//Blue     = "\033[34m"	// Unused colors
	//Purple   = "\033[35m"	// Unused colors
	Cyan = "\033[36m" // Unused colors
	//Gray     = "\033[37m" // Unused colors
	White = "\033[97m"
)

/*
	MUTABLE VARIABLES
*/

var (
	MasterConfig Config
	MasterKey    = []byte{
		0x24, 0xad, 0xcc, 0x33, 0xad, 0x83, 0x3e, 0x9f,
		0x5a, 0x01, 0xb1, 0x95, 0x3b, 0x21, 0x82, 0xa5,
		0x9d, 0xee, 0x8e, 0x70, 0x3a, 0xf4, 0x5e, 0xf1,
		0x3d, 0xf7, 0xc0, 0x82, 0x68, 0x70, 0x1c, 0x22,
	}
)

/*
	TYPE DEFS
*/

type Config struct {
	RepoUrl   string
	Protector rsa.PrivateKey
}

type TOKEN_ELEVATION struct {
	TokenIsElevated uint32
}
