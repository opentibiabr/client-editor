package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var newLineByte = []byte{0x0a}
var paddingByte = []byte{0x20}
var battleyeHex = []byte{0x8d, 0x4d, 0x80, 0x75, 0x0e, 0xe8, 0x2e, 0xc8}
var removeBattleyeHex = []byte{0x8d, 0x4d, 0x80, 0xeb, 0x0e, 0xe8, 0x2e, 0xc8}

const propertyLoginWebService = "loginWebService="
const propertyClientWebService = "clientWebService="

func main() {
	var currentExecutable, tibiaExe, customLoginWebService string
	var err error

	args := os.Args
	if len(args) > 0 {
		currentExecutable = args[0]
	}

	if len(args) > 1 {
		tibiaExe = args[1]
	}

	if len(args) > 2 {
		customLoginWebService = args[2]
	}

	if currentExecutable == "" || tibiaExe == "" || customLoginWebService == "" {
		fmt.Printf("USAGE: %s <Tibia.exe Path> <Address Login Service>\n", currentExecutable)
		os.Exit(1)
	}

	tibiaPath, tibiaBinary := readFile(tibiaExe)
	var originalBinarySize = len(tibiaBinary)

	_, tibiaRsa := readFile("tibia_rsa.key")
	_, otservRsa := readFile("otserv_rsa.key")

	tibiaExeFileName := filepath.Base(tibiaPath)
	tibiaExeBackupPath := filepath.Join(filepath.Dir(tibiaPath), fmt.Sprintf("BKP%d-%s", time.Now().Unix(), tibiaExeFileName))
	tibiaExeBackupFileName := filepath.Base(tibiaExeBackupPath)

	fmt.Printf("[INFO] Backuping %s to %s\n", tibiaExeFileName, tibiaExeBackupFileName)
	err = os.WriteFile(tibiaExeBackupPath, tibiaBinary, 0644)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("[INFO] Searching for Tibia RSA... \n")
	if bytes.ContainsAny(tibiaBinary, string(tibiaRsa)) {
		fmt.Printf("[INFO] Tibia RSA found!\n")
		tibiaBinary = bytes.Replace(tibiaBinary, tibiaRsa, otservRsa, 1)
		fmt.Printf("[PATCH] Tibia RSA replaced to OTServ RSA!\n")
	} else if bytes.ContainsAny(tibiaBinary, string(otservRsa)) {
		fmt.Printf("[WARN] OTServ RSA already patched!\n")
	} else {
		fmt.Printf("[ERROR] Unable to find Tibia RSA\n")
		os.Exit(1)
	}

	fmt.Printf("[INFO] Searching for Battleye... \n")
	if bytes.Contains(tibiaBinary, battleyeHex) {
		fmt.Printf("[INFO] Battleye found!\n")
		tibiaBinary = bytes.Replace(tibiaBinary, battleyeHex, removeBattleyeHex, 1)
		fmt.Printf("[PATCH] Battleye removed!\n")
	} else if bytes.Contains(tibiaBinary, removeBattleyeHex) {
		fmt.Printf("[WARN] Battleye already removed!\n")
	} else {
		fmt.Printf("[ERROR] Unable to find Battleye\n")
	}

	fmt.Printf("[INFO] Searching for Login WebService... \n")
	var replaced bool

	// Find in the binary where we have these properties
	var loginPropertyIndex = bytes.Index(tibiaBinary, []byte(propertyLoginWebService))
	var clientPropertyIndex = bytes.Index(tibiaBinary, []byte(propertyClientWebService))

	if loginPropertyIndex != -1 {
		// Extract current login web service
		var startLoginWebServiceValue = loginPropertyIndex + len(propertyLoginWebService)
		var endLoginWebServiceValue = startLoginWebServiceValue + bytes.Index(tibiaBinary[startLoginWebServiceValue:], newLineByte)
		var loginWebServiceValue = string(tibiaBinary[startLoginWebServiceValue:endLoginWebServiceValue])

		if len(customLoginWebService) > len(loginWebServiceValue) {
			fmt.Printf("[ERROR] Cannot replace webservice to %s, because the new loginWebService must be smaller than '%s' (%d chars).\n", customLoginWebService, loginWebServiceValue, len(loginWebServiceValue))
			os.Exit(1)
		}

		fmt.Printf("[INFO] Tibia Login WebService found! %s\n", loginWebServiceValue)

		// Create the new services with the correct length
		var customWebService = []byte(customLoginWebService)
		var paddedCustomLoginWebService = append(customWebService, bytes.Repeat(paddingByte, len(loginWebServiceValue)-len(customLoginWebService))...)

		// Merge everything back to the client
		remainingOfBinary := tibiaBinary[endLoginWebServiceValue:]

		tibiaBinary = append(tibiaBinary[:startLoginWebServiceValue], paddedCustomLoginWebService...)
		tibiaBinary = append(tibiaBinary, remainingOfBinary...)

		if originalBinarySize != len(tibiaBinary) {
			fmt.Printf("[ERROR] Fatal error: The new modified client (size %d) has different bytesize from the original (size %d). Make sure to use the correct versions of both the client and client-editor or report a bug\n", len(tibiaBinary), originalBinarySize)
			os.Exit(1)
		}

		fmt.Printf("[PATCH] Tibia Login WebService replaced to %s!\n", customLoginWebService)
		replaced = true
	} else {
		fmt.Printf("[WARNING] Tibia Login WebService was not found! \n")
	}

	if clientPropertyIndex != -1 {
		// Extract current client web service
		var startClientWebServiceValue = clientPropertyIndex + len(propertyClientWebService)
		var endClientWebServiceValue = startClientWebServiceValue + bytes.Index(tibiaBinary[startClientWebServiceValue:], newLineByte)
		var clientWebServiceValue = string(tibiaBinary[startClientWebServiceValue:endClientWebServiceValue])

		if len(customLoginWebService) > len(clientWebServiceValue) {
			fmt.Printf("[ERROR] Cannot replace webservice to %s, because the new clientWebService must be smaller than '%s' (%d chars).\n", customLoginWebService, clientWebServiceValue, len(clientWebServiceValue))
			os.Exit(1)
		}

		fmt.Printf("[INFO] Tibia Client WebService found! %s\n", clientWebServiceValue)

		// Create the new services with the correct length
		var customWebService = []byte(customLoginWebService)
		var paddedCustomClientWebService = append(customWebService, bytes.Repeat(paddingByte, len(clientWebServiceValue)-len(customLoginWebService))...)

		// Merge everything back to the client
		remainingOfBinary := tibiaBinary[endClientWebServiceValue:]

		tibiaBinary = append(tibiaBinary[:startClientWebServiceValue], paddedCustomClientWebService...)
		tibiaBinary = append(tibiaBinary, remainingOfBinary...)

		if originalBinarySize != len(tibiaBinary) {
			fmt.Printf("[ERROR] Fatal error: The new modified client (size %d) has different bytesize from the original (size %d). Make sure to use the correct versions of both the client and client-editor or report a bug\n", len(tibiaBinary), originalBinarySize)
			os.Exit(1)
		}

		fmt.Printf("[PATCH] Tibia Client WebService replaced to %s!\n", customLoginWebService)
		replaced = true
	} else {
		fmt.Printf("[WARNING] Tibia Client WebService was not found! Your client version might not require it. \n")
	}

	if !replaced {
		fmt.Printf("[ERROR] Unable to replace Tibia Login or Client WebService\n")
		os.Exit(1)
	}

	fmt.Printf("[PATCH] Exporting File!\n")
	err = os.WriteFile(tibiaPath, tibiaBinary, 0644)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}
}

func readFile(path string) (string, []byte) {
	fileAbs, err := filepath.Abs(path)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}

	fileName := filepath.Base(path)

	if _, err := os.Stat(fileAbs); os.IsNotExist(err) {
		fmt.Printf("[ERROR] cannot locate %s at %s\n", fileName, path)
		os.Exit(1)
	}

	raw, err := os.ReadFile(fileAbs)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}

	return fileAbs, raw
}
