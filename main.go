package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var endByte = []byte{0x0d, 0x0a}
var paddingByte = []byte{0x20}

const propertyTutorialProgressWebService = "tutorialProgressWebService="
const propertyLoginWebService = "loginWebService="

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
	_, tibiaRsa := readFile("tibia_rsa.key")
	_, otservRsa := readFile("otserv_rsa.key")

	tibiaExeFileName := filepath.Base(tibiaPath)
	tibiaExeBackupPath := filepath.Join(filepath.Dir(tibiaPath), fmt.Sprintf("BKP%d-%s", time.Now().Unix(), tibiaExeFileName))
	tibiaExeBackupFileName := filepath.Base(tibiaExeBackupPath)

	fmt.Printf("[INFO] Backuping %s to %s\n", tibiaExeFileName, tibiaExeBackupFileName)
	err = ioutil.WriteFile(tibiaExeBackupPath, tibiaBinary, 0644)
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

	fmt.Printf("[INFO] Searching for Login WebService... \n")
	var replaced bool

	if loginPropertyIndex := bytes.Index(tibiaBinary, []byte(propertyLoginWebService)); loginPropertyIndex != -1 {
		if tutorialPropertyIndex := bytes.Index(tibiaBinary, []byte(propertyTutorialProgressWebService)); tutorialPropertyIndex != -1 {
			loginPropertyIndex = loginPropertyIndex + len(propertyLoginWebService)
			webServiceMaxLength := tutorialPropertyIndex - loginPropertyIndex - 2

			if len(customLoginWebService) > webServiceMaxLength {
				fmt.Printf("[ERROR] Cannot replace webserivce to %s, because the new loginWebService length is greater then %d.\n", customLoginWebService, webServiceMaxLength)
				os.Exit(1)
			}

			oldCustomWebService := tibiaBinary[loginPropertyIndex : loginPropertyIndex+webServiceMaxLength]
			fmt.Printf("[INFO] Tibia Login WebService found! %s\n", strings.TrimSpace(string(oldCustomWebService)))

			customWebService := []byte(customLoginWebService)
			customWebService = append(customWebService, bytes.Repeat(paddingByte, webServiceMaxLength-len(customLoginWebService))...)
			customWebService = append(customWebService, endByte...)

			rest := tibiaBinary[tutorialPropertyIndex:]
			tibiaBinary = append(tibiaBinary[:loginPropertyIndex], customWebService...)
			tibiaBinary = append(tibiaBinary, rest...)

			fmt.Printf("[PATCH] Tibia Login WebService replaced to %s!\n", customLoginWebService)
			replaced = true
		}
	}

	if !replaced {
		fmt.Printf("[ERROR] Unable to replace Tibia Login WebService\n")
		os.Exit(1)
	}

	fmt.Printf("[PATCH] Exporting File!\n")
	err = ioutil.WriteFile(tibiaPath, tibiaBinary, 0644)
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

	raw, err := ioutil.ReadFile(fileAbs)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}

	return fileAbs, raw
}
