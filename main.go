package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

const bytePadding = 20
const propertyLoginWebService = "loginWebService="
const tibiaLoginWebService1 = "https://www.tibia.com/services/clientservices.php"
const tibiaLoginWebService2 = "https://secure.tibia.com/services/clientservices.php"
const tibiaLoginWebService3 = "https://secure.tibia.com/services/login.php"

func main() {
	var currentExecutable, tibiaExe, customLoginWebService string
	var err error

	args := os.Args
	if len(args) > 0 {
		currentExecutable = args[0]
		fmt.Println(currentExecutable)
	}

	if len(args) > 1 {
		tibiaExe = args[1]
		fmt.Println(tibiaExe)
	}

	if len(args) > 2 {
		customLoginWebService = args[2]
		fmt.Println(customLoginWebService)
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
	for _, tibiaLoginWebService := range []string{tibiaLoginWebService1, tibiaLoginWebService2, tibiaLoginWebService3} {
		if propertyIndex := bytes.IndexAny(tibiaBinary, fmt.Sprintf("%s%s", propertyLoginWebService, tibiaLoginWebService)); propertyIndex != -1 {
			if len(customLoginWebService) > len(tibiaLoginWebService) {
				fmt.Printf("[ERROR] Cannot replace %s to %s, because the new loginWebService length is greater then %d.\n", tibiaLoginWebService, customLoginWebService, len(tibiaLoginWebService))
				os.Exit(1)
			}

			originalWebService := []byte(propertyLoginWebService + tibiaLoginWebService)
			customWebService := []byte(propertyLoginWebService + customLoginWebService)

			if len(customWebService) < len(originalWebService) {
				customWebService = append(customWebService, bytes.Repeat([]byte{0x20}, len(originalWebService)-len(customWebService))...)
			}

			tibiaBinary = bytes.Replace(tibiaBinary, originalWebService, customWebService, 1)
			fmt.Printf("[INFO] Tibia Login WebService found! %s\n", tibiaLoginWebService)
			fmt.Printf("[PATCH] Tibia Login WebService replaced to %s!\n", customLoginWebService)
			replaced = true
			break
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
