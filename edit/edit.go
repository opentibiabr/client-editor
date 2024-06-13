package edit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

var (
	properties = []string{
		"loginWebService",
		"clientWebService",
		"tibiaPageUrl",
		"tibiaStoreGetCoinsUrl",
		"getPremiumUrl",
		"createAccountUrl",
		"accessAccountUrl",
		"lostAccountUrl",
		"manualUrl",
		"faqUrl",
		"premiumFeaturesUrl",
		"crashReportUrl",
		"fpsHistoryRecipient",
		"cipSoftUrl",
	}
)

var paddingByte = []byte{0x20}
var battleyeHex = []byte{0x8d, 0x4d, 0xb4, 0x75, 0x0e, 0xe8, 0x5f, 0x7b}
var removeBattleyeHex = []byte{0x8d, 0x4d, 0xb4, 0xeb, 0x0e, 0xe8, 0x5f, 0x7b}

func Edit(tibiaExe string) {
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("[ERROR] Failed to read config file: %s\n", err.Error())
		os.Exit(1)
	}
	// Check if all properties are present in the config file
	missingProperties := make([]string, 0)
	for _, prop := range properties {
		if !viper.IsSet(prop) {
			missingProperties = append(missingProperties, prop)
		}
	}

	// Error out if any properties are missing
	if len(missingProperties) > 0 {
		fmt.Printf("[ERROR] Missing properties in the config file: %v\n", missingProperties)
		os.Exit(1)
	}

	configValues := make(map[string]string)
	for _, prop := range properties {
		value := viper.GetString(prop)
		configValues[prop] = value
	}

	tibiaPath, tibiaBinary := readFile(tibiaExe)
	originalBinarySize := len(tibiaBinary)

	backupTibiaExecutable(tibiaPath, tibiaBinary)

	tibiaBinary = replaceTibiaRSAKey(tibiaBinary)
	tibiaBinary = removeBattlEye(tibiaBinary)

	for prop, value := range configValues {
		ok := setPropertyByName(tibiaBinary, prop, value)
		if !ok {
			fmt.Printf("[ERROR] Unable to replace %s\n", prop)
		}
	}

	exportModifiedFile(tibiaPath, tibiaBinary, originalBinarySize)
}

func backupTibiaExecutable(tibiaPath string, tibiaBinary []byte) {
	tibiaExeFileName := filepath.Base(tibiaPath)
	tibiaExeBackupPath := filepath.Join(filepath.Dir(tibiaPath), fmt.Sprintf("BKP%d-%s", time.Now().Unix(), tibiaExeFileName))
	tibiaExeBackupFileName := filepath.Base(tibiaExeBackupPath)

	fmt.Printf("[INFO] Backing up %s to %s\n", tibiaExeFileName, tibiaExeBackupFileName)

	err := os.WriteFile(tibiaExeBackupPath, tibiaBinary, 0644)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}
}

func replaceTibiaRSAKey(tibiaBinary []byte) []byte {
	tibiaRsaPath := "tibia_rsa.key"
	otservRsaPath := "otserv_rsa.key"

	_, tibiaRsa := readFile(tibiaRsaPath)
	_, otservRsa := readFile(otservRsaPath)

	fmt.Printf("[INFO] Searching for Tibia RSA... \n")

	if bytes.ContainsAny(tibiaBinary, string(tibiaRsa)) {
		fmt.Printf("[INFO] Tibia RSA found!\n")
		tibiaBinary = bytes.Replace(tibiaBinary, tibiaRsa, otservRsa, 1)
		fmt.Printf("[PATCH] Tibia RSA replaced with OTServ RSA!\n")
	} else if bytes.ContainsAny(tibiaBinary, string(otservRsa)) {
		fmt.Printf("[WARN] OTServ RSA already patched!\n")
	} else {
		fmt.Printf("[ERROR] Unable to find Tibia RSA\n")
		os.Exit(1)
	}

	return tibiaBinary
}

func removeBattlEye(tibiaBinary []byte) []byte {
	fmt.Printf("[INFO] Searching for Battleye... \n")

	if bytes.Contains(tibiaBinary, battleyeHex) {
		fmt.Printf("[INFO] Battleye found!\n")
		tibiaBinary = bytes.Replace(tibiaBinary, battleyeHex, removeBattleyeHex, 1)
		fmt.Printf("[PATCH] Battleye removed!\n")
	} else if bytes.Contains(tibiaBinary, removeBattleyeHex) {
		fmt.Printf("[WARN] Battleye already removed!\n")
	} else {
		fmt.Printf("[WARN] Battleye not found\n")
	}

	return tibiaBinary
}

func exportModifiedFile(tibiaPath string, tibiaBinary []byte, originalBinarySize int) {
	outputFilePath := tibiaPath

	if len(tibiaBinary) != originalBinarySize {
		fmt.Printf("[ERROR] Invalid patched file size, original: %d, modified: %d\n", originalBinarySize, len(tibiaBinary))
		os.Exit(1)
	}

	err := os.WriteFile(outputFilePath, tibiaBinary, 0644)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("[INFO] Patched file exported to: %s\n", outputFilePath)
}

func readFile(filePath string) (string, []byte) {
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}

	return filePath, fileData
}

func setPropertyByName(tibiaBinary []byte, propertyName string, customValue string) bool {
	originalBinarySize := len(tibiaBinary)
	propertyName = fmt.Sprintf("%s=", propertyName)
	propertyIndex := bytes.Index(tibiaBinary, []byte(propertyName))
	if propertyIndex != -1 {
		// Extract current property value
		startValue := propertyIndex + len(propertyName)
		endValue := startValue + bytes.IndexByte(tibiaBinary[startValue:], '\n')
		propertyValue := string(tibiaBinary[startValue:endValue])

		if len(customValue) > len(propertyValue) {
			fmt.Printf("[ERROR] Cannot replace %s to '%s' because the new value must be smaller than '%s' (%d chars).\n", propertyName, customValue, propertyValue, len(propertyValue))
			return false
		}

		fmt.Printf("[INFO] %s found! %s\n", propertyName, propertyValue)

		// Create the new value with the correct length
		customValueBytes := []byte(customValue)
		paddedCustomValue := append(customValueBytes, bytes.Repeat(paddingByte, len(propertyValue)-len(customValueBytes))...)

		// Merge everything back to the client
		remainingBinary := tibiaBinary[endValue:]

		tibiaBinary = append(tibiaBinary[:startValue], paddedCustomValue...)
		tibiaBinary = append(tibiaBinary, remainingBinary...)

		if originalBinarySize != len(tibiaBinary) {
			fmt.Printf("[ERROR] Fatal error: The new modified client (size %d) has a different byte size from the original (size %d). Make sure to use the correct versions of both the client and client-editor or report a bug.\n", len(tibiaBinary), originalBinarySize)
			os.Exit(1)
		}

		fmt.Printf("[PATCH] %s replaced to %s!\n", propertyName, customValue)
		return true
	}

	fmt.Printf("[WARNING] %s was not found!\n", propertyName)
	return false
}
