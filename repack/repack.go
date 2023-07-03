package repack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz/lzma"
)

type File struct {
	LocalFile    string `json:"localfile"`
	PackedHash   string `json:"packedhash"`
	PackedSize   int64  `json:"packedsize"`
	URL          string `json:"url"`
	UnpackedHash string `json:"unpackedhash"`
	UnpackedSize int64  `json:"unpackedsize"`
}

type AssetsInfo struct {
	Files   []File `json:"files"`
	Version int    `json:"version"`
}

type ClientInfo struct {
	Version    string `json:"version"`
	Files      []File `json:"files"`
	Executable string `json:"executable"`
	Generation string `json:"generation"`
	Variant    string `json:"variant"`
	Revision   int    `json:"revision"`
}

func repackFiles(src, dst, platform string) error {
	clientFilePath := filepath.Join(src, "client.json")
	assetsFilePath := filepath.Join(src, "assets.json")

	// Read the existing client info
	clientInfo, err := readClientInfo(clientFilePath)
	if err != nil {
		return fmt.Errorf("failed to read client info: %w", err)
	}

	// Read the existing assets info
	assetsInfo, err := readAssetsInfo(assetsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read assets info: %w", err)
	}

	// Create a new directory for repacked files
	err = os.MkdirAll(dst, 0755)
	if err != nil {
		return fmt.Errorf("failed to create repacked directory: %w", err)
	}

	fmt.Printf("Repacking %d client files and %d assets files\n", len(clientInfo.Files), len(assetsInfo.Files))

	bar := progressbar.Default(int64(len(clientInfo.Files) + len(assetsInfo.Files)))

	for i := range clientInfo.Files {
		err := repackFile(&clientInfo.Files[i], src, dst)
		if err != nil {
			return fmt.Errorf("failed to repack file: %w", err)
		}
		bar.Add(1)
	}

	for i := range assetsInfo.Files {
		err := repackFile(&assetsInfo.Files[i], src, dst)
		if err != nil {
			return fmt.Errorf("failed to repack file: %w", err)
		}
		bar.Add(1)
	}

	for i := len(clientInfo.Files) - 1; i >= 0; i-- {
		if clientInfo.Files[i].UnpackedSize == 0 {
			clientInfo.Files = append(clientInfo.Files[:i], clientInfo.Files[i+1:]...)
		}
	}

	for i := len(assetsInfo.Files) - 1; i >= 0; i-- {
		if assetsInfo.Files[i].UnpackedSize == 0 {
			assetsInfo.Files = append(assetsInfo.Files[:i], assetsInfo.Files[i+1:]...)
		}
	}

	fmt.Printf("Repacked %d client files and %d assets files\n", len(clientInfo.Files), len(assetsInfo.Files))

	clientInfo.Revision++

	err = saveClientInfo(filepath.Join(dst, "client."+platform+".json"), clientInfo)
	if err != nil {
		return fmt.Errorf("failed to save updated client info: %w", err)
	}
	err = saveAssetsInfo(filepath.Join(dst, "assets.mac.json"), assetsInfo, "mac")
	if err != nil {
		return fmt.Errorf("failed to save updated assets info: %w", err)
	}
	err = saveAssetsInfo(filepath.Join(dst, "assets.windows.json"), assetsInfo, "windows")
	if err != nil {
		return fmt.Errorf("failed to save updated assets info: %w", err)
	}

	return nil
}

func readClientInfo(filePath string) (*ClientInfo, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var clientInfo ClientInfo
	err = json.Unmarshal(file, &clientInfo)
	if err != nil {
		return nil, err
	}

	return &clientInfo, nil
}

func readAssetsInfo(filePath string) (*AssetsInfo, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var assetsInfo AssetsInfo
	err = json.Unmarshal(file, &assetsInfo)
	if err != nil {
		return nil, err
	}

	return &assetsInfo, nil
}

func repackFile(file *File, src, dst string) error {
	localFilePath := filepath.Join(src, file.LocalFile)
	packedFilePath := filepath.Join(dst, file.URL)
	if _, err := os.Stat(localFilePath); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	err := os.MkdirAll(filepath.Dir(packedFilePath), 0755)
	if err != nil {
		return err
	}

	localFile, err := os.Open(localFilePath)
	if err != nil {
		return err
	}
	defer localFile.Close()

	packedFile, err := os.Create(packedFilePath)
	if err != nil {
		return err
	}
	defer packedFile.Close()

	if filepath.Ext(packedFilePath) == filepath.Ext(localFilePath) {
		_, err = io.Copy(packedFile, localFile)
		if err != nil {
			return err
		}
	} else {
		lzmaWriter, err := lzma.NewWriter(packedFile)
		if err != nil {
			return err
		}
		defer lzmaWriter.Close()

		_, err = io.Copy(lzmaWriter, localFile)
		if err != nil {
			return err
		}
		lzmaWriter.Close()
	}

	unpackedHash, unpackedSize, err := calculateHashAndSize(localFilePath)
	if err != nil {
		return err
	}

	packedHash, packedSize, err := calculateHashAndSize(packedFilePath)
	if err != nil {
		return err
	}

	file.PackedHash = packedHash
	file.PackedSize = packedSize
	file.UnpackedHash = unpackedHash
	file.UnpackedSize = unpackedSize

	return nil
}

func calculateHashAndSize(filePath string) (string, int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", 0, err
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(hash.Sum(nil)), fileInfo.Size(), nil
}

func saveClientInfo(filePath string, clientInfo *ClientInfo) error {
	clientJSON, err := json.MarshalIndent(clientInfo, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, clientJSON, 0644)
}

func saveAssetsInfo(filePath string, assetsInfo *AssetsInfo, platform string) error {
	for i := range assetsInfo.Files {
		assetsInfo.Files[i].LocalFile = assetsInfo.Files[i].URL
		if platform == "mac" {
			assetsInfo.Files[i].LocalFile = "Contents/Resources/" + assetsInfo.Files[i].LocalFile
		}
	}
	assetsJSON, err := json.MarshalIndent(assetsInfo, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, assetsJSON, 0644)
}

func Repack(src, dst, platform string) error {
	fmt.Printf("Repacking %s into %s\n", src, dst)
	err := repackFiles(src, dst, platform)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	return nil
}
