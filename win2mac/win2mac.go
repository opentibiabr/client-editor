package win2mac

import (
	"encoding/json"
	"os"
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

func saveAssetsInfo(filePath string, assetsInfo *AssetsInfo) error {
	assetsJSON, err := json.MarshalIndent(assetsInfo, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, assetsJSON, 0644)
}

func Win2Mac(src, dst string) error {
	assetsInfo, err := readAssetsInfo(src)
	if err != nil {
		return err
	}
	for i := range assetsInfo.Files {
		assetsInfo.Files[i].LocalFile = "Contents/Resources/" + assetsInfo.Files[i].LocalFile
	}
	err = saveAssetsInfo(dst, assetsInfo)
	if err != nil {
		return err
	}
	return nil
}
