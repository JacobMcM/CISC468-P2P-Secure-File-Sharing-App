package file

import (
	"GoClient/crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type FileInfo struct {
	Name          string `json:"name"`
	Size          int64  `json:"size"`
	Hash          []byte `json:"hash"`
	Signature     []byte `json:"signature"`
	OriginalOwner string `json:"original_owner"`
}

func NewFileInfo(name, originalOwner string, size int64, hash, sig []byte) *FileInfo {
	return &FileInfo{
		Name: name,
		Size: size,
		Hash: hash,
		Signature: sig,
		OriginalOwner: originalOwner,
	}
}

func SaveFileList(path string, files []*FileInfo) error {
	data, err := json.MarshalIndent(files, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadFileList(path string) ([]*FileInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []*FileInfo{}, nil
		}
		return nil, err
	}
	var files []*FileInfo
	if err := json.Unmarshal(data, &files); err != nil {
		return nil, err
	}
	return files, nil
}

func AddToFileList(path string, fileInfo *FileInfo) error {
    files, err := LoadFileList(path)
    if err != nil {
        return err
    }
    files = append(files, fileInfo)
	return SaveFileList(path, files)
}

func NewSelfOwnedFileInfo(path string, privKey *rsa.PrivateKey, ownerName string) (*FileInfo, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    sum := sha256.Sum256(data)
    hash := sum[:]

	sig, err := crypto.RsaPssSign(privKey, data)
    if err != nil {
        return nil, err
    }

    return &FileInfo{
        Name:          filepath.Base(path),
        Size:          int64(len(data)),
        Hash:          hash,
        Signature:     []byte(sig),
        OriginalOwner: ownerName,
    }, nil
}

func InitFileList(path string, privateKey *rsa.PrivateKey, ownerName string) error {
    var files []*FileInfo

    entries, err := os.ReadDir(path)
    if err != nil {
        return fmt.Errorf("failed to read dir: %w", err)
    }

    for _, entry := range entries {
        if entry.IsDir() {
            continue
        }
        filePath := filepath.Join(path, entry.Name())
        fileInfo, err := NewSelfOwnedFileInfo(filePath, privateKey, ownerName)
        if err != nil {
            fmt.Printf("skipping %s: %v", entry.Name(), err)
            continue
        }
        files = append(files, fileInfo)
    }

    return SaveFileList(filepath.Join(path, "file_list.json"), files)
}

