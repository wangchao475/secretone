package api

import (
	"bitbucket.org/zombiezen/cardcpx/natsort"
	"net/http"
	"github.com/wangchao475/secretone/internals/api/uuid"
	"github.com/wangchao475/secretone/internals/crypto"
)

// Errors
var (
	ErrInvalidDirName = errAPI.Code("invalid_dir_name").StatusError(
		"directory names must be between 2 and 32 characters long and "+
			"may only contain letters, numbers, dashes (-), underscores (_), and dots (.)",
		http.StatusBadRequest,
	)
	ErrInvalidDirBlindName    = errAPI.Code("invalid_dir_name").StatusErrorf("directory name is invalid: %s", http.StatusBadRequest, ErrInvalidBlindName)
	ErrInvalidParentBlindName = errAPI.Code("invalid_parent_blind_name").StatusErrorf("directory parent blind name is invalid: %s", http.StatusBadRequest, ErrInvalidBlindName)
)

// EncryptedDir represents an encrypted Dir.
// The names are encrypted and so are the names of SubDirs and Secrets.
// The secrets contain no encrypted data, only the encrypted name.
type EncryptedDir struct {
	DirID uuid.UUID `json:"dir_id"`
	Path  string    `json:"path"`
	//BlindName      string               `json:"blind_name"`
	//EncryptedName  crypto.CiphertextSM2 `json:"encrypted_name"`
	Name           string     `json:"name"`
	ParentID       *uuid.UUID `json:"parent_id"`
	Status         string     `json:"status"`
	CreatedAt      string     `json:"created_at"`
	LastModifiedAt string     `json:"last_modified_at"`
}

// Decrypt decrypts an EncryptedDir into a Dir.
func (ed *EncryptedDir) Decrypt(accountKey *crypto.SM2PrivateKey) (*Dir, error) {
	//name, err := accountKey.Unwrap(ed.EncryptedName)
	//if err != nil {
	//	return nil, err
	//}

	result := &Dir{
		DirID: ed.DirID,
		//BlindName:      ed.BlindName,
		Path:           ed.Path,
		Name:           ed.Name,
		ParentID:       ed.ParentID,
		Status:         ed.Status,
		CreatedAt:      ed.CreatedAt,
		LastModifiedAt: ed.LastModifiedAt,
	}

	return result, nil
}

// Dir represents an directory.
// A dir belongs to a repo and contains other dirs and secrets.
type Dir struct {
	DirID uuid.UUID `json:"dir_id"`
	//BlindName      string     `json:"blind_name"`
	Path           string     `json:"path"`
	Name           string     `json:"name"`
	ParentID       *uuid.UUID `json:"parent_id"`
	Status         string     `json:"status"`
	CreatedAt      string     `json:"created_at"`
	LastModifiedAt string     `json:"last_modified_at"`
	SubDirs        []*Dir     `json:"sub_dirs"`
	Secrets        []*Secret  `json:"secrets"`
}

// CreateDirRequest contains the request fields for creating a new directory.
type CreateDirRequest struct {
	PathName        string `json:"path_name"`
	ParentBlindName string `json:"parent_name"` //todo tina 父路径是否需要待定

	EncryptedNames []EncryptedNameRequest `json:"encrypted_names"` //父路径下具有读权限的所有用户列表
}

// Validate validates the CreateDirRequest to be valid.
func (cdr *CreateDirRequest) Validate() error {
	//err := ValidateBlindName(cdr.PathName)
	//if err != nil {
	//	return ErrInvalidDirBlindName
	//}
	if cdr.PathName == "" {
		return ErrInvalidDirBlindName
	}
	//err = ValidateBlindName(cdr.ParentBlindName)
	//if err != nil {
	//	return ErrInvalidParentBlindName
	//}

	if len(cdr.EncryptedNames) < 1 {
		return ErrNotEncryptedForAccounts
	}

	//unique := make(map[uuid.UUID]int)
	for _, encryptedName := range cdr.EncryptedNames {
		err := encryptedName.Validate()
		if err != nil {
			return err
		}

		//unique[encryptedName.AccountID]++
	}
	//校验uuid唯一性
	//for _, count := range unique {
	//	if count != 1 {
	//		return ErrNotUniquelyEncryptedForAccounts
	//	}
	//}

	return nil
}

// SortDirByName makes a list of Dir sortable.
type SortDirByName []*Dir

func (d SortDirByName) Len() int {
	return len(d)
}
func (d SortDirByName) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
func (d SortDirByName) Less(i, j int) bool {
	return natsort.Less(d[i].Name, d[j].Name)
}
