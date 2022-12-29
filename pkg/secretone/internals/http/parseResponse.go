package http

import (
	"encoding/json"
	"errors"
	"github.com/wangchao475/secretone/internals/api"
	"strings"
)

func ParseAccountKeyResponse(out *api.HttpResponse) (*api.EncryptedAccountKey, error) {
	respData := &api.EncryptedAccountKey{}
	vars, ok := out.Data.(map[string]interface{})
	if !ok {
		return nil, errors.New("data struct not valid")
	}
	for key, value := range vars {
		switch key {
		case "account":
			arr, _ := json.Marshal(value)
			var account api.Account
			err := json.Unmarshal(arr, &account)
			if err != nil {
				return nil, err
			}
			respData.Account = &account
			break
		case "credential":
			arr, _ := json.Marshal(value)
			var credential api.Credential
			err := json.Unmarshal(arr, &credential)
			if err != nil {
				return nil, err
			}
			respData.Credential = &credential
			break
		case "public_key":
			tmp, ok := value.(string)
			if !ok {
				return nil, errors.New("public_key type not valid")
			}
			respData.PublicKey = []byte(tmp)
			break
		case "encrypted_private_key":
			keyVars, ok := value.(map[string]interface{})
			if !ok {
				return nil, errors.New("encrypted_private_key type not valid")
			}
			var encPriKey api.EncryptedData
			for kkey, kvalue := range keyVars {
				switch kkey {
				case "algorithm":
					encPriKey.Algorithm = kvalue.(string)
				case "ciphertext":
					encPriKey.Ciphertext = []byte(kvalue.(string))
				case "key":
					encPriKey.Key = kvalue
				}
			}
			respData.EncryptedPrivateKey = &encPriKey
		}
	}
	return respData, nil
}
func ParseResponseData(data interface{}, out interface{}) (err error) {
	dataBytes, _ := json.Marshal(data)
	var tmp string
	if strings.Contains(string(dataBytes), "\"parent_id\":\"\"") {
		//处理服务端传过来parent_id为空，uuid在做json序列化的时候会报错的问题,将空字符串处理成空对象
		tmp = strings.ReplaceAll(string(dataBytes), "\"parent_id\":\"\"", "\"parent_id\":null")
	} else {
		tmp = string(dataBytes)
	}
	err = json.Unmarshal([]byte(tmp), out)
	if err != nil {
		return err
	} else {
		return nil
	}
}
