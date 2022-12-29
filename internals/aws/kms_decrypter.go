package aws

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/wangchao475/secretone/internals/api"
)

// KMSDecrypter is an implementation of the secretone.Decrypter interface that uses AWS KMS for decryption.
type KMSDecrypter struct {
	kmsSvcGetter func(region string) kmsiface.KMSAPI
}

// NewKMSDecrypter returns a new KMSDecrypter that uses the provided configuration to configure the AWS session.
func NewKMSDecrypter(cfgs ...*aws.Config) (*KMSDecrypter, error) {
	sess, err := session.NewSession(cfgs...)
	if err != nil {
		return nil, HandleError(err)
	}

	return &KMSDecrypter{
		kmsSvcGetter: func(region string) kmsiface.KMSAPI {
			return kms.New(sess, aws.NewConfig().WithRegion(region))
		},
	}, nil
}

// Unwrap the provided ciphertext using AWS KMS.
func (d KMSDecrypter) Unwrap(ciphertext *api.EncryptedData) ([]byte, error) {
	data, _ := json.Marshal(ciphertext.Key)
	var awsEncKey api.EncryptionKeyAWS
	err := json.Unmarshal(data, &awsEncKey)
	if err != nil {
		return nil, api.ErrInvalidKeyType
	}
	//key, ok := ciphertext.Key.(*api.EncryptionKeyAWS)
	//if !ok {
	//	return nil, api.ErrInvalidKeyType
	//}
	keyARN, err := arn.Parse(awsEncKey.ID)
	if err != nil {
		return nil, api.ErrInvalidCiphertext
	}
	svc := d.kmsSvcGetter(keyARN.Region)
	baseData, err := base64.StdEncoding.DecodeString(string(ciphertext.Ciphertext)) //原来逻辑没有base64解码流程
	if err != nil {
		return nil, errors.New("decode account key failed:" + err.Error())
	}
	resp, err := svc.Decrypt(&kms.DecryptInput{
		CiphertextBlob: baseData,
		KeyId:          aws.String(awsEncKey.ID),
	})
	if err != nil {

		return nil, HandleError(err)
	}
	return resp.Plaintext, nil
	//key, ok := ciphertext.Key.(*api.EncryptionKeyAWS)
	//if !ok {
	//	return nil, api.ErrInvalidKeyType
	//}
	//keyARN, err := arn.Parse("arn:aws:kms:ap-east-1:332005660813:key/0aaa319d-e3b8-43c5-af6c-98cad83943f9")
	//if err != nil {
	//	return nil, api.ErrInvalidCiphertext
	//}
	//
	//svc := d.kmsSvcGetter(keyARN.Region)
	//text,_ := base64.StdEncoding.DecodeString("AQICAHisAB6m3aopSkhCV1BuUkPDPFnvU1ptIq8Sw7/N5RmuoQHWA0q5tvimzoR5ZdNWczsYAAABajCCAWYGCSqGSIb3DQEHBqCCAVcwggFTAgEAMIIBTAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAw2QJonuLpHeI0i/B8CARCAggEdrg8t66JSWYRB9buTFNxBlfkOXe7IRPpx43vxawqd1Rs6leidvTtyRyT5w5BU51NITj9cTXFyYNrdzAZ8+DNvWuAtpNdGl58XTAA8UI84ViuI4Cvql+hnB44FhUBg0p6XqHp81H7voiBEQEKkeUCTbt+JQDsgsx/qxr6sST5eoBKgoZqe5/CqwpyLax4U4ZI/Bxr0GSJmCAVtUuYknpwrCn26JBZypFuqSDpaK+jOUOhWQOvZc/1VTsR+wni2dvr2T0tEjzAj0m9v4jPIUOv3njWf1ujy+H9o7SUO7W5/wqM78Gs43U9c+Eqf1Lz08AJRd35nOtQLtcvEP4nMnpXwz7z3L1hyYzyGHA6QUi3pe+Alea9Rdn6u4yWT4AiL")
	//resp, err := svc.Decrypt(&kms.DecryptInput{
	//	CiphertextBlob: text,
	//})
	//if err != nil {
	//	return nil, HandleError(err)
	//}
	//return resp.Plaintext, nil
}
