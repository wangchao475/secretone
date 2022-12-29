package credentials_test

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/wangchao475/secretone/pkg/secretone"
	"github.com/wangchao475/secretone/pkg/secretone/credentials"
)

func ExampleCreateKey() {
	client := secretone.Must(secretone.NewClient())

	credential := credentials.CreateKey()
	_, err := client.Services().Create("my/repo", "description", credential)
	if err != nil {
		// handle error
	}
	key, err := credential.Export()
	if err != nil {
		// handle error
	}
	fmt.Printf("The key credential of the service is:\n%s", key)
}

func ExampleCreateAWS() {
	client := secretone.Must(secretone.NewClient())

	credential := credentials.CreateAWS("1234abcd-12ab-34cd-56ef-1234567890ab", "MyIAMRole")
	_, err := client.Services().Create("my/repo", "description", credential)
	if err != nil {
		// handle error
	}
}

func ExampleCreateAWS_setRegion() {
	client := secretone.Must(secretone.NewClient())

	credential := credentials.CreateAWS(
		"1234abcd-12ab-34cd-56ef-1234567890ab",
		"MyIAMRole",
		&aws.Config{Region: aws.String("eu-west-1")})
	_, err := client.Services().Create("my/repo", "description", credential)
	if err != nil {
		// handle error
	}
}
