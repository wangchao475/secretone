package secretone_test

import (
	"fmt"
	"log"

	"github.com/wangchao475/secretone/pkg/secretone"

	"github.com/wangchao475/secretone/pkg/secretone/credentials"

	"github.com/wangchao475/secretone/pkg/secretone/iterator"
)

var client secretone.ClientInterface

// Create a new Client.
func ExampleNewClient() {
	client, err := secretone.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// use the client
	_, err = client.Secrets().ReadString("workspace/repo/secret")
	if err != nil {
		log.Fatal(err)
	}
}

// Create a new client that uses native AWS services to handle encryption and authentication.
func ExampleNewClient_aws() {
	client, err := secretone.NewClient(secretone.WithCredentials(credentials.UseAWS()))
	if err != nil {
		log.Fatal(err)
	}

	// use the client
	_, err = client.Secrets().ReadString("workspace/repo/secret")
	if err != nil {
		log.Fatal(err)
	}
}

// Create a new repository.
func ExampleClient_Repos_create() {
	_, err := client.Repos().Create("workspace/repo")
	if err != nil {
		log.Fatal(err)
	}
}

// Create a new directory.
func ExampleClient_Dirs_create() {
	_, err := client.Dirs().Create("workspace/repo/dir")
	if err != nil {
		log.Fatal(err)
	}
}

// List all audit events for a given repository.
func ExampleClient_Repos_eventIterator() {
	iter := client.Repos().EventIterator("workspace/repo", &secretone.AuditEventIteratorParams{})
	for {
		event, err := iter.Next()
		if err == iterator.Done {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Audit event logged at:%s form ip address: %s", event.LoggedAt.Local(), event.IPAddress)
	}
}

// Write a secret.
func ExampleClient_Secrets_write() {
	secret := []byte("secret_value_123")
	_, err := client.Secrets().Write("workspace/repo/secret", secret)
	if err != nil {
		log.Fatal(err)
	}
}

// Read a secret.
func ExampleClient_Secrets_read() {
	secret, err := client.Secrets().Read("workspace/repo/secret")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(string(secret.Data))
}

// List all audit events for a given secret.
func ExampleClient_Secrets_eventIterator() {
	iter := client.Secrets().EventIterator("workspace/repo/secret", &secretone.AuditEventIteratorParams{})
	for {
		event, err := iter.Next()
		if err == iterator.Done {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Audit event logged at:%s form ip address: %s", event.LoggedAt.Local(), event.IPAddress)
	}
}

// Create a service account credential.
func ExampleClient_Services_create() {
	credentialCreator := credentials.CreateKey()
	service, err := client.Services().Create("workspace/repo", "Service account description", credentialCreator)
	if err != nil {
		log.Fatal(err)
	}

	key, err := credentialCreator.Export()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Service ID: %s\n", service.ServiceID)
	fmt.Printf("Credential: %s\n", string(key))
}
