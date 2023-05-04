package main

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/tg123/azkeyvault"
	"golang.org/x/crypto/ssh"
)

func keyFromKeyVault(credential azcore.TokenCredential, keyvaultUrl string, keyvaultKeyName string) (ssh.Signer, error) {

	keyClient, err := azkeys.NewClient(keyvaultUrl, credential, nil)
	if err != nil {
		return nil, err
	}

	certClient, err := azcertificates.NewClient(keyvaultUrl, credential, nil)
	if err != nil {
		return nil, err
	}

	kv, err := azkeyvault.NewSigner(keyClient, certClient, keyvaultKeyName, "")
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromSigner(kv)
}
