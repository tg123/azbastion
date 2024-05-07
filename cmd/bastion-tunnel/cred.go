package main

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

var _ azcore.TokenCredential = &staticTokenCredential{}

type staticTokenCredential struct {
	token string
}

func (s *staticTokenCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     s.token,
		ExpiresOn: time.Now().Add(time.Hour),
	}, nil
}

func createCred(fixedtoken string) (azcore.TokenCredential, error) {
	// test change
	var creds []azcore.TokenCredential

	{
		if fixedtoken != "" {
			creds = append(creds, &staticTokenCredential{fixedtoken})
		}
	}

	{
		cred, err := azidentity.NewAzureCLICredential(nil)
		if err == nil {
			creds = append(creds, cred)
		}
	}

	{

		cred, err := azidentity.NewInteractiveBrowserCredential(nil)
		if err == nil {
			creds = append(creds, cred)
		}
	}

	{
		cred, err := azidentity.NewDeviceCodeCredential(nil)
		if err == nil {
			creds = append(creds, cred)
		}
	}

	return azidentity.NewChainedTokenCredential(creds, nil)
}
