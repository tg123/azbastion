package main

import (
	"context"
	"reflect"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
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

func createCred(fixedtoken string, opts *azcore.ClientOptions) (azcore.TokenCredential, error) {
	var creds []azcore.TokenCredential

	// From azure sdk for go docs:
	//	  DisableInstanceDiscovery should be set true only by applications authenticating in
	//    disconnected clouds, or private clouds such as Azure Stack.
	disableInstanceDiscovery := false
	if !(reflect.DeepEqual(opts.Cloud, cloud.AzurePublic) || reflect.DeepEqual(opts.Cloud, cloud.AzureGovernment) || reflect.DeepEqual(opts.Cloud, cloud.AzureChina)) {
		disableInstanceDiscovery = true
	}

	// Add more credentials to the array here if needed
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
		interactiveOptions := azidentity.InteractiveBrowserCredentialOptions{
			ClientOptions:            *opts,
			DisableInstanceDiscovery: disableInstanceDiscovery,
		}
		cred, err := azidentity.NewInteractiveBrowserCredential(&interactiveOptions)
		if err == nil {
			creds = append(creds, cred)
		}
	}

	{
		deviceOptions := azidentity.DeviceCodeCredentialOptions{
			ClientOptions:            *opts,
			DisableInstanceDiscovery: disableInstanceDiscovery,
		}
		cred, err := azidentity.NewDeviceCodeCredential(&deviceOptions)
		if err == nil {
			creds = append(creds, cred)
		}
	}

	return azidentity.NewChainedTokenCredential(creds, nil)
}
