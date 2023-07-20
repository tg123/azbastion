# Azure Bastion tunnel client

## Basic Usage

```
bastion-tunnel --subscription <subscription id> --group <resource group> --name <bastion name> --target-addr <remote vm ip> --target-port <remote vm port> --local-port <local listening port>
```

## Advanced: Use a non-exportable ssh key in azure key vault

Traditional SSH client key-authenticatio requires a `PRIVATE` key at client side to establish connection to ssh server. 
Nonetheless, sharing the private key poses a significant security risk. Even placing the key in a key vault as a secret does not mitigate this risk, as individuals might still retain a local copy of the key despite their access to the key vault being revoked.

Conversely, the `bastion-tunnel` approach allows the utilization of a non-exportable RSA key stored in the key vault to authenticate with the ssh server located behind the bastion. This implementation significantly enhances the security level of the bastion, further safeguarding sensitive access.

### Generate Key 

 * Azure Portal
   ![image](https://github.com/tg123/azbastion/assets/170430/a4020256-69e4-49e1-884a-3d7c0c115006)

 * Powershell

   `Add-AzKeyVaultKey -VaultName <keyvaultname> -Name <keyname> -Destination Software -KeyType RSA`

### Connection sshd behind bastion using the key

```
bastion-tunnel --subscription <subscription id> --group <resource group> --name <bastion name> --target-addr <remote vm ip> --run-ssh --ssh-user <sshusername> --ssh-keyvault-url "https://<keyvaultname>.vault.azure.net" --ssh-keyvault-keyname <key_generated>
```  


## Limitation

You bastion must be Standard SKU and enable `Native client support` and `IP-based connection`
