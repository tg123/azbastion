# Azure Bastion tunnel client

## Usage

```
bastion-tunnel --subscription <subscription id> --group <resource group> --name <bastion name> --target-addr <remote vm ip> --target-port <remote vm port> --local-port <local listening port>
```

## Limitation

You bastion must be Standard SKU and enable `Native client support` and `IP-based connection`
