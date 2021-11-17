# GlobalProtect VPN Helper

This tool is a CLI friendly tool used to perform POST based SAML authentication for GlobalProtect VPN. It displays a browser window to allow you to enter your credentials and perform the full SAML flow. When complete
it gives an openconnect compatible cookie, ready to be used.

## Usage

This tool is intended to be used before openconnect to get the authentication cookie, like so:

```bash
COOKIE=$(./vpn -gateway dublin-1.vpn.company.com)
echo $COOKIE | sudo openconnect --protocol=gp --cookie-on-stdin dublin-1.vpn.company.com
```

## Requirements

- OpenConnect 8+
- Google Chrome 70+

## Limitations

The tool works at the gateway level. It means that it specifically connects to a specific gateway from your VPN provider, instead of connected to the global portal which allows the selection of the gateway - and even dynamic switching sometimes.

It also works only for POST based SAML authentication.

## Known bugs

- Sometimes, if you close the browser window, the executable won't exit properly.
