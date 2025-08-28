The idea is very simple: sometimes you want to only allow access to certain clients.
One way to achieve this goal is to list all the names that should have access, allowing for wildcards and regexps.
The names themselves come from `subjectAltName` part of client's SSL certificate, specifically its DNS section.

If a name starts and ends with a slash, it's treated as a go's RE2 regexp. Be careful to not accidentally match
more than you should. Otherwise, if it contains an astrisk, it's treated as a hostname wildcard. Otherwise,
it has to match exactly.

You may want to control the trusted CA list explicitly to reduce the risk of accepting a client with a certificate
that has been obtained under circumstances you wouldn't necessarily deem ideal.

Here's the sample config (only relevant parts):

```json
{
  "apps": {
    "layer4": {
      "servers": {
        "servername": {
          "routes": [
            {
              "handle": [
                {
                  "handler": "tls",
                  "connection_policies": [
                    {
                      "client_authentication": {
                        "mode": "require_and_verify",
                        "verifiers": [
                          {
                            "verifier": "san_dns",
                            "names": [
                              "hostname.domain.tld",
                              "*.example.com",
                              "/^container-.*\\.localhost$/"
                            ]
```

And as Caddyfile configuration
```
tls {
    trust_pool http {
        endpoints https://some.endpoint.tld:443/root.pem
    }
    client_auth {
        mode require_and_verify
        verifier san_dns {
            names [ "hostname.domain.tld", "*.example.com", "/^container-.*\\.localhost$/" ]
        }
    }
}
```

It should work the same without L4, as connection policies are a part of the caddy itself, not L4 module.

Disclaimer: the code was simple enough to hack together, and it works for me so far, but in no way I'm an expert in go.
