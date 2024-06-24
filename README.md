The idea is very simple: sometimes you want to only allow access to certain clients.
One way to achieve this goal is to list all the names that should have access, allowing for wildcards.
The names themselves come from `subjectAltName` part of client's SSL certificate, specifically its DNS section.

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
                              "*.example.com"
                            ]
```
It should work the same without L4, as connection policies are a part of the caddy itself, not L4 module.

Disclaimer: I have no idea what I'm doing lol, but the code was simple enough to hack together.
