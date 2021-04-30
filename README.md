# ct-scrutinize

ct-scrutinize is a set of tools extract intelligence from Certificate Transparency logs.

## Features

The objective is to have a minimal framework to extract intelligence and information out of the Certificate Transparency logs.

## Modules

- [ct](./bin/ct.py) - main module gathering the certstream and publishing the X.509 certificate in a Redis pub-sub channel
- [cert-writer](./bin/cert-writer.py) - writer module to store X.509 certificate on the file-system
- [ct-dns-resolver](./bin/ct-dns-resolver.py) - extract potential hostname from X.509 certificate and brute-force DNS resolution to gather specific DNS records

## Requirements

To use ct-scrutinize, the requirements are:

- Python 3.8 [REQUIREMENTS](REQUIREMENTS)
- A running [certstream](https://github.com/CaliDog/certstream-server) accessible server
- A redis server

## Ideas and contribution

ct-scrutinize is a playground for experimenting new ideas of gathering intelligence from CT logs. If you have any ideas or modules to contribute, don't hesitate to open an issue or make a pull-request.

