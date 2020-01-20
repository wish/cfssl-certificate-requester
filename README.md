# cfssl-certificate-requester
A self-contained tool for getting signed certificates and their bundles from our
[cfssl](https://github.com/cloudflare/cfssl)-based PKI.

## How to build this

```bash
$ git clone git@github.com:wish/cfssl-certificate-requester.git
$ cd cfssl-certificate-requester
$ go install github.com/wish/cfssl-certificate-requester
```

## Sample usage

Assuming a cfssl server is running at `http://127.0.0.1:9999/` and a PEM-encoded
CSR file has already been generated:

    cfssl-certificate-requester --csr-file=~/cfssl/tier-3-ca/ca.csr --cfssl-server=127.0.0.1:9999
