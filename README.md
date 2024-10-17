# gotinca

A simple tool to create a Certificate Authority (CA) and derive server and client certificates for your home network. 

Inspired by tools such as [easyrsa](https://github.com/OpenVPN/easy-rsa) and [TinyCA](https://github.com/lechgu/tinyca), _gotinca_ fills a gap by providing an easy way to quickly create certificates for home network applications. Whether you're setting up a secure server, protecting internal communications, or ensuring safe client connections, _gotinca_ simplifies the process.

All output is in [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) format, ensuring compatibility with a wide range of software and systems.

Generated certificates can be outputted to stdout for direct use in scripts or applications. Any messages or errors will be sent to stderr.

## Usage

### Create a CA

Syntax: `gotinca ca <Common name> [Organization] [flags]`

This command initializes a new Certificate Authority. Use it to establish a root CA for your network.

```shell
gotinca ca "My main CA" "My house project" --output main-ca.pem --duration 20y 
```

### Create an intermediate CA

Create an intermediate CA, which can be useful for issuing certificates for different departments or services while keeping the root CA secure.

```shell
gotinca ca "Intermediate CA 2024" --ca main-ca.pem --output intermediate-ca.pem --duration 5y
```

### Create a server certificate

Syntax: `gotinca server <CA filename> <Domain/IPv4/IPv6> [Domain/IPv4/IPv6]... [flags]`

Generate server certificates for your applications.

```shell
gotinca server intermediate-ca.pem little.monster.internal blazkowicz.internal 192.168.0.1 --output server-cert.pem --duration 2y
```

### Create a client certificate

Syntax: `gotinca client <CA filename> <Common name> [flags]`

Issue client certificates to secure access to your services and authenticate users or devices.

```shell
gotinca client intermediate-ca.pem "Access to website little.monster.internal" --output client-cert.pem --duration 2y
```

## Useful links

* [shaneutt.com: Creating a Certificate Authority + Signing Certificates in Go](https://shaneutt.com/blog/golang-ca-and-signed-cert-go/)
