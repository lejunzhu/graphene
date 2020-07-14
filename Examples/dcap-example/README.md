# SGX DCAP

This directory contains the sample code to perform SGX ECDSA remote attestation
in Graphene SGX, both the quote generation and verification. It is tested with
Intel SGX DCAP 1.6 release on Ubuntu 18.04.

# Quick Start

This example only works with SGX. It also requires DCAP software installed on
the host. To run the regression test, execute:
```
make SGX=1 check
```
