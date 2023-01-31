# Crypto Package

This package contains intermediate layers cryptographic functions.

By intermediate layers, I mean that they are convenience wrappers
around Go standard library, 
but that they only handle the (symmetric) cryptographic abstractions 
of HORNET (PRG, PRP, ENC, DEC, MAC, ...).
Onion encryption is not from this package.

Notably, if Sphinx is reimplemented from scratch, 
its asymmetric cryptography abstraction should also go in this package. 
But as I currently reuse go-sphinxmixcrypto, it does not.
