---
title: "authelia crypto rand"
description: "Reference for the authelia crypto rand command."
lead: ""
date: 2022-10-17T21:51:59+11:00
draft: false
images: []
menu:
  reference:
    parent: "cli-authelia"
weight: 330
toc: true
---

## authelia crypto rand

Generate a cryptographically secure random string

### Synopsis

Generate a cryptographically secure random string.

This subcommand allows generating cryptographically secure random strings for use for encryption keys, HMAC keys, etc.

```
authelia crypto rand [flags]
```

### Examples

```
authelia crypto rand --help
authelia crypto rand --length 80
authelia crypto rand -n 80
authelia crypto rand --charset alphanumeric
authelia crypto rand --charset alphabetic
authelia crypto rand --charset ascii
authelia crypto rand --charset numeric
authelia crypto rand --charset numeric-hex
authelia crypto rand --characters 0123456789ABCDEF
```

### Options

```
      --characters string   Sets the explicit characters for the random output
  -c, --charset string      Sets the charset for the output, options are 'ascii', 'alphanumeric', 'alphabetic', 'numeric', and 'numeric-hex' (default "alphanumeric")
  -h, --help                help for rand
  -n, --length int          Sets the length of the random output (default 80)
```

### SEE ALSO

* [authelia crypto](authelia_crypto.md)	 - Perform cryptographic operations

