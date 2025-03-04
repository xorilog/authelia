---
title: "authelia crypto hash generate sha2crypt"
description: "Reference for the authelia crypto hash generate sha2crypt command."
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

## authelia crypto hash generate sha2crypt

Generate cryptographic SHA2 Crypt hash digests

### Synopsis

Generate cryptographic SHA2 Crypt hash digests.

This subcommand allows generating cryptographic SHA2 Crypt hash digests.

```
authelia crypto hash generate sha2crypt [flags]
```

### Examples

```
authelia crypto hash generate sha2crypt --help
```

### Options

```
  -c, --config strings      configuration files to load (default [configuration.yml])
  -h, --help                help for sha2crypt
  -i, --iterations int      number of iterations (default 50000)
      --no-confirm          skip the password confirmation prompt
      --password string     manually supply the password rather than using the terminal prompt
      --random              uses a randomly generated password
      --random.length int   when using a randomly generated password it configures the length (default 72)
  -s, --salt-size int       salt size in bytes (default 16)
  -v, --variant string      variant, options are sha256 and sha512 (default "sha512")
```

### SEE ALSO

* [authelia crypto hash generate](authelia_crypto_hash_generate.md)	 - Generate cryptographic hash digests

