---
title: "authelia crypto hash generate scrypt"
description: "Reference for the authelia crypto hash generate scrypt command."
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

## authelia crypto hash generate scrypt

Generate cryptographic scrypt hash digests

### Synopsis

Generate cryptographic scrypt hash digests.

This subcommand allows generating cryptographic scrypt hash digests.

```
authelia crypto hash generate scrypt [flags]
```

### Examples

```
authelia crypto hash generate scrypt --help
```

### Options

```
  -r, --block-size int      block size (default 8)
  -c, --config strings      configuration files to load (default [configuration.yml])
  -h, --help                help for scrypt
  -i, --iterations int      number of iterations (default 16)
  -k, --key-size int        key size in bytes (default 32)
      --no-confirm          skip the password confirmation prompt
  -p, --parallelism int     parallelism or threads (default 1)
      --password string     manually supply the password rather than using the terminal prompt
      --random              uses a randomly generated password
      --random.length int   when using a randomly generated password it configures the length (default 72)
  -s, --salt-size int       salt size in bytes (default 16)
```

### SEE ALSO

* [authelia crypto hash generate](authelia_crypto_hash_generate.md)	 - Generate cryptographic hash digests

