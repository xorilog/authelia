---
title: "authelia crypto hash generate pbkdf2"
description: "Reference for the authelia crypto hash generate pbkdf2 command."
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

## authelia crypto hash generate pbkdf2

Generate cryptographic PBKDF2 hash digests

### Synopsis

Generate cryptographic PBKDF2 hash digests.

This subcommand allows generating cryptographic PBKDF2 hash digests.

```
authelia crypto hash generate pbkdf2 [flags]
```

### Examples

```
authelia crypto hash generate pbkdf2 --help
```

### Options

```
  -c, --config strings      configuration files to load (default [configuration.yml])
  -h, --help                help for pbkdf2
  -i, --iterations int      number of iterations (default 310000)
      --no-confirm          skip the password confirmation prompt
      --password string     manually supply the password rather than using the terminal prompt
      --random              uses a randomly generated password
      --random.length int   when using a randomly generated password it configures the length (default 72)
  -s, --salt-size int       salt size in bytes (default 16)
  -v, --variant string      variant, options are 'sha1', 'sha224', 'sha256', 'sha384', and 'sha512' (default "sha512")
```

### SEE ALSO

* [authelia crypto hash generate](authelia_crypto_hash_generate.md)	 - Generate cryptographic hash digests

