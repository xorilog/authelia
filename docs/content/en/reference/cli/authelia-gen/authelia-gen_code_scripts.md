---
title: "authelia-gen code scripts"
description: "Reference for the authelia-gen code scripts command."
lead: ""
date: 2022-09-16T14:21:05+10:00
draft: false
images: []
menu:
  reference:
    parent: "cli-authelia-gen"
weight: 330
toc: true
---

## authelia-gen code scripts

Generate the generated portion of the authelia-scripts command

```
authelia-gen code scripts [flags]
```

### Options

```
  -h, --help   help for scripts
```

### Options inherited from parent commands

```
  -C, --cwd string                               Sets the CWD for git commands
      --dir.docs.cli-reference string            The directory to store the markdown in (default "docs/content/en/reference/cli")
      --dir.docs.content string                  The directory with the docs content (default "docs/content")
      --dir.locales string                       The locales directory in relation to the root (default "internal/server/locales")
  -d, --dir.root string                          The repository root (default "./")
  -X, --exclude strings                          Sets the names of excluded generators
      --file.bug-report string                   Sets the path of the bug report issue template file (default ".github/ISSUE_TEMPLATE/bug-report.yml")
      --file.commit-lint-config string           The commit lint javascript configuration file in relation to the root (default "web/.commitlintrc.js")
      --file.configuration-keys string           Sets the path of the keys file (default "internal/configuration/schema/keys.go")
      --file.docs-commit-msg-guidelines string   The commit message guidelines documentation file in relation to the root (default "docs/content/en/contributing/guidelines/commit-message.md")
      --file.docs-keys string                    Sets the path of the docs keys file (default "docs/data/configkeys.json")
      --file.docs.data.languages string          The languages docs data file in relation to the docs data folder (default "docs/data/languages.json")
      --file.feature-request string              Sets the path of the feature request issue template file (default ".github/ISSUE_TEMPLATE/feature-request.yml")
      --file.scripts.gen string                  Sets the path of the authelia-scripts gen file (default "cmd/authelia-scripts/cmd/gen.go")
      --file.web-i18n string                     The i18n typescript configuration file in relation to the root (default "web/src/i18n/index.ts")
      --package.configuration.keys string        Sets the package name of the keys file (default "schema")
      --package.scripts.gen string               Sets the package name of the authelia-scripts gen file (default "cmd")
      --versions int                             the maximum number of minor versions to list in output templates (default 5)
```

### SEE ALSO

* [authelia-gen code](authelia-gen_code.md)	 - Generate code

