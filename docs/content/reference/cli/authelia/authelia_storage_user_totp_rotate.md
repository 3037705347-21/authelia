---
title: "authelia storage user totp rotate"
description: "Reference for the authelia storage user totp rotate command."
lead: ""
date: 2026-09-27T14:52:21+10:00
draft: false
images: []
weight: 905
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

## authelia storage user totp rotate

Perform rotation of the TOTP configurations listed in a roster

### Synopsis

Perform rotation of the TOTP configurations listed in a roster.

This subcommand allows reconciling the TOTP configurations in the database with the new configurations listed in the
roster file. For each listed user the configuration is replaced and the used TOTP step history is retired in a single
transaction so the new configuration starts with a clean replay window. Users not listed in the roster are not
modified. Users whose stored configuration already matches the roster are skipped, which makes repeated executions
idempotent and allows interrupted executions to be resumed. The format is determined by the extension of the file;
'.toml' is read as TOML, '.json' as JSON, and anything else as YAML.

```
authelia storage user totp rotate <filename> [flags]
```

### Examples

```
authelia storage user totp rotate authelia.roster.totp.yml
authelia storage user totp rotate --config config.yml authelia.roster.totp.yml
authelia storage user totp rotate --encryption-key b3453fde-ecc2-4a1f-9422-2707ddbed495 --postgres.address tcp://postgres:5432 --postgres.password autheliapw authelia.roster.totp.yml
```

### Options

```
  -h, --help   help for rotate
```

### Options inherited from parent commands

```
  -c, --config strings                                   configuration files or directories to load, for more information run 'authelia -h authelia config' (default [configuration.yml])
      --config.filters strings                           list of filters to apply to all configuration files, for more information run 'authelia -h authelia filters'
      --config.filters.template.delimiter.left string    sets the left delimiter for the 'template' filter
      --config.filters.template.delimiter.right string   sets the right delimiter for the 'template' filter
      --config.filters.values strings                    file paths of values files (.yml, .yaml, .json, .toml) to utilize with configuration file filters; files are loaded in order with later files deep-merged on top, for more information run 'authelia -h authelia filters'
      --encryption-key string                            the storage encryption key to use
      --mysql.address string                             the MySQL server address (default "tcp://127.0.0.1:3306")
      --mysql.database string                            the MySQL database name (default "authelia")
      --mysql.password string                            the MySQL password
      --mysql.username string                            the MySQL username (default "authelia")
      --postgres.address string                          the PostgreSQL server address (default "tcp://127.0.0.1:5432")
      --postgres.database string                         the PostgreSQL database name (default "authelia")
      --postgres.password string                         the PostgreSQL password
      --postgres.schema string                           the PostgreSQL schema name (default "public")
      --postgres.username string                         the PostgreSQL username (default "authelia")
      --sqlite.path string                               the SQLite database path
```

### SEE ALSO

* [authelia storage user totp](authelia_storage_user_totp.md)	 - Manage TOTP configurations

