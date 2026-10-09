---
title: "authelia storage bans reconcile"
description: "Reference for the authelia storage bans reconcile command."
lead: ""
date: 2026-10-09T21:11:05+08:00
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

## authelia storage bans reconcile

Reconciles user and ip bans with a roster file

### Synopsis

Reconciles user and ip bans with a roster file.

This subcommand performs a declarative reconciliation of the user and ip bans with the entries listed in the roster
file. Entries listed in the roster are banned or have their ban renewed with the given expiry, entries which were
previously managed using this subcommand but are removed from the roster are explicitly revoked, and bans originating
from other sources such as automatic regulation are left untouched.

The reconciliation is performed atomically; if any error occurs no changes are made. Running this subcommand multiple
times with the same roster does not result in the bans oscillating.

```
authelia storage bans reconcile [flags]
```

### Examples

```
authelia storage bans reconcile --file bans.yml
authelia storage bans reconcile --file bans.yml --dry-run
authelia storage bans reconcile --file bans.yml --config config.yml
```

### Options

```
      --dry-run       computes and lists the changes without applying them
  -f, --file string   the path to the ban roster file to reconcile with
  -h, --help          help for reconcile
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

* [authelia storage bans](authelia_storage_bans.md)	 - Manages user and ip bans

