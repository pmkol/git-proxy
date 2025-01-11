# git-proxy

A GitHub HTTP proxy server written by go.

## Usage

### Start

```shell
Usage:
  git-proxy [flags]

Flags:
  -l, --bandwidth-limit int       set total bandwidth limit (MB/s), 0 as no limit (default 0)
  -b, --blacklist-path string     set repository blacklist (default "blacklist.txt")
      --disable-color             disable color output
  -d, --domain-list-path string   set accept domain (default "domainlist.txt")
  -h, --help                      help for git-proxy
  -p, --running-port int          disable color output (default 30000)

```

### URL scheme

`https://<your_domain>/<github_request_url>`

#### example

`https://abc.com/https://github.com/github/docs.git`

## Installation

### Build

#### windows

`git clone https://github.com/PuerNya/git-proxy.git && cd git-proxy && go build -o git-proxy.exe -v -trimpath -ldflags "-s -w" main.go`

#### !windows

`git clone https://github.com/PuerNya/git-proxy.git && cd git-proxy && go build -o git-proxy -v -trimpath -ldflags "-s -w" main.go`

## Features

### Repository blacklist

Block repositories in blacklist.

#### Struct

`<user>/<repo>`

- Wildcard characters `*` `?` are supported
- Blank user/repo will be parsed as `*`
```text
examples:

    `/abcd` => User: "*", Repo: "abcd"
    `abcd/` => User: "abcd", Repo: "*"
```

### Accept domain list

Accept requests whose url host is in the list.

#### Default list

- `github.com`
- `raw.github.com`
- `raw.githubusercontent.com`
- `gist.github.com`
- `objects.githubusercontent.com`
- `gist.githubusercontent.com`
- `codeload.github.com`
- `api.github.com`

## Notes

- use `nginx` to add upgrade request to H2/H3