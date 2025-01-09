# git-proxy

A GitHub HTTP proxy server written by go.

## Supported Domain

- `github.com`
- `raw.github.com`
- `raw.githubusercontent.com`
- `gist.github.com`

## Usage

### Start

```shell
Usage:
  git-proxy [flags]

Flags:
      --disable-color      disable color output
  -h, --help               help for git-proxy
  -p, --running-port int   disable color output (default 30000)
```

### URL scheme

`https://[username:password@]<your_domain>/<proxy_domain>/<path>`

## Installation

### Build

#### windows

`git clone https://github.com/PuerNya/git-proxy.git && cd git-proxy && go build -o git-proxy.exe -v -trimpath -ldflags "-s -w" main.go`

#### !windows

`git clone https://github.com/PuerNya/git-proxy.git && cd git-proxy && go build -o git-proxy -v -trimpath -ldflags "-s -w" main.go`

## Notes

- use `nginx` to add upgrade request to H2/H3