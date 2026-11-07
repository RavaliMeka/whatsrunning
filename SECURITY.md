# Security

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue.

Include the version (`whatsrunning version`), what you ran, and what happened. You can expect an acknowledgement within 3 working days and a fix or a mitigation plan within 30 days. Only the latest release receives security fixes.

## Threat model

whatsrunning usually runs as root on production servers, and its report describes that server's attack surface. The design follows from that.

| Asset or risk | Mitigation |
|---|---|
| Secrets in container environments | Values are never stored. Names are kept; values are scanned in memory for container hostnames and then dropped. |
| Secrets in process command lines | `password`, `secret`, `token` and `key` arguments and `user:pass@` URL credentials are redacted before the 200-character truncation. |
| Report readable by other users | HTML and JSON reports are created with mode `0600`, and existing files are reset to `0600`. |
| Symlink attack on the output path (root writing into a shared directory) | Output is opened with `O_NOFOLLOW`, so a planted symlink makes the run fail instead of overwriting its target. |
| Script injection through container names, labels, image names or hostnames | Scanned values enter the page only as JSON (`<`, `>` and `&` escaped) and are inserted with `textContent` or an escaping helper. The page's Content-Security-Policy allows exactly one script, pinned by its SHA-256 hash. |
| Report leaking data when opened | The CSP is `default-src 'none'`: no network requests, images, fonts or frames. No referrer is sent. |
| Hostile Docker API responses | Responses are size-limited and parsed into fixed structs; requests time out after 20 seconds. |
| Network exposure of the tool | It opens no listening sockets. A local scan makes no network connections; it only talks to the local Docker unix socket. |
| SSH targets used as options (`-oProxyCommand=...`) | Targets must match a strict host pattern and are passed after `--`. The remote script is a constant; no user input is interpolated into it. |
| SSH trust | The system `ssh` client runs with `BatchMode=yes`, so the user's `known_hosts` and host key checking apply and nothing prompts for a password. |
| Binary left on a server | It is written with `umask 077` to a `mktemp` file in the remote user's home and removed by an `EXIT` trap, also on failure. |
| Hostile server output | Each server's result is size-limited, parsed as data, and rendered through the same escaping and CSP as local results. |
| nginx configs | Read-only, at most 256 files of 1 MiB each, with bounded `include` depth so loops terminate. |
| Supply chain | Standard library only, no third-party Go modules. CI actions are pinned to commit SHAs, workflows default to read-only tokens, and every push runs `govulncheck`. Releases are built with the latest stable Go and ship a `checksums.txt`. |

## Scanner notes

`gosec` reports G304 (file path from a variable) in four places and G204 (subprocess with a variable) once. These are intended:

- `internal/collector/ports`: reading `/proc/net/tcp*` and `/proc/<pid>/{comm,cmdline,cgroup,net/tcp*}`. Paths are built from `/proc` and a numeric PID.
- `internal/nginx`: reading nginx configs from `/etc/nginx` or from an nginx container's bind mounts as reported by Docker.
- `internal/remote`: running `ssh` with the target the user passed to `-ssh`, validated as described above.
- `cmd/whatsrunning`: writing the report to the path the user passed with `-o` or `-json`, with the protections above.

## Running with least privilege

Root is only needed to name processes owned by other users. Membership of the `docker` group is enough for the Docker view (`-no-ports` skips `/proc`). The `docker` group is itself root-equivalent, so grant it deliberately.
