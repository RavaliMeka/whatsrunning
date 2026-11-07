# whatsrunning

Go CLI that maps what runs on a Linux server (Docker containers, native listeners, volumes), flags risks, and writes a self-contained HTML map.

## Commands

```bash
go vet ./... && go test ./...                  # must pass before every commit
go build -o bin/whatsrunning ./cmd/whatsrunning
./bin/whatsrunning demo -o docs/index.html    # regenerate the live demo after UI changes
sudo ./bin/whatsrunning -v                    # scan this machine
```

## Layout

- `cmd/whatsrunning`: flags, output files, exit codes
- `internal/graph`: the shared model (nodes, edges); everything else reads or writes it
- `internal/collector/{docker,ports}`: data sources implementing `collector.Collector`
- `internal/scan`: runs collectors and merges results
- `internal/rules`: findings; one check per concern, each with a tested positive and negative case
- `internal/render`: terminal, JSON, and `map.html` (embedded; vanilla JS, no CDN)
- `internal/demo`: sample server used by `whatsrunning demo` and `docs/index.html`

## Rules

- Standard library only. Adding a dependency needs a strong reason.
- Never store environment variable values or unredacted command lines.
- Scanned strings reach the HTML only through the embedded JSON; insert them with `textContent` or `esc()`, never raw `innerHTML`.
- Do not load anything external in `map.html`; the CSP pins the script by hash and blocks network access.
- Report files are written through `writeFile` (0600, no symlinks).
- Comments explain why, not what. Keep functions small; delete dead code.
- Work on `main`. Commits are authored by RavaliMeka with no co-author trailers or tool attribution.
