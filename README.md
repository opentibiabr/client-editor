# client-editor

## Usage

### Edit client

Edit or make a `config.toml` with all the URLs you want to change, there's an example one in `config.toml.dist`.

```bash
# Windows
.\client-editor.exe edit -t <tibia.exe location> -c config.toml

# Unix
./client-editor edit -t <tibia.exe location> -c config.toml
```

For a local client using [SlenderAAC](https://github.com/luan/slenderaac) you can use `local.toml` as a base.

```bash
# Windows
.\client-editor.exe edit -t <tibia.exe location> -c local.toml

# Unix
./client-editor edit -t <tibia.exe location> -c local.toml
```

The `edit` command also keeps the client-side `config.ini` in sync with the embedded INI block from the source client executable. The tool looks for the client default block starting at `[URLS]`, applies the TOML URL overrides that are also patched into the executable, writes to `conf/config.ini` when that client layout exists, and falls back to `config.ini` beside the executable otherwise. Existing comments and unknown sections are preserved. In sections managed by the embedded client config, outdated values are replaced, missing keys are appended, and obsolete keys that no longer exist in that client build are removed.

### Client-check safety

By default, `edit` applies known stable BattlEye patches and automatically neutralizes the client-check pair only when both paths pass structural verification before either path is changed. Verification requires unique normalized instruction shapes, exact RIP-relative `clientcheck_disconnected`, `error`, and `enableClientCheck` string targets, valid executable and writable PE sections, matching runtime-function boundaries from `.pdata`, consistent IAT/thunk relationships, and valid call targets. The final `clientcheck_disconnected` dispatch call and the `enableClientCheck` wrapper call are the only rewritten instructions.

Source SHA256 values and observed offsets are retained as audit evidence, but they are not runtime authorization requirements. A future client can therefore be patched automatically when addresses, relative displacements, or the client object field offset move while the full verified structure remains the same. If the compiler, Qt wrapper, function boundary, semantic target, candidate count, or paired relationship changes, normal mode fails closed and reports the evidence without rewriting either path. The ambiguous `75 0F E8 35 FF FF FF 48` branch signature is diagnostic-only because it also occurs in unrelated container code.

The edit command refuses to export only when strong unsupported client-check evidence remains. If the verdict is `PARTIAL` or `WARNING` but strong evidence is `none`, the export is allowed and the tool prints warnings for manual validation.

```bash
# Windows
.\client-editor.exe edit -t <new-client.exe> -c config.toml

# Unix
./client-editor edit -t <new-client> -c config.toml
```

Use `--strict` for CI, release scripts, or any workflow where `PARTIAL`, `WARNING`, or `UNSUPPORTED` support must stop the export:

```bash
# Windows
.\client-editor.exe edit -t <new-client.exe> -c config.toml --strict

# Unix
./client-editor edit -t <new-client> -c config.toml --strict
```

When a pristine executable is available, pass it with `--source-exe`. If omitted, `edit` automatically uses `client - original.exe` beside `--tibia-exe` when that file exists.

```bash
# Windows
.\client-editor.exe edit -t client.exe --source-exe "client - original.exe" -c local.toml

# Unix
./client-editor edit -t client --source-exe "client-original" -c local.toml
```

### Aggressive mode

`--aggressive` remains available for experimental compatibility work and keeps its prominent backup warning, but it does not bypass the structural verification required for the client-check pair. Legacy version-scoped high-risk masks are retained as diagnostic evidence only and cannot authorize a rewrite by themselves.

- `--aggressive=false`: default behavior; a uniquely verified structural pair is rewritten automatically, while incomplete or ambiguous evidence is only reported.
- `--aggressive=true`: uses the same structural gate for these two paths and prints the aggressive-mode backup warning.
- `--strict --aggressive`: still fails the export when the final diagnosis is unsafe, even after aggressive rewriting.

Every applied patch logs a before/after byte window covering the rewritten bytes. Re-running the editor accepts the structurally verified already-patched state without applying the instructions again.

```bash
# Windows
.\client-editor.exe edit -t client.exe --source-exe "client - original.exe" -c local.toml --aggressive

# Unix
./client-editor edit -t client --source-exe "client-original" -c local.toml --aggressive
```

### Diagnose client-check compatibility

Use `diagnose` to inspect a Tibia executable without modifying it. The report includes SHA256, file size, known BattlEye/client-check signature states, remaining client-check string indicators, nearby code references, and a support verdict.

The report separates weak indicators, suspicious active candidates, high-risk diagnostic-only signatures, and strong unsupported evidence. `BEClient` is treated as weak because it often appears in Qt metadata. Critical strings become strong evidence only when the code reference also has nearby branch/call evidence and no known patch signature close to that context.

Verdicts:

- `SUPPORTED`: all known patchable signatures are covered and no strong evidence remains.
- `PARTIAL`: only some known patchable signatures are covered.
- `WARNING`: a known patch is applied, but suspicious or high-risk diagnostic evidence still remains.
- `UNSUPPORTED`: strong client-check code evidence remains.

`diagnose --strict` exits with an error for `PARTIAL`, `WARNING`, or `UNSUPPORTED`; plain `diagnose` only reports.

```bash
# Windows
.\client-editor.exe diagnose -t <new-client.exe>

# Unix
./client-editor diagnose -t <new-client>
```

When running from a source checkout before building a binary, use `go run .` from the repository root:

```bash
# Windows
go run . diagnose -t <new-client.exe>

# Unix
go run . diagnose -t <new-client>
```

Use strict mode in CI or release scripts when diagnostics should fail if compatibility is partial, warning, or unsupported:

```bash
# Windows
.\client-editor.exe diagnose -t <new-client.exe> --strict

# Unix
./client-editor diagnose -t <new-client> --strict
```

For a useful old-vs-new comparison, pass a known-good older client with `--compare-with`:

```bash
# Windows, comparing original binaries before client-editor patches either file
.\client-editor.exe diagnose -t <new-original-client.exe> --compare-with <old-original-client.exe>

# Windows, same comparison through go run from the repository root
go run . diagnose -t <new-original-client.exe> --compare-with <old-original-client.exe>

# Windows, comparing already patched binaries after client-editor was run on both versions
.\client-editor.exe diagnose -t <new-patched-client.exe> --compare-with <old-patched-client.exe>

# Unix, comparing original binaries before client-editor patches either file
./client-editor diagnose -t <new-original-client> --compare-with <old-original-client>

# Unix, comparing already patched binaries after client-editor was run on both versions
./client-editor diagnose -t <new-patched-client> --compare-with <old-patched-client>
```

The old client does not have to be original, but both sides should be in the same state. Compare original-vs-original when deciding whether a new version is supported before editing. Compare patched-vs-patched when diagnosing why a new patched client still behaves differently from an older patched client that works.

### Repack client

Repack an existing tibia client for [use with slender-launcher](https://github.com/luan/slender-launcher). Repack requires a `client.<platform>.json` and `assets.<platform>.json` for each of the platforms you want to repack. Check out https://github.com/luan/tibia-client for an example.

```bash
# Windows
.\client-editor.exe repack -s <Tibia-windows folder> -d <tibia-client output folder> -p windows
.\client-editor.exe repack -s <Tibia-mac folder> -d <tibia-client output folder> -p mac
.\client-editor.exe repack -s <Tibia-linux folder> -d <tibia-client output folder> -p linux

# Unix
./client-editor repack -s ~/Games/Tibia-windows -d ~/src/tibia-client -p windows
./client-editor repack -s ~/Games/Tibia-mac -d ~/src/tibia-client -p mac
./client-editor repack -s ~/Games/Tibia-linux -d ~/src/tibia-client -p linux
```

### Editing appearances.dat

Sometimes all you want is make that one item house-wrappable. Or add use-with to something. But you don't want to have to load up asset editor since it's heavy and has a lot more features. You can use client-editor to edit appearances.dat directly.

```bash
# Windows
.\client-editor.exe appearances -a appearances.dat -c config.toml

# Unix
./client-editor appearances -a appearances.dat -c config.toml
```

It'll write a appearances.out.dat file with the changes. You can then copy that over to your client and to the canary `data/items/` folder to have your changes applied.

### Compiled Releases (Windows/Mac/Linux)

https://github.com/opentibiabr/client-editor/releases

### How to Compile

Requirements: golang 1.8+

```bash
$ make build
```
