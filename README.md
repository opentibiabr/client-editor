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

### Repack client

Repack an existing tibia client for [use with slender-launcher](https://github.com/luan/slender-launcher). Repack requires a `client.<platform>.json` and `assets.<platform>.json` for each of the platforms you want to repack. Check out https://github.com/luan/tibia-client for an example.

```bash
# Windows
.\client-editor.exe repack -s C:\Games\Tibia-windows -d C:\Users\YourName\src\tibia-client -p windows
.\client-editor.exe repack -s C:\Games\Tibia-mac -d C:\Users\YourName\src\tibia-client -p mac
.\client-editor.exe repack -s C:\Games\Tibia-linux -d C:\Users\YourName\src\tibia-client -p linux

# Unix
./client-editor repack -s ~/Games/Tibia-windows -d ~/src/tibia-client -p windows
./client-editor repack -s ~/Games/Tibia-mac -d ~/src/tibia-client -p mac
./client-editor repack -s ~/Games/Tibia-linux -d ~/src/tibia-client -p linux
```

### Compiled Releases (Windows/Mac/Linux)

https://github.com/opentibiabr/client-editor/releases

### How to Compile

Requirements: golang 1.8+

```bash
$ make build
```
