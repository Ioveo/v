# SERV00 Safe Project

This is a standalone SERV00 project folder. It includes source files, header files,
and a safe runtime wrapper so it can run independently from the original directory.

## Why this version is safer

- Uses explicit binary path (`./saia`) instead of stealth paths under `/tmp`
- Single-instance guard (PID + lock file)
- Centralized runtime state under `serv00-safe/runtime/`
- Controlled stop sequence (SIGTERM, then SIGKILL fallback)
- Persistent log file for troubleshooting

## Directory layout

- `./*.c` and `./saia.h`: compile sources
- `./saia-safe.sh`: process manager wrapper
- `./runtime/run/saia.pid`: active PID
- `./runtime/run/saia.lock`: startup lock
- `./runtime/logs/saia.log`: runtime logs

## Usage

One-click install (from remote):

```bash
curl -fsSL https://raw.githubusercontent.com/Ioveo/v/main/serv00-safe/install-serv00-safe.sh | bash
```

Build first:

```bash
cd ~/saia/serv00-safe/project
cc *.c -o saia -lpthread -lm -std=c11
chmod +x saia-safe.sh
```

Start (example):

```bash
./saia-safe.sh start --run-audit 3 1 1000 30
```

Open interactive menu on demand (no persistent menu process):

```bash
./saia-safe.sh menu
```

Status:

```bash
./saia-safe.sh status
```

Logs:

```bash
./saia-safe.sh logs
```

Stop:

```bash
./saia-safe.sh stop
```

Restart:

```bash
./saia-safe.sh restart --run-audit 3 1 1000 30
```

## Recommended SERV00 flow

1. Run stage-1 discover mode with your preferred concurrency.
2. Check logs and counters.
3. Switch to verify mode (if needed) with restart command.
4. Keep only one running instance managed by this script.
