# SERV00 Safe Runtime

This folder provides a safer and more stable runtime wrapper for SERV00.

## Why this version is safer

- Uses explicit binary path (`./saia`) instead of stealth paths under `/tmp`
- Single-instance guard (PID + lock file)
- Centralized runtime state under `serv00-safe/runtime/`
- Controlled stop sequence (SIGTERM, then SIGKILL fallback)
- Persistent log file for troubleshooting

## Directory layout

- `serv00-safe/saia-safe.sh`: process manager wrapper
- `serv00-safe/runtime/run/saia.pid`: active PID
- `serv00-safe/runtime/run/saia.lock`: startup lock
- `serv00-safe/runtime/logs/saia.log`: runtime logs

## Usage

Build first:

```bash
cd ~/saia
cc *.c -o saia -lpthread -lm -std=c11
chmod +x serv00-safe/saia-safe.sh
```

Start (example):

```bash
./serv00-safe/saia-safe.sh start --run-audit 3 1 1000 30
```

Status:

```bash
./serv00-safe/saia-safe.sh status
```

Logs:

```bash
./serv00-safe/saia-safe.sh logs
```

Stop:

```bash
./serv00-safe/saia-safe.sh stop
```

Restart:

```bash
./serv00-safe/saia-safe.sh restart --run-audit 3 1 1000 30
```

## Recommended SERV00 flow

1. Run stage-1 discover mode with your preferred concurrency.
2. Check logs and counters.
3. Switch to verify mode (if needed) with restart command.
4. Keep only one running instance managed by this script.
