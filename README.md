# Jarvis

Anti-VPN and anti-bot protection for Minecraft servers.

This repository contains the Jarvis connector for three platforms:

- `velocity/`: Velocity proxy
- `bungee/`: BungeeCord proxy
- `paper/`: Paper / Spigot (single server)

The connector links your server to the Jarvis Guard service, which makes the anti-VPN and anti-bot decision at login, in real time, with no lag for legitimate players.

## What it blocks

- VPNs, proxies and datacenter connections
- Bot waves and automated account floods
- Ban evasion and alt / multi-accounts
- Account-takeover logins

## Setup

1. Download the connector for your platform from https://jarvisguard.com (or build it, see below).
2. Place the jar in your `plugins` folder and start the server.
3. Create a free account at https://jarvisguard.com and copy your license key.
4. Run `/antivpn key <your-key>`.

## Build

Each platform is an independent Maven project. From its folder:

```
mvn package
```

The jar is produced in `target/`. Requires JDK 21 or newer.

## Links

- Website: https://jarvisguard.com
- Status: https://jarvisguard.com/status

## License

Copyright JarvisAntiVPN. All rights reserved.
