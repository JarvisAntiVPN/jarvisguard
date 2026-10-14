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

1. Download the official connector for your platform from https://jarvisguard.com.
2. Place the jar in your `plugins` folder and start the server.
3. The console shows a link to connect the server. Open it, sign in (or create your
   free account) and confirm: no key to paste. `/antivpn link` shows the link again.
4. Or, if you already have your license key, run `/antivpn key <your-key>`.

## Why this code is public

So you can read exactly what runs on your server and what data leaves it. That is the
only reason it is here. It is not a licence to reuse it: see LICENSE.

## Build it yourself to check it

Each platform is an independent Maven project. From its folder:

```
mvn package
```

The jar is produced in `target/`. Requires JDK 17 or newer, for all three modules.

Building is for auditing: compare what you get with the official jar, or just read the
code. Compare the bytecode (`javap -c -p` on each class), not the raw bytes: the classes
match instruction for instruction, and only the debug line numbers differ, because this
tree is laid out differently. The default config.yml in the official jar also carries
setup notes that are not in this tree. On your server, run the official build from
https://jarvisguard.com, so that support and updates match what we ship.

## Links

- Website: https://jarvisguard.com
- Status: https://jarvisguard.com/status

## License

Copyright JarvisAntiVPN. All rights reserved.
