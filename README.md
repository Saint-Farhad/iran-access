# Iran-Access Firewall (nftables)

A robust, high-performance automated script designed to restrict server inbound and outbound traffic exclusively to Iranian IP ranges in under 3 seconds using `nftables` and native Python address compilation.

## Features
- **Atomic Batch Load:** Injects ~4000 subnets instantly into nftables sets.
- **Zero-Dependency Installation:** Detects system package managers (`apt`, `dnf`, `yum`) and provisions dependencies automatically.
- **Persistence:** Configures a weekly `cron` job to fetch and update the IP database from IP2Location dynamically.

## One-Click Deployment

Execute the following command to download, install dependencies, schedule the auto-updater, and instantly isolate your server:

```bash
curl -sSL [https://github.com/Saint-Farhad/iran-access/raw/refs/heads/main/access-saz.sh](https://github.com/Saint-Farhad/iran-access/raw/refs/heads/main/access-saz.sh) -o access-saz.sh && chmod +x access-saz.sh && sudo ./access-saz.sh --install
