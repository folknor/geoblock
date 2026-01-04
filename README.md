# geoblock - Geolocation-based IP Blocking

Block traffic from specified countries using Windows Firewall, with event log analysis to detect unauthorized login attempts.

## Quick Start

```bash
# 1. Configure
cp config.example.lua config.lua
# Edit config.lua: add your whitelist IPs, choose a zone preset

# 2. Download blocklists and validate
lua scan.lua --validate

# 3. Apply firewall rules (Windows, as Administrator)
powershell -Command "Set-ExecutionPolicy Bypass; .\Recurse.ps1; Set-ExecutionPolicy Restricted"
```

## Usage

```
lua scan.lua [options]

Options:
  --update          Update zone files from ipdeny.com (default)
  --validate        Validate whitelist IPs aren't in blocklists
  --parse-logs      Parse Windows event log XML files
  --all             Run update + validate + parse-logs
  --help            Show help
```

**Examples:**
```bash
lua scan.lua                 # Just update zones
lua scan.lua --validate      # Update + check whitelist
lua scan.lua --all           # Full workflow
```

## Configuration

Copy `config.example.lua` to `config.lua`. The example includes three presets:

| Preset | Countries | Use Case |
|--------|-----------|----------|
| `PRESET_MINIMAL` | CN, RU, KP, IR | Low false-positive risk |
| `PRESET_MODERATE` | +UA, VN, IN, BR, PK, ID | Balanced |
| `PRESET_AGGRESSIVE` | +20 more countries | Maximum blocking |

```lua
-- config.lua
config.whitelist = {
    ["your.server.ip"] = true,
    ["teammate.ip"] = true,
}
config.blockZones = PRESET_MINIMAL  -- or PRESET_MODERATE, PRESET_AGGRESSIVE
```

## Firewall Deployment (Windows)

**Apply all zones:**
```powershell
Set-ExecutionPolicy Bypass
.\Recurse.ps1
Set-ExecutionPolicy Restricted
```

**Apply single zone:**
```powershell
.\Import-Firewall-Blocklist.ps1 -InputFile Zones\cn-aggregated.zone
```

**Remove rules:**
```powershell
.\Import-Firewall-Blocklist.ps1 -InputFile Zones\cn-aggregated.zone -DeleteOnly
```

## Event Log Analysis (Optional)

1. Export Windows Security logs (Event ID 4625) as XML to `EventLogXML/`
2. Add filenames to `config.xmlFiles`
3. Run `lua scan.lua --parse-logs`
4. Re-run `--validate` to find unblocked attackers

## Dependencies

**Lua scripts:**
- Lua 5.2+ with `bit32`
- [LuaFileSystem](https://keplerproject.github.io/luafilesystem/) (lfs)
- [serpent](https://github.com/pkulchenko/serpent)
- [xml2lua](https://github.com/manoelcampos/xml2lua) (only for --parse-logs)
- `curl` (system)

**Install via LuaRocks:**
```bash
luarocks install luafilesystem
luarocks install serpent
luarocks install xml2lua  # optional
```

## Files

```
├── config.example.lua      # Template (copy to config.lua)
├── config.lua              # Your config (gitignored)
├── scan.lua                # Main tool
├── checkblocks.lua         # Standalone validator (optional)
├── iputils.lua             # CIDR library
├── Import-Firewall-Blocklist.ps1
├── Recurse.ps1
├── Zones/                  # Downloaded blocklists (gitignored)
├── EventLogXML/            # Your event logs (gitignored)
└── Logins/                 # Parsed results (gitignored)
```

## Zone Sources

- IPv4: https://www.ipdeny.com/ipblocks/data/aggregated/
- IPv6: https://www.ipdeny.com/ipv6/ipaddresses/aggregated/

## License

Public domain (PowerShell), MIT (iputils.lua)
