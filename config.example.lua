-- geoblock configuration
-- Copy this file to config.lua and customize for your environment

local config = {}

-------------------------------------------------------------------------------
-- WHITELIST: IPs that must NEVER be blocked
-- Add your own IPs, team members, partners, critical services
-------------------------------------------------------------------------------

config.ignore = {
    -- Your infrastructure (examples - replace with your own)
    ["192.168.1.1"] = true,      -- Example: gateway
    ["10.0.0.1"] = true,         -- Example: internal server

    -- Always ignore localhost
    ["::1"] = true,
    ["-"] = true,
}

-- Same IPs used for blocklist validation
-- checkblocks will error if any of these appear in zone files
config.whitelist = config.ignore

-------------------------------------------------------------------------------
-- ZONE PRESETS: Choose one or customize your own
-------------------------------------------------------------------------------

-- MINIMAL: High-risk countries only (recommended starting point)
local PRESET_MINIMAL = {
    "cn-aggregated.zone",   -- China
    "ru-aggregated.zone",   -- Russia
    "kp-aggregated.zone",   -- North Korea
    "ir-aggregated.zone",   -- Iran
    "custom.zone",
}

-- MODERATE: Common attack sources
local PRESET_MODERATE = {
    "cn-aggregated.zone",   -- China
    "ru-aggregated.zone",   -- Russia
    "kp-aggregated.zone",   -- North Korea
    "ir-aggregated.zone",   -- Iran
    "ua-aggregated.zone",   -- Ukraine
    "vn-aggregated.zone",   -- Vietnam
    "in-aggregated.zone",   -- India
    "br-aggregated.zone",   -- Brazil
    "pk-aggregated.zone",   -- Pakistan
    "id-aggregated.zone",   -- Indonesia
    "custom.zone",
}

-- AGGRESSIVE: Extended blocklist (may cause false positives)
local PRESET_AGGRESSIVE = {
    "cn-aggregated.zone",   -- China
    "ru-aggregated.zone",   -- Russia
    "kp-aggregated.zone",   -- North Korea
    "ir-aggregated.zone",   -- Iran
    "ua-aggregated.zone",   -- Ukraine
    "vn-aggregated.zone",   -- Vietnam
    "in-aggregated.zone",   -- India
    "br-aggregated.zone",   -- Brazil
    "pk-aggregated.zone",   -- Pakistan
    "id-aggregated.zone",   -- Indonesia
    "th-aggregated.zone",   -- Thailand
    "kr-aggregated.zone",   -- South Korea
    "tw-aggregated.zone",   -- Taiwan
    "ph-aggregated.zone",   -- Philippines
    "bd-aggregated.zone",   -- Bangladesh
    "eg-aggregated.zone",   -- Egypt
    "tr-aggregated.zone",   -- Turkey
    "mx-aggregated.zone",   -- Mexico
    "ar-aggregated.zone",   -- Argentina
    "co-aggregated.zone",   -- Colombia
    "custom.zone",
}

-- Select your preset (or define custom list below)
config.blockZones = PRESET_MINIMAL

-- CUSTOM: Uncomment and modify to create your own list
-- config.blockZones = {
--     "cn-aggregated.zone",
--     "ru-aggregated.zone",
--     -- Add more from: https://www.ipdeny.com/ipblocks/data/aggregated/
--     "custom.zone",
-- }

-------------------------------------------------------------------------------
-- EVENT LOG FILES (optional, for --parse-logs)
-- Place exported Windows Security event logs in EventLogXML/
-------------------------------------------------------------------------------

config.xmlFiles = {
    -- "ServerName.xml",
    -- "AnotherServer.xml",
}

return config
