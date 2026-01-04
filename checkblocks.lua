#!/usr/bin/lua

--[[
Validates that:
1. Whitelisted IPs are NOT in any blocklist (prevents blocking friendly IPs)
2. Known attack IPs from event logs ARE in blocklists (identifies gaps)
]]

local function helpExit(err)
    if err then
        print("Error: " .. tostring(err))
    end
    print([[
geoblock validator

Usage: lua checkblocks.lua

Validates whitelist IPs against zone files and checks that
detected attack IPs are properly blocked.

Requires config.lua with 'whitelist' and 'blockZones' defined.
]])
    os.exit(err and 1 or 0)
end

-------------------------------------------------------------------------------
-- LOAD CONFIG
--

local configOk, config = pcall(require, "config")
if not configOk then
    helpExit("Could not load config.lua. Copy config.example.lua to config.lua and customize it.")
end

local cantBeIn = config.whitelist or {}
local blockland = config.blockZones or {}

if not next(cantBeIn) then
    print("Warning: No whitelist IPs defined in config.lua")
end

if not next(blockland) then
    helpExit("No blockZones defined in config.lua")
end

-------------------------------------------------------------------------------

local iputils = require("iputils")
local BLOCK_FOLDER = "Zones/"

local s = require("serpent")
local lfs = require("lfs")
local zones = {}
local tinsert = table.insert

print("Loading zone files...")
for _, zone in next, blockland do
    local f = io.open(BLOCK_FOLDER .. zone, "r")
    if f then
        local content = f:read("*a")
        f:close()
        zones[zone] = {}
        for w in content:gmatch("([^\n]+)") do
            -- Skip comments and empty lines
            if not w:match("^%s*#") and w:match("%S") then
                tinsert(zones[zone], w)
            end
        end
        print(("  %s: %d ranges"):format(zone, #zones[zone]))
    else
        print("  Warning: Could not open " .. zone)
    end
end

print("\nParsing CIDR ranges...")
local parsed = {}
for _, zone in next, blockland do
    if zones[zone] then
        parsed[zone] = iputils.parse_cidrs(zones[zone])
    end
end

-------------------------------------------------------------------------------
-- CHECK WHITELIST
--

print("\nValidating whitelist IPs are not in any blocklist...")
local whitelistOk = true

for ip in pairs(cantBeIn) do
    for _, zone in next, blockland do
        if parsed[zone] then
            local present = iputils.ip_in_cidrs(ip, parsed[zone])
            if present then
                print(("  ERROR: %s found in %s!"):format(ip, zone))
                whitelistOk = false
            end
        end
    end
end

if whitelistOk then
    print("  All whitelist IPs are clear.")
else
    print("\n*** WHITELIST VIOLATION - Fix before deploying firewall rules! ***")
    os.exit(1)
end

-------------------------------------------------------------------------------
-- CHECK ATTACK IPS
--

print("\nChecking that detected attack IPs are blocked...")

-- Find all login analysis files
local loginFiles = {}
local loginDir = "Logins/"
local dirAttr = lfs.attributes(loginDir)

if dirAttr and dirAttr.mode == "directory" then
    for file in lfs.dir(loginDir) do
        if file:match("%.lua$") then
            tinsert(loginFiles, file)
        end
    end
end

if #loginFiles == 0 then
    print("  No login analysis files found in Logins/")
    print("  Run 'lua scan.lua --parse-logs' first to analyze event logs.")
    os.exit(0)
end

local unblocked = {}

for _, verify in next, loginFiles do
    local f = io.open(loginDir .. verify)
    if f then
        local ok, raw = s.load(f:read("*a"))
        f:close()
        if not ok then
            print("  Warning: Could not parse " .. verify)
        else
            for ip in pairs(raw) do
                local isBlocked = false
                for _, zone in next, blockland do
                    if parsed[zone] then
                        local present = iputils.ip_in_cidrs(ip, parsed[zone])
                        if present then
                            isBlocked = true
                            break
                        end
                    end
                end

                if not isBlocked then
                    if not unblocked[ip] then
                        unblocked[ip] = {}
                    end
                    tinsert(unblocked[ip], verify)
                end
            end
        end
    end
end

local unblockedList = {}
for ip in pairs(unblocked) do
    tinsert(unblockedList, ip)
end

if #unblockedList == 0 then
    print("  All detected attack IPs are blocked.")
else
    print(("\n  Found %d unblocked attack IP(s):"):format(#unblockedList))
    table.sort(unblockedList)
    for _, ip in ipairs(unblockedList) do
        print(("    %s (from: %s)"):format(ip, table.concat(unblocked[ip], ", ")))
    end
    print("\n  Add these to Zones/custom.zone and re-run firewall import.")
end

print("\nDone.")
