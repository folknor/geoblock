#!/usr/bin/lua

local VERSION = 3

local function helpExit(err)
    if err then
        print("Error: " .. tostring(err))
    end
    print(([[
geoblock v%d

Usage: lua scan.lua [options]

Options:
  --update          Update zone files from ipdeny.com (default if no options)
  --validate        Validate whitelist IPs aren't blocked
  --parse-logs      Parse event log XML files
  --all             Run update + validate + parse-logs
  --help            Show this help message

Examples:
  lua scan.lua                    # Update zones only
  lua scan.lua --validate         # Update zones, then validate
  lua scan.lua --all              # Full workflow

Requires: serpent, lfs, curl, xmllint (for --parse-logs)
]]):format(VERSION))
    os.exit(err and 1 or 0)
end

-------------------------------------------------------------------------------
-- UTILITIES
--

local function exec(cmd)
    local handle = io.popen(cmd .. " 2>/dev/null")
    if not handle then return nil end
    local result = handle:read("*a")
    local ok = handle:close()
    return result, ok
end

local function commandExists(cmd)
    local result, ok = exec("command -v " .. cmd)
    return ok and result and result:len() > 0
end

local function curl(url)
    local result, ok = exec('curl -s "' .. url .. '"')
    if ok and result and result:len() > 0 then
        return result
    end
    return nil
end

-------------------------------------------------------------------------------
-- PARSE ARGUMENTS
--

local doUpdate = false
local doValidate = false
local doParseLogs = false

if #arg == 0 then
    doUpdate = true
end

for i = 1, #arg do
    if arg[i] == "--update" then
        doUpdate = true
    elseif arg[i] == "--validate" then
        doUpdate = true  -- Always update before validating
        doValidate = true
    elseif arg[i] == "--parse-logs" then
        doParseLogs = true
    elseif arg[i] == "--all" then
        doUpdate = true
        doValidate = true
        doParseLogs = true
    elseif arg[i] == "--help" or arg[i] == "-h" then
        helpExit()
    else
        helpExit("Unknown option: " .. arg[i])
    end
end

-------------------------------------------------------------------------------
-- LOAD CONFIG
--

local configOk, config = pcall(require, "config")
if not configOk then
    helpExit("Could not load config.lua. Copy config.example.lua to config.lua and customize it.")
end

local xmlFiles = config.xmlFiles or {}
local IGNORE = config.ignore or {}
local blockZones = config.blockZones or {}
local whitelist = config.whitelist or {}

-------------------------------------------------------------------------------
-- CHECK DEPENDENCIES
--

if not commandExists("curl") then
    helpExit("curl is required but not found in PATH")
end

-------------------------------------------------------------------------------
-- UPDATE ZONE FILES
--

local BLOCK_PREFIX = "https://www.ipdeny.com/ipblocks/data/aggregated/"
local BLOCK_FOLDER = "Zones/"

local lfs = require("lfs")

-- Ensure Zones directory exists
lfs.mkdir(BLOCK_FOLDER)

-- Create custom.zone if it doesn't exist
local attr = lfs.attributes(BLOCK_FOLDER .. "custom.zone")
if not attr then
    local f = io.open(BLOCK_FOLDER .. "custom.zone", "w")
    if f then
        f:write("# Custom IP blocks - add CIDR ranges here (one per line)\n")
        f:close()
    end
end

if doUpdate then
    print("Downloading IP blocks from ipdeny.com...")

    local updated = 0
    local failed = 0

    for _, zone in ipairs(blockZones) do
        if zone ~= "custom.zone" then
            local content = curl(BLOCK_PREFIX .. zone)
            if content then
                -- Read existing file
                local existing = ""
                local f = io.open(BLOCK_FOLDER .. zone, "r")
                if f then
                    existing = f:read("*a")
                    f:close()
                end

                -- Update if different
                if existing ~= content then
                    f = io.open(BLOCK_FOLDER .. zone, "w")
                    if f then
                        f:write(content)
                        f:close()
                        print("  [updated] " .. zone)
                        updated = updated + 1
                    end
                end
            else
                print("  [failed]  " .. zone)
                failed = failed + 1
            end
        end
    end

    if updated == 0 and failed == 0 then
        print("  All zone files up to date.")
    else
        print(("  %d updated, %d failed"):format(updated, failed))
    end
end

-------------------------------------------------------------------------------
-- VALIDATE WHITELIST
--

if doValidate then
    print("\nValidating whitelist...")

    local iputils = require("iputils")

    -- Load and parse zones
    local zones = {}
    local tinsert = table.insert

    for _, zone in ipairs(blockZones) do
        local f = io.open(BLOCK_FOLDER .. zone, "r")
        if f then
            local content = f:read("*a")
            f:close()
            local cidrs = {}
            for line in content:gmatch("([^\n]+)") do
                if not line:match("^%s*#") and line:match("%S") then
                    tinsert(cidrs, line)
                end
            end
            zones[zone] = iputils.parse_cidrs(cidrs)
        end
    end

    -- Check whitelist IPs
    local violations = {}
    for ip in pairs(whitelist) do
        for zone, parsed in pairs(zones) do
            if iputils.ip_in_cidrs(ip, parsed) then
                tinsert(violations, { ip = ip, zone = zone })
            end
        end
    end

    if #violations == 0 then
        print("  All whitelist IPs are clear.")
    else
        print("  WHITELIST VIOLATIONS:")
        for _, v in ipairs(violations) do
            print(("    %s is in %s"):format(v.ip, v.zone))
        end
        print("\n  Fix config.lua before deploying firewall rules!")
        os.exit(1)
    end

    -- Check for unblocked attack IPs
    local s = require("serpent")
    local loginDir = "Logins/"
    local dirAttr = lfs.attributes(loginDir)

    if dirAttr and dirAttr.mode == "directory" then
        local unblocked = {}

        for file in lfs.dir(loginDir) do
            if file:match("%.lua$") then
                local f = io.open(loginDir .. file)
                if f then
                    local ok, raw = s.load(f:read("*a"))
                    f:close()
                    if ok then
                        for ip in pairs(raw) do
                            local isBlocked = false
                            for _, parsed in pairs(zones) do
                                if iputils.ip_in_cidrs(ip, parsed) then
                                    isBlocked = true
                                    break
                                end
                            end
                            if not isBlocked and not unblocked[ip] then
                                unblocked[ip] = file
                            end
                        end
                    end
                end
            end
        end

        local count = 0
        for _ in pairs(unblocked) do count = count + 1 end

        if count > 0 then
            print(("\n  %d unblocked attacker IP(s):"):format(count))
            for ip, source in pairs(unblocked) do
                print(("    %s (from %s)"):format(ip, source))
            end
            print("  Add these to Zones/custom.zone")
        end
    end
end

-------------------------------------------------------------------------------
-- PARSE EVENT LOGS
--

if doParseLogs then
    if #xmlFiles == 0 then
        print("\nNo XML files configured in config.lua, skipping log parsing.")
    else
        if not commandExists("xmllint") then
            helpExit("xmllint is required for --parse-logs but not found in PATH")
        end

        local s = require("serpent")
        local XML_FOLDER = "EventLogXML/"
        local XML_LINTED_POSTFIX = ".clean"

        -- Ensure directories exist
        lfs.mkdir(XML_FOLDER)
        lfs.mkdir("Logins")

        print("\nParsing event logs...")

        for _, sourceFile in ipairs(xmlFiles) do
            local input = XML_FOLDER .. sourceFile
            local linted = input .. XML_LINTED_POSTFIX
            local loginFile = "Logins/" .. sourceFile .. ".lua"

            local attr = lfs.attributes(input)
            if not attr then
                print("  [skip] " .. sourceFile .. " (not found)")
                goto continue
            end

            -- Lint XML
            os.execute('xmllint -o "' .. linted .. '" --format "' .. input .. '" 2>/dev/null')

            attr = lfs.attributes(linted)
            if not attr then
                print("  [fail] " .. sourceFile .. " (xmllint failed)")
                goto continue
            end

            print("  [scan] " .. sourceFile)

            -- Parse XML
            local xml2lua = require("xml2lua")
            local xmlHandler = require("xmlhandler.tree")

            local handler = xmlHandler:new()
            local parser = xml2lua.parser(handler)
            parser:parse(xml2lua.loadFile(linted))

            local logins = {}
            local FIELD_IP = "IpAddress"
            local FIELD_USER = "TargetUserName"

            if handler.root and handler.root.Events and handler.root.Events.Event then
                for _, ev in pairs(handler.root.Events.Event) do
                    if type(ev) == "table" and type(ev.EventData) == "table" then
                        for _, evData in pairs(ev.EventData) do
                            local userName, userHost = nil, nil

                            if type(evData) == "table" then
                                for _, y in pairs(evData) do
                                    if type(y) == "table" and y._attr then
                                        if y._attr.Name == FIELD_IP then
                                            userHost = y[1]
                                        elseif y._attr.Name == FIELD_USER then
                                            userName = y[1]
                                        end
                                    end
                                end
                            end

                            if userHost and userName and not IGNORE[userHost] then
                                if not logins[userHost] then
                                    logins[userHost] = { names = {}, count = 0 }
                                end
                                local found = false
                                for _, n in ipairs(logins[userHost].names) do
                                    if n == userName then found = true; break end
                                end
                                if not found then
                                    table.insert(logins[userHost].names, userName)
                                end
                                logins[userHost].count = logins[userHost].count + 1
                            end
                        end
                    end
                end
            end

            -- Write results
            local f = io.open(loginFile, "w")
            if f then
                f:write(s.block(logins))
                f:close()
            end

            -- Cleanup
            os.remove(linted)

            -- Summary
            local ipCount = 0
            for _ in pairs(logins) do ipCount = ipCount + 1 end
            print(("         %d unique IPs"):format(ipCount))

            ::continue::
        end
    end
end

print("\nDone.")
