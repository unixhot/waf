local base        = require("resty.core.base")
local bit         = require("bit")
local clear_tab   = require("table.clear")
local new_tab     = base.new_tab
local find_str    = string.find
local tonumber    = tonumber
local ipairs      = ipairs
local pairs       = pairs
local ffi         = require "ffi"
local ffi_cdef    = ffi.cdef
local ffi_new     = ffi.new
local C           = ffi.C
local insert_tab  = table.insert
local string      = string
local setmetatable=setmetatable
local type        = type
local error       = error
local str_sub     = string.sub
local str_byte    = string.byte
local cur_level   = ngx.config.subsystem == "http" and
                    require "ngx.errlog" .get_sys_filter_level()

local AF_INET     = 2
local AF_INET6    = 10
if ffi.os == "OSX" then
    AF_INET6 = 30
end


local _M = {_VERSION = 0.2}


ffi_cdef[[
    int inet_pton(int af, const char * restrict src, void * restrict dst);
    uint32_t ntohl(uint32_t netlong);
]]


local function parse_ipv4(ip)
    if not ip then
        return false
    end

    local inet = ffi_new("unsigned int [1]")
    if C.inet_pton(AF_INET, ip, inet) ~= 1 then
        return false
    end

    return C.ntohl(inet[0])
end
_M.parse_ipv4 = parse_ipv4


local function parse_ipv6(ip)
    if not ip then
        return false
    end

    if str_byte(ip, 1, 1) == str_byte('[')
        and str_byte(ip, #ip) == str_byte(']') then

        -- strip square brackets around IPv6 literal if present
        ip = str_sub(ip, 2, #ip - 1)
    end

    local inets = ffi_new("unsigned int [4]")
    if C.inet_pton(AF_INET6, ip, inets) ~= 1 then
        return false
    end

    local inets_arr = new_tab(4, 0)
    for i = 0, 3 do
        insert_tab(inets_arr, C.ntohl(inets[i]))
    end
    return inets_arr
end
_M.parse_ipv6 = parse_ipv6


local mt = {__index = _M}


    local ngx_log = ngx.log
    local ngx_INFO = ngx.INFO
local function log_info(...)
    if cur_level and ngx_INFO > cur_level then
        return
    end

    return ngx_log(ngx_INFO, ...)
end


local function split_ip(ip_addr_org)
    local idx = find_str(ip_addr_org, "/", 1, true)
    if not idx then
        return ip_addr_org
    end

    local ip_addr = str_sub(ip_addr_org, 1, idx - 1)
    local ip_addr_mask = str_sub(ip_addr_org, idx + 1)
    return ip_addr, tonumber(ip_addr_mask)
end
_M.split_ip = split_ip


    local idxs = {}
local function gen_ipv6_idxs(inets_ipv6, mask)
    clear_tab(idxs)

    for _, inet in ipairs(inets_ipv6) do
        local valid_mask = mask
        if valid_mask > 32 then
            valid_mask = 32
        end

        if valid_mask == 32 then
            insert_tab(idxs, inet)
        else
            insert_tab(idxs, bit.rshift(inet, 32 - valid_mask))
        end

        mask = mask - 32
        if mask <= 0 then
            break
        end
    end

    return idxs
end


function _M.new(ips)
    if not ips or type(ips) ~= "table" then
        error("missing valid ip argument", 2)
    end

    local parsed_ipv4s = {}
    local parsed_ipv4s_mask = {}
    local parsed_ipv6s = {}
    local parsed_ipv6s_mask = {}

    for _, ip_addr_org in ipairs(ips) do
        local ip_addr, ip_addr_mask = split_ip(ip_addr_org)

        local inet_ipv4 = parse_ipv4(ip_addr)
        if inet_ipv4 then
            ip_addr_mask = ip_addr_mask or 32
            if ip_addr_mask == 32 then
                parsed_ipv4s[ip_addr] = true

            else
                local valid_inet_addr = bit.rshift(inet_ipv4, 32 - ip_addr_mask)

                parsed_ipv4s[ip_addr_mask] = parsed_ipv4s[ip_addr_mask] or {}
                parsed_ipv4s[ip_addr_mask][valid_inet_addr] = true
                parsed_ipv4s_mask[ip_addr_mask] = true
                log_info("ipv4 mask: ", ip_addr_mask,
                         " valid inet: ", valid_inet_addr)
            end
        end

        local inets_ipv6 = parse_ipv6(ip_addr)
        if inets_ipv6 then
            ip_addr_mask = ip_addr_mask or 128
            if ip_addr_mask == 128 then
                parsed_ipv6s[ip_addr] = true

            else
                parsed_ipv6s[ip_addr_mask] = parsed_ipv6s[ip_addr_mask] or {}

                local inets_idxs = gen_ipv6_idxs(inets_ipv6, ip_addr_mask)
                local node = parsed_ipv6s[ip_addr_mask]
                for i, inet in ipairs(inets_idxs) do
                    if i == #inets_idxs then
                        node[inet] = true
                    elseif not node[inet] then
                        node[inet] = {}
                        node = node[inet]
                    end
                end

                parsed_ipv6s_mask[ip_addr_mask] = true
            end
        end

        if not inet_ipv4 and not inets_ipv6 then
            return nil, "invalid ip address: " .. ip_addr
        end
    end

    local ipv4_mask_arr = {}
    for k, _ in pairs(parsed_ipv4s_mask) do
        insert_tab(ipv4_mask_arr, k)
    end

    local ipv6_mask_arr = {}
    for k, _ in pairs(parsed_ipv6s_mask) do
        insert_tab(ipv6_mask_arr, k)
    end

    return setmetatable({
        ipv4 = parsed_ipv4s,
        ipv4_mask = parsed_ipv4s_mask,
        ipv4_mask_arr = ipv4_mask_arr,

        ipv6 = parsed_ipv6s,
        ipv6_mask = parsed_ipv6s_mask,
        ipv6_mask_arr = ipv6_mask_arr,
    }, mt)
end


function _M.match(self, ip)
    local inet_ipv4 = parse_ipv4(ip)
    if inet_ipv4 then
        local ipv4s = self.ipv4
        if ipv4s[ip] then
            return true
        end

        for _, mask in ipairs(self.ipv4_mask_arr) do
            if mask == 0 then
                return true -- match any ip
            end

            local valid_inet_addr = bit.rshift(inet_ipv4, 32 - mask)

            log_info("ipv4 mask: ", mask,
                     " valid inet: ", valid_inet_addr)

            if ipv4s[mask][valid_inet_addr] then
                return true
            end
        end

        return false
    end

    local inets_ipv6 = parse_ipv6(ip)
    if not inets_ipv6 then
        return false, "invalid ip address, not ipv4 and ipv6"
    end

    local ipv6s = self.ipv6
    if ipv6s[ip] then
        return true
    end

    for _, mask in ipairs(self.ipv6_mask_arr) do
        if mask == 0 then
            return true -- match any ip
        end

        local node = ipv6s[mask]
        local inet_idxs = gen_ipv6_idxs(inets_ipv6, mask)
        for _, inet in ipairs(inet_idxs) do
            if not node[inet] then
                break
            else
                if node[inet] == true then
                    return true
                end
                node = node[inet]
            end
        end
    end

    return false
end


return _M
