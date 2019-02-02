--WAF Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

--allow white ip
function white_ip_check()
     if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_rule('whiteip.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP,rule,"jo") then
                    log_record('White_IP',ngx.var_request_uri,"_","_")
                    return true
                end
            end
        end
    end
end

--deny black ip
function black_ip_check()
     if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_rule('blackip.rule')
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"jo") then
                    log_record('BlackList_IP',ngx.var_request_uri,"_","_")
                    if config_waf_enable == "on" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

--allow white url
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI,rule,"jo") then
                    return true
                end
            end
        end
    end
end

--deny cc attack
function cc_attack_check()
    if config_cc_check == "on" then
        local get_headers = ngx.req.get_headers
        local ua = ngx.var.http_user_agent
        local uri = ngx.var.request_uri
        local url = ngx.var.host .. uri
        local redis = require 'redis'
        local red = redis.new()
        local RedisIP = '127.0.0.1'
        local RedisPORT = 6379
        local blackseconds = 7200
        if ua == nil then
            ua = "unknown"
        end
        if (string.find(uri,'/.*')) then
            CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
            CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
        end
        red:set_timeout(100)
        local ok, err = red.connect(red, RedisIP, RedisPORT)
        if ok then
            red.connect(red, RedisIP, RedisPORT)
            function getClientIp()
                IP = ngx.req.get_headers()["x_forwarded_for"]
                if IP == nil then
                    IP = ngx.req.get_headers()["X-Real-IP"]
                end
                if IP == nil then
                    IP  = ngx.var.remote_addr
                end
                if IP == nil then
                    IP  = "unknown"
                end
                return IP
            end
            function getToken()
                clientToken = ngx.var.cookie_Token
                return clientToken
            end
            local token = getClientIp() .. "." .. ngx.md5(uri .. url .. ua)
            if red:exists(token) == 0 then
                ngx.header['Set-Cookie'] = 'Token=' .. token
                red:incr(token)
                red:expire(token,CCseconds)
            else
                local clientToken = getToken()
                if red:exists(clientToken) == 0 then
                    ngx.exit(503)
                end
                local times = tonumber(red:get(token))
                if times >= CCcount then
                    local blackReq = red:exists("black." .. token)
                    if (blackReq == 0) then
                         red:set("black." .. token,1)
                         red:expire("black." .. token,blackseconds)
                         red:expire(token,blackseconds)
                         ngx.exit(503)
                    else
                         ngx.exit(503)
                    end
                else
                    red:incr(token)
                end
            end
        end        
    end
    return false
end

--deny cookie
function cookie_attack_check()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE,rule,"jo") then
                    log_record('Deny_Cookie',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
             end
	 end
    end
    return false
end

--deny url
function url_attack_check()
    if config_url_check == "on" then
        local URL_RULES = get_rule('url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"jo") then
                log_record('Deny_URL',REQ_URI,"-",rule)
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny url args
function url_args_attack_check()
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('args.rule')
        for _,rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"jo") then
                    log_record('Deny_URL_Args',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end
--deny user agent
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"jo") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny post
function post_attack_check()
    if config_post_check == "on" then
        local POST_RULES = get_rule('post.rule')
        for _,rule in pairs(POST_RULES) do
            ngx.req.read_body()
            local POST_ARGS = ngx.req.get_post_args()
        end
        return true
    end
    return false
end

