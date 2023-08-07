--WAF Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

--allow white ip
function white_ip_check()
    if config_white_ip_check == "on" then
        local IP_WHITE_RULE = config_white_ip
        local ipmatcher = require "vendor.ipmatcher"
        local ip = ipmatcher.new(IP_WHITE_RULE)
        local CLIENT_IP = get_client_ip()

        -- clinetip in white_ip
        if ip:match(CLIENT_IP) then
            return true
        end
    end

    return false
end

--deny black ip
function black_ip_check()
    if config_black_ip_check == "on" then
        local IP_BLACK_RULE = config_black_ip
        local ipmatcher = require "vendor.ipmatcher"
        local ip = ipmatcher.new(IP_BLACK_RULE)
        local CLIENT_IP = get_client_ip()

         -- clinetip in black_ip
         if ip:match(CLIENT_IP) then
            ngx.exit(403)
            return true
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
        CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
        CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
        local ATTACK_URI=ngx.var.uri
        local CC_USER = get_client_ip()..ATTACK_URI
        -- set redis key with expire time
        -- lua redis conn pool

        -- redis connect
        local redis = require "vendor.redis"
        local red = redis:new()
        red:set_timeouts(1000, 1000, 1000)

        local ok, err = red:connect(config_redis_host, config_redis_port)
        if not ok then
            ngx.say("failed to connect redis: ", err)
            return
        end
        local res, err = red:auth(config_redis_passwd)
        if not res then
            ngx.say("failed to authenticate: ", err)
            return
        end

        red:incr(CC_USER)
        red:expire(CC_USER,CCseconds)

        if tonumber(red:get(CC_USER)) >= CCcount then
            ngx.say("访问过于频繁 请稍后重试")
            return
        end 

        local ok, err = red:set_keepalive(10000, 100)
        if not ok then
            ngx.say("failed to set keepalive: ", err)
            return
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
        for _,rule in pairs(ARGS_RULES) do
            local POST_ARGS = ngx.req.get_post_args()
        end
        return true
    end
    return false
end

