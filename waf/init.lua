require 'config'
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

function GetClientIp()
	ClientIp = ngx.req.get_headers()["wm-client-ip"]
	if ClientIp == nil then
		ClientIp = ngx.req.get_headers()["X_Forwarded_For"]
	end
    if ClientIp == nil then
		ClientIp  = ngx.var.remote_addr 
    end
    if ClientIp == nil then
        ClientIp  = "unknown"
    end
    return ClientIp
end

function GetUserAgent()
	UserAgent = ngx.var.http_user_agent
	if UserAgent == nil then
		UserAgent = "unknown"
	end
	return UserAgent
end

function GetRule(rulefilename)
	local io = require 'io'
	local RulePath = Rule_Dir
	local RuleFile = io.open(RulePath..'/'..rulefilename,"r")
	if RuleFile == nil then
		return
	end
	RuleTable = {}
	for line in RuleFile:lines() do
		table.insert(RuleTable,line)
	end
	RuleFile:close()
	return(RuleTable)
end

function LogRecord(method,url,data,ruletag)
	if Attack_Log == "on" then
		local io = require 'io'
		local LogPath = Log_Dir
		local ClientIp = GetClientIp()
		local UserAgent = GetUserAgent()
		local ServerName = ngx.var.server_name
		local LocalTime = ngx.localtime()
		local LogLine = ClientIp.." ["..LocalTime.."] \""..method.." "..ServerName..url.."\" \""..data.."\" \""..UserAgent.."\" \""..ruletag.."\"\n"
		local LogName = LogPath..'/'..ngx.today().."_waf.log"
		local file = io.open(LogName,"a")
		if file == nil then
			return
		end
		file:write(LogLine)
		file:flush()
		file:close()
	end
end

function WhiteListIp()
	if next(White_List_Ip) ~= nil then
		for _,IpValue in pairs(White_List_Ip) do
			if GetClientIp() == IpValue then
				return true
			end
		end
	end
	return false
end

function DenyBlockIp()
	if next(Block_List_Ip) ~= nil then
		for _,IpValue in pairs(Block_List_Ip) do
			if GetClientIp() == IpValue then
				ngx.exit(403)
				return true
			end
		end
	end
	return false
end

function DenyCCAttack()
	if CC_Deny == "on" then
		local AttackUri=ngx.var.uri
		local token = GetClientIp()..AttackUri
		local limit = ngx.shared.limit
		CCcount=tonumber(string.match(CC_Rate,'(.*)/'))
		CCseconds=tonumber(string.match(CC_Rate,'/(.*)'))
		local req,_=limit:get(token)
		if req then
			if req > CCcount then
				ngx.exit(403)
			else
				limit:incr(token,1)
			end
		else
			limit:set(token,1,CCseconds)
		end
	end
	return false
end

function WhiteUrl()
	if Url_White == "on" then
		local UrlWhiteRules = GetRule('writeurl.rule')
    		local uri = ngx.var.request_uri
		if UrlWhiteRules ~=nil then
			for _,rule in pairs(UrlWhiteRules) do
				if rule ~="" and rulematch(uri,rule,"jo") then
                    			return true 
            			end
        		end
    		end
	end
    	return false
end

function DenyCookie()
	if Cookie_Deny == "on" then
		local CookieRules = GetRule('cookie.rule')
		local UserCookie = ngx.var.http_cookie
		if UserCookie ~= nil then
			for _,rule in pairs(CookieRules) do
				if rule ~="" and rulematch(UserCookie,rule,"jo") then
					LogRecord('Cookie',ngx.var.request_uri,"-",rule)
					ngx.exit(403)
					return true
				end
			end
		end
	end
	return false
end

function DenyUrl()
	if Url_Deny == "on" then
		local UrlRules = GetRule('url.rule')
		local uri = ngx.var.request_uri
		for _,rule in pairs(UrlRules) do
			if rule ~="" and rulematch(uri,rule,"jo") then
				LogRecord('GET',uri,"-",rule)
				ngx.exit(403)
				return true
			end
		end
	end
	return false
end

function DenyUrlArgs()
	if Url_Deny == "on" then
		local ArgsRules = GetRule('args.rule')
		for _,rule in pairs(ArgsRules) do
			local args = ngx.req.get_uri_args()
			for key, val in pairs(args) do
				if type(val) == 'table' then
					data = table.concat(val, " ")
				else
					data = val
				end
				if data and type(data) ~= "boolean" and rule ~="" and rulematch(unescape(data),rule,"jo") then
					LogRecord('GET',ngx.var.request_uri,"-",rule)
					ngx.exit(403)
					return true
				end
			end
		end
	end
	return false
end


function DenyUserAgent()
	if User_Agent_Deny == "on" then
		local UserAgentRules = GetRule('useragent.rule')
		local UserAgent = ngx.var.http_user_agent
		if UserAgent ~= nil then
			for _,rule in pairs(UserAgentRules) do
				if rule ~="" and rulematch(UserAgent,rule,"jo") then
					LogRecord('UserAgent',ngx.var.request_uri,"-",rule)
					ngx.exit(403)
					return true
				end
			end
		end
	end
	return false
end
