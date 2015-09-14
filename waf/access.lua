require 'config'

function WAF_Main()
	if WhiteListIp() then
	elseif DenyBlockIp() then
	elseif DenyUserAgent() then
	elseif DenyCCAttack() then
	elseif DenyCookie() then
	elseif WhiteUrl() then
	elseif DenyUrl() then
	elseif DenyUrlArgs() then
	else
		return
	end
end

WAF_Main()
