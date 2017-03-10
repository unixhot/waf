require 'init'

function waf_main()
    if white_ip_check() then
    elseif black_ip_check() then
    elseif user_agent_attack_check() then
    elseif cc_attack_check() then
    elseif cookie_attack_check() then
    elseif white_url_check() then
    elseif url_attack_check() then
    elseif url_args_attack_check() then
    --elseif post_attack_check() then
    else
        return
    end
end

waf_main()

