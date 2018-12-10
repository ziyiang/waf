-- WAF Action
require "config"
require "lib"

-- args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri
local redis = require "redis"
local mysql = require "mysql"

-- allow white ip
function white_ip_check()
    if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_rule("whiteip")
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _, rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP, rule, "jo") then
                    -- log_record("White_IP",ngx.var.request_uri,"_","_")
                    return true
                end
            end
        end
    end
end

-- deny black ip
function black_ip_check()
    if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_rule("blackip")
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _, rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP, rule, "jo") then
                    log_record('BlackList_IP', ngx.var.request_uri, "_", "_")
                    if config_waf_enable == "on" then
                        ngx.header.content_type = "text/html"
                        ngx.say('Your IP blacklist, Please contact the administrator! ')
                        return true
                    end
                end
            end
        end
    end
end

-- allow white url
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule("whiteurl")
        local REQ_URI = string.lower(ngx.var.request_uri)
        if URL_WHITE_RULES ~= nil then
            for _, rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI, rule, "jo") then
                    return true
                end
            end
        end
    end
end

-- deny cc attack
function cc_attack_check()
    if config_cc_check == "on" then
        local USER_AGENT = get_user_agent()
        local ARGS = ngx.var.args or ""

        local ATTACK_URL = ngx.var.host .. ngx.var.uri
        -- local ATTACK_URL = ngx.var.host .. ngx.var.request_uri
        -- local ATTACK_URL = ngx.var.host .. ngx.var.uri .. '?' .. ARGS

        local CC_TOKEN = get_client_ip() .. "." .. ngx.md5(string.lower(ATTACK_URL) .. USER_AGENT)
        local limit = ngx.shared.limit
        local CCcount = tonumber(string.match(config_cc_rate, '(.*)/'))
        local CCseconds = tonumber(string.match(config_cc_rate, '/(.*)'))
        local req, _ = limit:get(CC_TOKEN)
        if req then
            -- write("/data/wwwlogs/info.log",CC_TOKEN .."\t".. ATTACK_URL .. "\t".. "req: " .. req .."\n")
            if req > CCcount then
                log_record("CC_Attack", ngx.var.request_uri, "-", "-")
                if config_waf_enable == "on" then
                    local source = ngx.encode_base64(ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri)
                    local dest = '/captcha-waf.html' .. '?continue=' .. source
                    local CCcountcode, _ = math.modf(CCcount / 2);
                    limit:set(CC_TOKEN, CCcountcode)
                    ngx.redirect(dest, 302)
                end
            else
                limit:incr(CC_TOKEN, 1)
            end
        else
            limit:set(CC_TOKEN, 1, CCseconds)
        end
    end
    return false
end

-- deny cookie
function cookie_attack_check()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule("cookie")
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _, rule in pairs(COOKIE_RULES) do
                if rule ~= "" and rulematch(USER_COOKIE, rule, "jo") then
                    log_record("Deny_Cookie", ngx.var.request_uri, "-", rule)
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

-- deny url
function url_attack_check()
    if config_url_check == "on" then
        local URL_RULES = get_rule("blackurl")
        local REQ_URI = string.lower(ngx.var.request_uri)
        for _, rule in pairs(URL_RULES) do
            if rule ~= "" and rulematch(REQ_URI, rule, "jo") then
                log_record("Deny_URL", REQ_URI, "-", rule)
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

-- deny url args
function url_args_attack_check()
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('args')
        for _, rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                if type(val) == "table" then
                    local ARGS_DATA = table.concat(val, " ")
                else
                    local ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~= "" and rulematch(unescape(ARGS_DATA), rule, "jo") then
                    log_record("Deny_URL_Args", ngx.var.request_uri, "-", rule)
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

-- deny user agent
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule("useragent")
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _, rule in pairs(USER_AGENT_RULES) do
                if rule ~= "" and rulematch(USER_AGENT, rule, "jo") then
                    log_record("Deny_USER_AGENT", ngx.var.request_uri, "-", rule)
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

-- deny post
function post_attack_check()
    if config_post_check == "on" then
        local POST_RULES = get_rule("post")
        for _, rule in pairs(ARGS_RULES) do
            local POST_ARGS = ngx.req.get_post_args()
        end
        return true
    end
    return false
end

------------------------------------------------------------------------------

-- test
function test()
    ngx.header.content_type = "text/html"
    ngx.say('hello')
    return false
end



function test_redis()
    return false
end

function test_mysql()
    return false
end





function web_check()
    ngx.header.content_type = "text/html"
    local check_ip = get_client_ip()

    local cache = redis.new()
    local ok, err = cache.connect(cache, '127.0.0.1', '6379')

    -- 判断次数
    local res = cache:get(check_ip)
    if res ~= nil then -- 连接成功
        local times=cache:get(check_ip)
        log_record('当前次数为','total',times)
        if (times == ngx.null) then
            -- 初始化
            cache:set(check_ip,1)
            log_record('计入redis','write',times)
        else
            --自增
            cache:incr(check_ip)
            times=cache:get(check_ip)
            log_record('自增','incr',times)
        end

        times=tonumber(times)
        log_record('转换后的值为','changed',times)
        log_record('配置值为','config_times',config_redis_limit)
        if (tonumber(times)>config_redis_limit) then
            log_record('大于'..config_redis_limit..'次的记录','count',times)
            -- 大于n次 存入mysql
            save_to_mysql(check_ip,times)
        else
            log_record('小于'..config_redis_limit..'次的记录','count',times)
        end

    else
        log_record('写入redis链接失败')
    end


    return true
end


function save_to_mysql(check_ip,times)
    log_record('进入add_mysql','mysql')
    ngx.header.content_type = "text/html"
    local db, err = mysql:new()
    if not db then
        ngx.say("failed to instantiate mysql: ", err)
        return
    end
    db:set_timeout(1000)
    local ok, err, errcode, sqlstate = db:connect{
        host = "127.0.0.1",
        port = 3306,
        database = "test",
        user = "root",
        password = "123456",
        charset = "utf8",
        max_packet_size = 1024 * 1024,
    }
    if not ok then
        ngx.say("failed to connect: ", err, ": ", errcode, " ", sqlstate)
        return
    end
    log_record('connected to mysql','mysql')
    if(find_mysql(sqlstate,check_ip) ~='no_find') then
        log_record('即将开始插入数据')
        --add_mysql(sqlstate)
    else
        log_record('未找到该数据')
    end



end

function find_mysql(sqlstate,check_ip)
    log_record('进入find_mysql','mysql',check_ip)
    log_record(res)
    res, err, errcode, sqlstate = db:query("select id from ngx_ip_black where id=6 limit 1;")
    log_record(err)
    log_record(errcode)
--[[    if not res then
        log_record('mysql未找到该数据')
        return 'no_find'
    else
        log_record('mysql找到该数据','mysql_find',res)
        return  res
    end]]
end
function add_mysql(sqlstate)
    res, err, errcode, sqlstate = db:query("insert into ngx_ip_black(ip,times,create_time) values('"..check_ip.."',"..times..",now())")
    if not res then
        ngx.say("bad result: ", err, ": ", errcode, ": ", sqlstate, ".")
        return
    else
        log_record('插入数据库成功')
        return true
    end
end

