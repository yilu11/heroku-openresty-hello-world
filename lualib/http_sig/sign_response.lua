local resty_rsa = require "http_sig.rsa"
local resty_hmac = require "http_sig.hmac"
local resty_string = require "resty.string"

local _M = { _VERSION = '0.01' }

function getAbsolutePath(relativePath)
    -- Get the current working directory
    local pwdCmd = io.popen("pwd")
    local currentDir = pwdCmd:read("*l")
    pwdCmd:close()

    -- Construct the absolute path
    -- You might need to adapt the following line depending on your operating system
    -- For Windows use "\\" and for Unix/Linux/Mac use "/"
    local pathSeparator = "/"
    local absolutePath = currentDir .. pathSeparator .. relativePath

    return absolutePath
end

-- local rsa_public_key, rsa_priv_key, err = resty_rsa:generate_rsa_keys(2048)
local function get_privkey()
    local p = getAbsolutePath("path")
    ngx.log(ngx.ERR, "relative path", p)
    local file = io.open("../nginx/https_cert/test.alux.fun/privkey.pem", "r")

    if not file then
        ngx.log(ngx.ERR, "cannot open privkey.pem")
        return
    end

    local content = file:read("*all")

    file:close()

    return content
end
local rsa_priv_key = get_privkey()

local algo = resty_hmac.ALGOS.SHA512
local algo_str = "sha-512"
local secret_key = "" -- salt
local cache_key = "x-cache-key"

local function get_full_response()
    local chunk, eof = ngx.arg[1], ngx.arg[2]
    local buffer = ngx.ctx.buffer or ""

    if eof then
        -- Finalize the buffer with last chunk (if any)
        local complete_body = buffer .. (chunk or "")
        -- Replace the body with the complete signed body
        ngx.arg[1] = complete_body
    else
        -- Accumulate chunks into the buffer
        ngx.ctx.buffer = buffer .. (chunk or "")
        -- Prevent partial response body from being sent to client
        ngx.arg[1] = nil
    end
    return ngx.arg[1]
end

local function do_hmac(data)
    -- Calculate the signature
    local hmac = resty_hmac:new(secret_key, algo)
    if not hmac then
        ngx.say("failed to create the hmac object")
        return
    end
    local ok = hmac:update(data)
    if not ok then
        ngx.say("failed to add data")
        return
    end

    local mac = hmac:final() -- binary mac

    -- dont forget to reset after final!
    if not hmac:reset() then
        ngx.say("failed to reset hmac")
        return
    end
    --ngx.log(ngx.ERR, "data=" .. data)
    --ngx.log(ngx.ERR, "data=" .. resty_string.to_hex( data))
    --ngx.log(ngx.ERR, "mac=" .. ( mac))
    --ngx.log(ngx.ERR, "mac=" .. resty_string.to_hex( mac))

    return mac
end

local function hmac_hex(data)
    return resty_string.to_hex(do_hmac(data))
end

local function print_req_headers()
    local headers = ngx.req.get_headers()
    for key, value in pairs(headers) do
        if type(value) == "table" then
            -- If multiple values exist for the header, they will be in a table.
            value = table.concat(value, ", ")
        end
        ngx.log(ngx.ERR, "Header: ", key, " = ", value)
    end
end

function _M.set_cache_key_in_req_header(self)
    local key_str = tostring(ngx.var.request_uri) .. tostring(ngx.var.remote_port)
    local key = hmac_hex(key_str)
    ngx.req.set_header(cache_key, key)
end

local function get_cache_key_from_req_header()
    return ngx.req.get_headers()[cache_key]
end

local function get_content_digest_from_cache(my_cache)
    local key = get_cache_key_from_req_header()
    local content_digest = my_cache:get(key)
    my_cache:delete(key)
    return algo_str .. "=:" .. ngx.encode_base64(content_digest) .. ":"
end

local function sign(signing_string)
    -- local secret_key = "your_secret_key"
    -- Trim the trailing newline
    -- signing_string = signing_string:sub(1, -2)
    -- ngx.say("signing_string: ", signing_string)
    -- Calculate the signature
    --local algorithm = "SHA256"
    --local priv, err = resty_rsa:new({ private_key = rsa_priv_key, algorithm = algorithm })
    local algorithm = "SHA512"
    local priv, err = resty_rsa:new({ private_key = rsa_priv_key, algorithm = algorithm })
    if not priv then
        ngx.say("new rsa err: ", err)
        return
    end
    local digest = do_hmac(signing_string);
    -- ngx.say("digest:", resty_string.to_hex(digest))
    local sig, err = priv:sign(signing_string)
    if not sig then
        ngx.say("failed to sign:", err)
        return
    end
    return sig
end

function _M.save_content_digest_into_cache(self, my_cache)
    local response = get_full_response()
    if response then
        local digest = do_hmac(response)
        local key = get_cache_key_from_req_header()
        my_cache:set(key, digest)
    end
end

function _M.add_signature(self, my_cache)
    local content_digest = get_content_digest_from_cache(my_cache)
    if content_digest then
        ngx.header["Content-Digest"] = content_digest
        local timestamp = os.time()
        local keyid = "RSA (X.509 preloaded)"
        local alg = "rsa-pss-sha512"
        local sig_input = 'sig=(@status @method @content-digest @content-type);alg=' ..
            alg .. ';created=' .. timestamp .. ';keyid=' .. keyid
        ngx.header["Signature-Input"] = sig_input

        local status = tostring(ngx.status)
        local method = tostring(ngx.method)
        local authority = tostring(ngx.authority)
        local path = tostring(ngx.path)
        local content_length = ngx.header["Content-Length"] or ""
        local content_type = ngx.header["Content-Type"] or ""
        --local sig_input_data = 'sig=("' .. status .. '" "' .. method .. '" "'  .. content_digest .. '" "' .. content_type .. '");alg="' .. alg .. '";created=' .. timestamp .. ';keyid="' .. keyid .. '"'
        local sig_input_data = 'sig=(' ..
            status ..
            ' ' ..
            method ..
            ' ' ..
            content_digest .. ' ' .. content_type .. ');alg=' .. alg .. ';created=' .. timestamp .. ';keyid=' .. keyid
        ngx.log(ngx.ERR, "data:" .. sig_input_data)
        -- sign data
        local sig = sign(sig_input_data)
        -- base64
        local sig_base64 = ngx.encode_base64(sig)
        ngx.log(ngx.ERR, sig_base64)

        ngx.header["Signature"] = "sig=:" .. sig_base64 .. ":"
    end
end

function _M.get_cookie(self, key)
    local cookies = ngx.var.http_cookie
    --ngx.log(ngx.ERR, cookies)
    ngx.log(ngx.ERR, "key = " .. key .. ":end")

    -- Check if the cookies string is not empty or nil
    if cookies then
        -- Pattern to extract a specific cookie named "MyCookieName"
        local pattern = key .. "=([^;]+)"
        -- Use string.match to search for MyCookieName and capture its value
        local cookie_value = string.match(cookies, pattern)

        return cookie_value
    else
        return nil
    end
end

return _M

