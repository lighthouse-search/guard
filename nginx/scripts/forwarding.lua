local cjson = require "cjson"

-- Function to handle the intermediary server response
local function handle_response()
    ngx.req.read_body()
    local res_body = ngx.var.request_body
    local status = ngx.status

    if status == 200 then
        local data = cjson.decode(res_body)
        if data and data.success then
            ngx.ctx.destination_url = data.destination_url
            ngx.ctx.guard = cjson.encode(data.guard)
        else
            ngx.status = 401
            ngx.say('{"success":false}')
            ngx.exit(ngx.HTTP_OK)
        end
    else
        ngx.status = 401
        ngx.say('{"success":false}')
        ngx.exit(ngx.HTTP_OK)
    end
end

handle_response()
