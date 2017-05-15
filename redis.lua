--local cjson = require "cjson"

local packet_hash_sec = {}
local packet_hash_usec = {}
local packet_hash_cmd = {}

function parse_request(str)
    if string.byte(str, 1) ~= 42 then
        return string.gsub(str, "[\r\n]", " ")
    end

    local result = ""
    for sub_str in string.gmatch(str, "(%g+)\r\n") do
        local first_char = string.byte(sub_str, 1)
        -- ascii('$') = 36, ascii('*') = 42
        if first_char ~= 36 and first_char ~= 42 then
            result = result.." "..sub_str
        end
    end
    return result
end

function calculate_request_cost(key, item)
    if packet_hash_cmd[key] then
        local time_str = os.date('%Y-%m-%d %H:%M:%S', item.tv_sec).."."..item.tv_usec
        local cost = (item.tv_sec - packet_hash_sec[key]) * 1000
        cost = cost +  (item.tv_usec - packet_hash_usec[key]) / 1000
        if string.len(packet_hash_cmd[key]) > 50 then
            print(string.format("%s | %36s | %1.50s... | %3.3fms", time_str, key, packet_hash_cmd[key], cost))
        else
            print(string.format("%s | %36s | %-53s | %3.3fms", time_str, key, packet_hash_cmd[key], cost))
        end
        packet_hash_sec[key] = nil 
        packet_hash_usec[key] = nil 
        packet_hash_cmd[key] = nil 
    end
end

function store_request(key, item)
    packet_hash_sec[key] = item.tv_sec
    packet_hash_usec[key] = item.tv_usec
    packet_hash_cmd[key] = parse_request(item.payload)
end

function handle_incoming(item)
    if item.is_client == 1 then
        key = item.dst.. ":" .. item.dport .. " | " .. item.src.. ":" .. item.sport
        calculate_request_cost(key, item)
    else
        key = item.src.. ":" .. item.sport .. " | " .. item.dst.. ":" .. item.dport
        store_request(key, item)
    end
end

function handle_outgoing(item)
    if item.is_client == 1 then
        key = item.src.. ":" .. item.sport .. " | " .. item.dst.. ":" .. item.dport
        store_request(key, item)
    else
        key = item.dst.. ":" .. item.dport .. " | " .. item.src.. ":" .. item.sport
        calculate_request_cost(key, item)
    end
end

function process_packet(item)
    -- ignore tcp flow packet
    if item.len == 0 then
        return
    end

    if item.incoming == 1 then
        handle_incoming(item)
    else
        handle_outgoing(item)
    end
end
