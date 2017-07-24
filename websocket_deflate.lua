--
-- https://github.com/grzeg1/websocket_deflate_postdissector
--

local zlib=require 'zlib'

zlibPrefix = "\x78\x01"

tcp_stream = Field.new("tcp.stream")
websocket_payload = Field.new("websocket.payload")
websocket_rsv = Field.new("websocket.rsv")

websocket_pmd_proto = Proto("websocket_pmd", "WebSocket permessage-deflate postdissector")
websocket_pmd_payload_f = ProtoField.bytes("websocket_pmd.payload", "Inflated payload")
websocket_pmd_proto.fields = {websocket_pmd_payload_f}

local streams
local frame_data

function websocket_pmd_proto.init()
  streams = {}
  frame_data = {}
end

-- function to "postdissect" each frame
function websocket_pmd_proto.dissector(buffer, pinfo, tree)
    -- if we've already processed this frame, return stored data
    -- decompression is stateful so we don't want to process again
    local stored_payloads = frame_data[pinfo.number]
    if stored_payloads ~= nil then
        for i,b in ipairs(stored_payloads) do
            local tvb = ByteArray.tvb(b, "Inflated payload")
            tree:add(websocket_pmd_payload_f, tvb:range())
        end
        return
    end

    -- check for WebSocket payloads in this frame
    local websocket_payloads = { websocket_payload() }
    if #websocket_payloads == 0 then
        return
    end

    -- look up zlib state for this TCP stream
    local stream = tcp_stream()()
    local streamData = streams[stream]
    if (streamData == nil) then
        -- new TCP stream; initialize zlib state
        local direction1InflateStream = zlib.inflate()
        direction1InflateStream(zlibPrefix)
        local direction2InflateStream = zlib.inflate()
        direction2InflateStream(zlibPrefix)
        streamData = { direction1InflateStream=direction1InflateStream,
                       direction2InflateStream=direction2InflateStream,
                       direction1Src=pinfo.src,
                       direction1SrcPort=pinfo.src_port }
        streams[stream] = streamData
    end

    -- determine direction (client-server or server-client)
    local inflateStream;
    if ((pinfo.src == streamData.direction1Src) and
            (pinfo.src_port == streamData.direction1SrcPort)) then
        inflateStream = streamData.direction1InflateStream
    else
        inflateStream = streamData.direction2InflateStream
    end

    -- process all Websocket payloads
    websocket_pmd_payloads = {}
    for i,payload in ipairs(websocket_payloads) do
        local data = payload.range:bytes():raw().."\0\0\xff\xff"
        local inflated = inflateStream(data)
        local b = ByteArray.new()
        b:set_size(#inflated)
        for i=1,#inflated do
            b:set_index(i-1,inflated:byte(i))
        end
        local tvb = ByteArray.tvb(b, "Inflated payload")
        tree:add(websocket_pmd_payload_f, tvb:range())
        table.insert(websocket_pmd_payloads, b)
    end

    -- save decompressed payloads for future invocations
    -- decompression is stateful so we don't want to process again
    frame_data[pinfo.number] = websocket_pmd_payloads
end

register_postdissector(websocket_pmd_proto)
