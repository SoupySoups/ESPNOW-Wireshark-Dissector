-- Define ESP-NOW Post-Dissector
espnow_postdissector = Proto("ESPNow", "ESP-NOW Post-Dissector")

-- Add preferences
espnow_postdissector.prefs.check_oui = Pref.bool("Drop packets not signed Espressif OUI", true, "This option will cause packets to not process if they have an incorrect OUI.")


-- Define fields
local f_random_bytes = ProtoField.bytes("espnow.random", "Random Bytes (Anti-Relay)")

local f_element_id = ProtoField.uint8("espnow.vs.element_id", "Element ID", base.DEC)
local f_length = ProtoField.uint8("espnow.vs.length", "Length", base.DEC)
local f_oui = ProtoField.uint24("espnow.vs.oui", "OUI", base.HEX)
local f_type = ProtoField.uint8("espnow.vs.type", "Type", base.HEX)

local f_reserved = ProtoField.uint8("espnow.vs.reserved", "Reserved", base.HEX, nil, 0xF0) -- Bits 7-4
local f_version = ProtoField.uint8("espnow.vs.version", "Version", base.DEC, nil, 0x0F) -- Bits 3-0

local f_data = ProtoField.bytes("espnow.vs.data", "Data")

espnow_postdissector.fields = { f_random_bytes, f_element_id, f_length, f_oui, f_type, f_reserved, f_version, f_data }

local data = Field.new("data")

-- Post-dissector function
function espnow_postdissector.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "ESP-NOW"
    pinfo.cols.info = "ESP-NOW Data"

    -- Extract Wireshark's "tagged parameters" field
    local data_field = data()
    if not data_field then return end  -- No tagged parameters, skip

    -- Get the offset where tagged parameters start
    local data_offset = data_field.range():offset()
    local data_length = data_field.range():len()

    if data_length < 11 then return end  -- Too short for ESP-NOW

    -- Extract the ESP-NOW vendor-specific element
    local esp_data = buffer(data_offset, data_length)
    local random_bytes = esp_data(0,4)
    local element_id = esp_data(4,1)
    local length = esp_data(5,1)
    local oui = esp_data(6,3)
    local ptype = esp_data(9,1)

    local resver = esp_data(10,1):le_uint() -- Read as little-endian 16-bit integer

    -- Extract fields using bitwise operations
    local reserved = bit32.rshift(bit32.band(resver, 0x00F0), 4) -- Bits 7-4
    local version = bit32.band(resver, 0x000F) -- Bits 3-0

    -- Check if it's a vendor-specific element (221)
    if element_id:uint() ~= 221 then return end

    -- Check if the OUI is the expected value (0x18fe34)
    if oui:uint() ~= 0x18fe34 and espnow_postdissector.prefs.check_oui then return end

    -- Check if the type is 0x04 (ESP-NOW)
    if ptype:uint() ~= 0x04 then return end

    -- Add ESP-NOW subtree to the Wireshark packet tree
    local esp_tree = tree:add(espnow_postdissector, esp_data, "ESP-NOW Data")
    esp_tree:add(f_random_bytes, random_bytes)

    local vs_tree = esp_tree:add(esp_data(4, data_length-4), "Vendor Specific Data")

    vs_tree:add(f_element_id, element_id)
    vs_tree:add(f_length, length)
    vs_tree:add(f_oui, oui)
    vs_tree:add(f_type, ptype)

    local resver_tree = vs_tree:add(esp_data(10, 1), "Reserved/Version Byte"):append_text(" (" .. resver .. ")")

    resver_tree:add(f_reserved, esp_data(10,1), reserved):append_text(" (" .. reserved .. ")")
    resver_tree:add(f_version, esp_data(10,1), version):append_text(" (" .. version .. ")")

    if data_length > 10 then  -- Too short for ESP-NOW
        vs_tree:add(f_data, esp_data(11, data_length-11), "Data"):append_text(" (" .. (data_length-11) .. " bytes)")
    end
end

-- Register as a post-dissector
register_postdissector(espnow_postdissector)
