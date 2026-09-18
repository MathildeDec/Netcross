-- netcross_capwap_fortinet.lua — Post-dissecteur CAPWAP Fortinet (Job 30, issue #30)
--
-- Fortinet utilise des extensions vendor-specific dans le canal data CAPWAP
-- (UDP 5247) que le dissecteur natif de Wireshark ne decode pas :
--
--   - Vendor ID 12356 (Fortinet, IANA enterprise number)
--   - Payload types proprietaires pour configuration WTP, info station,
--     statistiques radio, etc.
--
-- Ce script s'enregistre comme post-dissecteur sur les trames CAPWAP data
-- et ajoute des champs protocolaires Fortinet visibles dans la sortie EK
-- JSON de tshark (-T ek), exploitables par pcap_parser.tunnels.
--
-- Installation : copier ce fichier dans le repertoire plugins de tshark
-- (ou utiliser -X lua_script:netcross_capwap_fortinet.lua).
--
-- Limitation connue : le canal de controle (UDP 5246) est chiffre DTLS en
-- pratique chez Fortinet -- aucune dissection possible cote data. Ce
-- post-dissecteur ne cible QUE le canal data (UDP 5247) non chiffre.

-- Variables de protocole
local netcross_fortinet = Proto("fortinet_capwap", "Fortinet CAPWAP Vendor Extensions")

-- Champs exposes
local pf_vendor_id = ProtoField.uint32("fortinet_capwap.vendor_id", "Fortinet Vendor ID", base.DEC)
local pf_payload_type = ProtoField.uint16("fortinet_capwap.payload_type", "Fortinet Payload Type", base.HEX)
local pf_payload_length = ProtoField.uint16("fortinet_capwap.payload_length", "Fortinet Payload Length", base.DEC)
local pf_payload_data = ProtoField.bytes("fortinet_capwap.payload_data", "Fortinet Payload Data")
local pf_wtp_serial = ProtoField.string("fortinet_capwap.wtp_serial", "Fortinet WTP Serial")
local pf_station_count = ProtoField.uint16("fortinet_capwap.station_count", "Fortinet Station Count")

netcross_fortinet.fields = {
    pf_vendor_id, pf_payload_type, pf_payload_length, pf_payload_data,
    pf_wtp_serial, pf_station_count,
}

-- Constantes Fortinet CAPWAP
local FORTINET_VENDOR_ID = 12356
local FORTINET_PAYLOAD_CONFIG = 0x0001
local FORTINET_PAYLOAD_STATION = 0x0002
local FORTINET_PAYLOAD_RADIO_STATS = 0x0003
local FORTINET_PAYLOAD_WTP_INFO = 0x0004

-- Port CAPWAP data
local CAPWAP_DATA_PORT = 5247

-- Buffer de dissection
local function dissect_fortinet_payload(buffer, subtree, offset, length)
    local parsed_any = false

    while offset + 8 <= length do
        -- Header TLV Fortinet : vendor_id (4) + payload_type (2) + payload_length (2)
        local vendor_id = buffer(offset, 4):uint()
        local payload_type = buffer(offset + 4, 2):uint()
        local payload_len = buffer(offset + 6, 2):uint()

        if vendor_id ~= FORTINET_VENDOR_ID then
            break
        end

        local tlv_total = 8 + payload_len
        if offset + tlv_total > length then
            break
        end

        local tlv_subtree = subtree:add(buffer(offset, tlv_total),
            "Fortinet Vendor Payload (type=0x" .. string.format("%04X", payload_type) ..
            ", len=" .. payload_len .. ")")

        tlv_subtree:add(pf_vendor_id, buffer(offset, 4))
        tlv_subtree:add(pf_payload_type, buffer(offset + 4, 2))
        tlv_subtree:add(pf_payload_length, buffer(offset + 6, 2))

        -- Decodage specifique par type de payload
        local data_offset = offset + 8
        if payload_len > 0 then
            tlv_subtree:add(pf_payload_data, buffer(data_offset, payload_len))
        end

        if payload_type == FORTINET_PAYLOAD_WTP_INFO and payload_len >= 4 then
            -- WTP serial : chaine ASCII terminee par 0x00
            local serial_end = data_offset
            while serial_end < data_offset + payload_len and serial_end < buffer:len() do
                if buffer(serial_end, 1):uint() == 0 then
                    break
                end
                serial_end = serial_end + 1
            end
            if serial_end > data_offset then
                local serial_str = buffer(data_offset, serial_end - data_offset):string()
                tlv_subtree:add(pf_wtp_serial, serial_str)
            end
        elseif payload_type == FORTINET_PAYLOAD_STATION and payload_len >= 2 then
            local stacount = buffer(data_offset, 2):uint()
            tlv_subtree:add(pf_station_count, stacount)
        end

        parsed_any = true
        offset = offset + tlv_total
    end

    return parsed_any
end

-- Post-dissector : execute apres tous les dissecteurs natifs
function netcross_fortinet.postdissector(buffer, pinfo, tree)
    -- Ne traiter que les trames sur le port CAPWAP data
    local udp_dst = pinfo.dst_port
    local udp_src = pinfo.src_port

    if udp_dst ~= CAPWAP_DATA_PORT and udp_src ~= CAPWAP_DATA_PORT then
        return
    end

    -- Verifier que la couche CAPWAP data est presente dans la trame
    -- Le dissecteur natif a deja decode l'en-tete CAPWAP ; on cherche
    -- les extensions vendor-specific Fortinet dans le payload restant.
    local capwap_layer = buffer(0, buffer:len())
    local length = buffer:len()

    -- Chercher le magic Fortinet (vendor ID 12356 = 0x00 0x00 0x30 0x34)
    -- dans le payload apres l'en-tete CAPWAP standard (8 octets minimum)
    local found = false
    local offset = 8  -- apres en-tete CAPWAP standard

    while offset + 8 <= length do
        local vid = buffer(offset, 4):uint()
        if vid == FORTINET_VENDOR_ID then
            local subtree = tree:add(netcross_fortinet, buffer(offset, length - offset),
                "Fortinet CAPWAP Vendor Extensions")
            found = dissect_fortinet_payload(buffer, subtree, offset, length)
            if found then
                pinfo.cols.protocol = "Fortinet-CAPWAP"
                pinfo.cols.info:append(" [Fortinet CAPWAP]")
            end
            break
        end
        offset = offset + 1
    end
end

-- Enregistrement comme post-dissecteur
register_postdissector(netcross_fortinet)
