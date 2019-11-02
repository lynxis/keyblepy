
evlock = Proto("evlock", "evlock")

local types = {
  [0x00] = "FRAGMENT_ACK",
  [0x06] = "CLOSE_CONNECTION",
  [0x87] = "COMMAND",
  [0x03] = "CONNECTION_INFO",
  [0x02] = "CONNECTION_REQUEST",
  [0x05] = "STATUS_CHANGED_NOTIFICATION",
  [0x83] = "STATUS_INFO",
  [0x81] = "ANSWER_WITH_SECURITY",
  [0x01] = "ANSWER_WITHOUT_SECURITY",
  [0x04] = "PAIRING_REQUEST",
  [0x82] = "STATUS_REQUEST",
  [0x8f] = "USER_INFO",
  [0x90] = "USER_NAME_SET",
}
local answer_types = {
  [0x80] = "Failed",
  [0x81] = "Success",
}

local myfield = ProtoField.new("Transaction ID", "myproto.trans_id", ftypes.UINT8)
local f_fragment_status = ProtoField.new("Fragment status", "evlock.fragment_status",ftypes.UINT8)
local f_type = ProtoField.new("Message Type", "evlock.type", ftypes.UINT8, types)
local f_answer = ProtoField.new("Answer", "evlock.answer", ftypes.UINT8, answer_types)
local f_userid = ProtoField.new("UserID", "evlock.userid", ftypes.UINT8)
local f_bootver = ProtoField.new("Bootloader Version", "evlock.bootversion", ftypes.UINT16)
local f_appver = ProtoField.new("Application Version", "evlock.appversion", ftypes.UINT16)
local f_local_nounce = ProtoField.new("Local Session Nounce", "evlock.local_nounce", ftypes.UINT64)
local f_remote_nounce = ProtoField.new("Remote Session Nounce", "evlock.remote_nounce", ftypes.UINT64)
evlock.fields = { f_fragment_status, f_type, f_answer, f_userid, f_bootver, f_appver, f_local_nounce, f_remote_nounce }


function evlock.dissector(buffer, pinfo, tree)
  local status = buffer(0, 1):uint()
  local msg_type = buffer(1, 1):uint()
  local payload_len = buffer:len() - 2

  pinfo.cols.protocol = "evlock"
  pinfo.cols.info = types[msg_type]

  local subtree = tree:add(evlock, buffer(), "evlock")
  subtree:add(f_fragment_status, buffer(0, 1))

  -- support only non-fragmented packets
  if status ~= 0x80 then
    string.format("%s %s", pinfo.cols.info, "Fragment")
    return
  end

  subtree:add(f_type, buffer(1, 1))

  if types[msg_type] == "ANSWER_WITHOUT_SECURITY" then
    subtree:add_packet_field(f_answer, buffer(2, 1), 0)
    local value = buffer(2, 1):uint()
    pinfo.cols.info = string.format("%s (%s)", pinfo.cols.info, answer_types[value])
  elseif types[msg_type] == "CONNECTION_INFO" then
    subtree:add_packet_field(f_userid, buffer(2, 1), 0)
    subtree:add_packet_field(f_remote_nounce, buffer(3, 8), ENC_LITTLE_ENDIAN)
    subtree:add_packet_field(f_bootver, buffer(11, 1), 0)
    subtree:add_packet_field(f_appver, buffer(13, 1), 0)
  elseif types[msg_type] == "CONNECTION_REQUEST" then
    subtree:add_packet_field(f_userid, buffer(2, 1), 0)
    subtree:add_packet_field(f_remote_nounce, buffer(3, 8), ENC_LITTLE_ENDIAN)
  end

end

bl_table = DissectorTable.get("bluetooth.uuid")
bl_table:add("3141dd40-15db-11e6-a24b-0002a5d5c51b", evlock) -- transmit
bl_table:add("359d4820-15db-11e6-82bd-0002a5d5c51b", evlock) -- recv
bl_table:add("58e06900-15d8-11e6-b737-0002a5d5c51b", evlock) -- lock service
