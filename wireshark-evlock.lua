require 'bitop'

evlock = Proto("evlock", "evlock")

local types = {
  [0x00] = "FRAGMENT_ACK",
  [0x01] = "ANSWER_WITHOUT_SECURITY",
  [0x02] = "CONNECTION_REQUEST",
  [0x03] = "CONNECTION_INFO",
  [0x04] = "PAIRING_REQUEST",
  [0x05] = "STATUS_CHANGED_NOTIFICATION",
  [0x06] = "CLOSE_CONNECTION",
  [0x10] = "BOOTLOADER_START_APP",
  [0x11] = "BOOTLOADER_DATA",
  [0x12] = "BOOTLOADER_STATUS",
  [0x81] = "ANSWER_WITH_SECURITY",
  [0x82] = "STATUS_REQUEST",
  [0x83] = "STATUS_INFO",
  [0x84] = "MOUNT_OPTIONS_REQUEST",
  [0x85] = "MOUNT_OPTIONS_INFO",
  [0x86] = "MOUNT_OPTIONS_SET",
  [0x87] = "COMMAND",
  [0x88] = "AUTO_RELOCK_SET",
  [0x8a] = "PAIRING_SET",
  [0x8b] = "USER_LIST_REQUEST",
  [0x8c] = "USER_LIST_INFO",
  [0x8d] = "USER_REMOVE",
  [0x8e] = "USER_INFO_REQUEST",
  [0x8f] = "USER_INFO",
  [0x90] = "USER_NAME_SET",
  [0x91] = "USER_OPTIONS_SET",
  [0x92] = "USER_PROG_REQUEST",
  [0x93] = "USER_PROG_INFO",
  [0x94] = "USER_PROG_SET",
  [0x95] = "AUTO_RELOCK_PROG_REQUEST",
  [0x96] = "AUTO_RELOCK_PROG_INFO",
  [0x97] = "AUTO_RELOCK_PROG_SET",
  [0x98] = "LOG_REQUEST",
  [0x99] = "LOG_INFO",
  [0x9a] = "KEY_BLE_APPLICATION_BOOTLOADER_CALL",
  [0x9b] = "DAYLIGHT_SAVING_TIME_OPTIONS_REQUEST",
  [0x9c] = "DAYLIGHT_SAVING_TIME_OPTIONS_INFO",
  [0x9d] = "DAYLIGHT_SAVING_TIME_OPTIONS_SET",
  [0x9e] = "FACTORY_RESET",
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
local f_bootver_major = ProtoField.new("Bootloader Version Major", "evlock.bootversion_major", ftypes.UINT8)
local f_bootver_minor = ProtoField.new("Bootloader Version Minor", "evlock.bootversion_minor", ftypes.UINT8)
local f_appver_major = ProtoField.new("Application Version Major", "evlock.appversion", ftypes.UINT8)
local f_appver_minor = ProtoField.new("Application Version Minor", "evlock.appversion", ftypes.UINT8)
local f_local_nounce = ProtoField.new("Local Session Nounce", "evlock.local_nounce", ftypes.UINT64)
local f_remote_nounce = ProtoField.new("Remote Session Nounce", "evlock.remote_nounce", ftypes.UINT64)
evlock.fields = { f_fragment_status, f_type, f_answer, f_userid, f_bootver_major, f_bootver_minor, f_appver_major, f_appver_minor, f_local_nounce, f_remote_nounce }

function setContains(set, key)
    return set[key] ~= nil
end

function evlock.dissector(buffer, pinfo, tree)
  local status = buffer(0, 1):uint()
  local msg_type = buffer(1, 1):uint()
  local payload_len = buffer:len() - 2
  local subtree = tree:add(evlock, buffer(), "evlock")

  subtree:add(f_fragment_status, buffer(0, 1))

  pinfo.cols.protocol = "evlock"

  -- support only non-fragmented packets
  -- hack around lua bitwise operator missing in lua < 5.3
  if status < 0x80 then
    -- string.format("%s %s", pinfo.cols.info, "Fragment")
    pinfo.cols.info = "FRAGMENT"
    return
  end

  if setContains(types, msg_type) then
    pinfo.cols.info = types[msg_type]
  else
    pinfo.cols.info = "Unknown Message"
  end

  if status > 0x80 then
    pinfo.cols.info = string.format("%s %s", pinfo.cols.info, "(first Fragment)")
  end

  subtree:add(f_type, buffer(1, 1))

  if types[msg_type] == "ANSWER_WITHOUT_SECURITY" then
    subtree:add_packet_field(f_answer, buffer(2, 1), 0)
    local value = buffer(2, 1):uint()
    pinfo.cols.info = string.format("%s (%s)", pinfo.cols.info, answer_types[value])
  elseif types[msg_type] == "CONNECTION_INFO" then
    subtree:add_packet_field(f_userid, buffer(2, 1), 0)
    subtree:add_packet_field(f_remote_nounce, buffer(3, 8), ENC_LITTLE_ENDIAN)
    -- TODO: subtree:add_packet_field(unknown, buffer(11, 1), 0)
    subtree:add(f_bootver_major, buffer(12, 1), bit.rshift(buffer(12, 1):uint(), 4))
    subtree:add(f_bootver_minor, buffer(12, 1), bit.band(buffer(12, 1):uint(), 0xf))
    subtree:add(f_appver_major, buffer(13, 1), bit.rshift(buffer(13, 1):uint(), 4))
    subtree:add(f_appver_minor, buffer(13, 1), bit.band(buffer(13, 1):uint(), 0xf))

  elseif types[msg_type] == "CONNECTION_REQUEST" then
    subtree:add_packet_field(f_userid, buffer(2, 1), 0)
    subtree:add_packet_field(f_local_nounce, buffer(3, 8), ENC_LITTLE_ENDIAN)
  end

end

bl_table = DissectorTable.get("bluetooth.uuid")
bl_table:add("3141dd40-15db-11e6-a24b-0002a5d5c51b", evlock) -- transmit
bl_table:add("359d4820-15db-11e6-82bd-0002a5d5c51b", evlock) -- recv
bl_table:add("58e06900-15d8-11e6-b737-0002a5d5c51b", evlock) -- lock service
