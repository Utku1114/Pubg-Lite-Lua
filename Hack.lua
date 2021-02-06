function WriteSignatures(targetSignature, overrideSignature, codePage)
  local byteLine = overrideSignature:gsub("%w+", "0x%0,"):sub(1,-2)
  local results = AOBScan(targetSignature, codePage)
  if (results == nil) then  return end
  for i = 0, results.Count-1 do
    local address = getAddress(results.getString(i))
    local lineCode = 'writeBytes('..address..','.. byteLine..')'
    loadstring(lineCode)()
  end
  results.destroy()
end
function recoilon()
  local targetSignature   = '54 73 6C 52 65 63 6F 69 6C 43 6F 6D 70 6F 6E 65 6E 74'
  local overrideSignature = '91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function recoiloff()
  local targetSignature   = '91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91'
  local overrideSignature = '54 73 6C 52 65 63 6F 69 6C 43 6F 6D 70 6F 6E 65 6E 74'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function antenaon()
  local targetSignature   = 'F3 02 B1 42 3F 8E AE 42 EA D2 C9 C2 00 00 80 3F 00 00 80 3F 00 00 80 3F 01'
  local overrideSignature = '00 00 FC 3F 00 00 FC 3F EA D2 C9 C2 00 C0 79 44 00 00 80 3F 00 00 80 3F 01'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function antenaoff()
  local targetSignature   = '00 00 FC 3F 00 00 FC 3F EA D2 C9 C2 00 C0 79 44 00 00 80 3F 00 00 80 3F 01'
  local overrideSignature = 'F3 02 B1 42 3F 8E AE 42 EA D2 C9 C2 00 00 80 3F 00 00 80 3F 00 00 80 3F 01'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function fog()
  local targetSignature   = '46 6F 67'
  local overrideSignature = '91 91 91'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function drivetext()
  local targetSignature   = 'AE C5 9D 74 FF FF'
  local overrideSignature = '00 00 10 41 FF FF 47 42 FF FF C7 41 00 00 00 00'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function grass()
  local targetSignature   = '47 72 61 73 73'
  local overrideSignature = '00 00 00 00 00'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function speedon()
  local targetSignature   = '00 00 80 3F 00 00 80 3F 00 00 80 3F 17 B7 D1 38'
  local overrideSignature = 'E1 7A 94 3F E1 7A 94 3F E1 7A 94 3F 17 B7 D1 38'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function speedoff()
  local targetSignature   = 'E1 7A 94 3F E1 7A 94 3F E1 7A 94 3F 17 B7 D1 38'
  local overrideSignature = '1F 85 8B 3F 1F 85 8B 3F 1F 85 8B 3F 17 B7 D1 38'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function waterinvis()
  local targetSignature   = '5F 5F 57 61 74 65 72'
  local overrideSignature = '91 91 91 91 91 91 91'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function jumpon()
  local targetSignature   = '01 00 00 00 00 00 80 3F 00 00 0C 42 00 80 DD 43 00 00 00 3F 00 00 5C 42 E8'
  local overrideSignature = '01 00 00 00 00 00 40 40 00 00 0C 42 00 40 1C 45 00 00 00 00 00 00 5C 42 E8'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function jumpoff()
  local targetSignature   = '01 00 00 00 00 00 40 40 00 00 0C 42 00 40 1C 45 00 00 00 00 00 00 5C 42 E8'
  local overrideSignature = '01 00 00 00 00 00 80 3F 00 00 0C 42 00 80 DD 43 00 00 00 3F 00 00 5C 42 E8'
  local codePage = '-X*C*W'
  WriteSignatures(targetSignature, overrideSignature, codePage)
end

function whiteflooron()
local targetSignature = '44 65 66 61 75 6C 74 5F 5F 4C 61 6E 64 73 63 61 70 65 4D 61 74 65 72 69 61 6C 49 6E 73 74 61 6E 63 65 43 6F 6E 73 74 61 6E 74'
local overrideSignature = '91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91'
local codePage = '-X*C*W'
WriteSignatures(targetSignature, overrideSignature, codePage)
end

function noobjecton()
local targetSignature = '44 65 66 61 75 6C 74 5F 5F 53 74 61 74 69 63 4D 65 73 68 00'
local overrideSignature = '91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 91 00'
local codePage = '-X*C*W'
WriteSignatures(targetSignature, overrideSignature, codePage)
end

createHotkey(recoilon, VK_INSERT)
createHotkey(recoiloff, VK_DELETE)
createHotkey(antenaon, VK_NUMPAD7)
createHotkey(antenaoff, VK_NUMPAD8)
createHotkey(drivetext, VK_NUMPAD0)
createHotkey(grass, VK_NUMPAD6)
createHotkey(speedon, VK_F5)
createHotkey(speedoff, VK_F6)
createHotkey(waterinvis, VK_NUMPAD6)
createHotkey(jumpon, VK_F8)
createHotkey(jumpoff, VK_F9)
createHotkey(drivetext, VK_NUMPAD0)
createHotkey(whiteflooron, VK_F3)
createHotkey(noobjecton, VK_F4)
