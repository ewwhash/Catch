-- https://github.com/somesocks/lua-lockbox
-- The MIT License (MIT)

-- Copyright (c) 2015 James L.

-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:

-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

local len, gsub, format, byte, char, rep, concat, ceil, pullSignal, xor_with_0x5c, xor_with_0x36 = string.len, string.gsub, string.format, string.byte, string.char, string.rep, table.concat, math.ceil, (computer or require and require("computer")or error("no computer library")).pullSignal, {}, {}

local function uint32_lrot(a, bits)
   return ((a << bits) & 0xFFFFFFFF) | (a >> (32 - bits))
end

local function uint32_ternary(a, b, c)
   return c ~ (a & (b ~ c))
end

local function uint32_majority(a, b, c)
   return (a & (b | c)) | (b & c)
end

local function bytes_to_uint32(a, b, c, d)
    return a * 0x1000000 + b * 0x10000 + c * 0x100 + d
end

local function uint32_to_bytes(a)
    local a4, a3, a2, a1 = a % 256
    a = (a - a4) / 256
    a3 = a % 256
    a = (a - a3) / 256
    a2 = a % 256
    a1 = (a - a2) / 256
    return a1, a2, a3, a4
end

local function hex_to_binary(hex)
    return (hex:gsub("..", function(hexval)
       return char(tonumber(hexval, 16))
    end))
end 

local function hash(str)
    local first_append, non_zero_message_bytes, h0, h1, h2, h3, h4, w, second_append, third_append = char(0x80), #str + 1 + 8, 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, {}
    second_append = ("\0"):rep(-non_zero_message_bytes % 64)
    third_append = char(0, 0, 0, 0, uint32_to_bytes(#str * 8))

    str = str .. first_append .. second_append .. third_append
    assert(#str % 64 == 0)

    for chunk_start = 1, #str, 64 do
        local uint32_start, a, b, c, d, e = chunk_start, h0, h1, h2, h3, h4

        for i = 0, 15 do
            w[i] = bytes_to_uint32(byte(str, uint32_start, uint32_start + 3))
            uint32_start = uint32_start + 4
        end

        for i = 16, 79 do
            w[i] = uint32_lrot(w[i - 3] ~ w[i - 8] ~ w[i - 14] ~ w[i - 16], 1)
        end

        for i = 0, 79 do
            local f, k

            if i <= 19 then
                f = uint32_ternary(b, c, d)
                k = 0x5A827999
            elseif i <= 39 then
                f = b ~ c ~ d
                k = 0x6ED9EBA1
            elseif i <= 59 then
                f = uint32_majority(b, c, d)
                k = 0x8F1BBCDC
            else
                f = b ~ c ~ d
                k = 0xCA62C1D6
            end

            local temp = (uint32_lrot(a, 5) + f + e + k + w[i]) % 0x100000000
            e = d
            d = c
            c = uint32_lrot(b, 30)
            b = a
            a = temp
        end

        h0 = (h0 + a) % 0x100000000
        h1 = (h1 + b) % 0x100000000
        h2 = (h2 + c) % 0x100000000
        h3 = (h3 + d) % 0x100000000
        h4 = (h4 + e) % 0x100000000
    end

    return ("%08x%08x%08x%08x%08x"):format(h0, h1, h2, h3, h4)
end

local function hashBinary(str)
    return hex_to_binary(hash(str))
end

for i = 0, 0xff do
   xor_with_0x5c[char(i)] = char(0x5c ~ i)
   xor_with_0x36[char(i)] = char(0x36 ~ i)
end

local function hmac(key, text)
    if #key > 64 then
        key = hashBinary(key)
    end
 
    local key_xord_with_0x36, key_xord_with_0x5c = key:gsub('.', xor_with_0x36) .. rep(char(0x36), 64 - #key), key:gsub('.', xor_with_0x5c) .. rep(char(0x5c), 64 - #key)
    return hash(key_xord_with_0x5c .. hashBinary(key_xord_with_0x36 .. text))
end

local function toBytes(str)
    local tmp = {}
    for i = 1, len(str) do
        tmp[i] = byte(str, i)
    end
    return tmp
end

local function toString(bArray)
    local tmp = {}
    for i = 1, #bArray do
        tmp[i] = char(bArray[i])
    end
    tmp = concat(tmp)
    return tmp
end

local function num2string(l, n)
    local s, idx = {}
    for i = 1, n do
        idx = (n + 1) - i
        s[idx] = char(l & 255)
        l = l >> 8
    end
    s = concat(s)
    return s
end

return {
    deriveKey = function(password, salt, keyLen, iterationCount, yieldOnIter, status)
        local derivedKey, nextYield, blocks, s, out = "", yieldOnIter, ceil(keyLen / 20)
        status(0)

        for i = 1, blocks do
            s, out = toBytes(salt .. num2string(i, 4)), {}
        
            for j = 1, iterationCount do
                s = toBytes(hex_to_binary(hmac(password, toString(s))))
        
                if (j > 1) then
                    for k, v in pairs(out) do
                        out[k] = v ~ s[k]
                    end
                else
                    out = s
                end
        
                nextYield = nextYield - 1

                if nextYield == 0 then
                    if status then
                        status(math.ceil((j / iterationCount + i - 1) / blocks * 100))
                    end
                    nextYield = yieldOnIter
                    pullSignal(0)
                end
            end
        
            derivedKey = derivedKey .. toString(out)
        end

        status(100)

        return derivedKey:sub(1, keyLen)
    end
}