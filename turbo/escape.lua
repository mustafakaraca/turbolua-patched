--- Turbo.lua Escape module
--
-- Copyright John Abrahamsen 2011, 2012, 2013 < JhnAbrhmsn@gmail.com >
--
-- "Permission is hereby granted, free of charge, to any person obtaining a copy of
-- this software and associated documentation files (the "Software"), to deal in
-- the Software without restriction, including without limitation the rights to
-- use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
-- of the Software, and to permit persons to whom the Software is furnished to do
-- so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE."

local json = require('cjson.safe')

local escape = {} -- escape namespace

--- JSON stringify a table.
-- @param t Value to JSON encode.
-- @note May raise a error if table could not be decoded.
function escape.json_encode(t)
    return json.encode(t)
end

--- Decode a JSON string to table.
-- @param s (String) JSON enoded string to decode into
-- Lua primitives.
-- @return (Table)
function escape.json_decode(s)
    return json.decode(s)
end

do
    local ffi = require('ffi')
    local ffi_C = ffi.C
    local ffi_cast = ffi.cast
    local ffi_string = ffi.string
    local ffi_copy = ffi.copy
    local sbyte = string.byte

    local escape_buf_len = 0
    local escape_buf = nil

    local function realloc_buffer(size)
        if escape_buf_len == 0 then
            escape_buf_len = 16
        end
        while escape_buf_len < size do
            escape_buf_len = escape_buf_len * 2
        end
        escape_buf = ffi_cast('uint8_t *', ffi_C.realloc(escape_buf, escape_buf_len))
        assert(escape_buf ~= nil, 'realloc')
    end

    do
        local mark = sbyte('%', 1)
        local amark = sbyte('a', 1)
        local fmark = sbyte('f', 1)
        local Amark = sbyte('A', 1)
        local Fmark = sbyte('F', 1)
        local zeromark = sbyte('0', 1)
        local ninemark = sbyte('9', 1)

        function escape.unescape(s)
            local idx = 0
            local i = 0
            local slen = #s
            while i < slen do
                i = i + 1
                local b = sbyte(s, i)
                if b == mark and (i + 2) <= slen then
                    local v1 = sbyte(s, i + 1)
                    if v1 >= zeromark and v1 <= ninemark then
                        v1 = v1 - zeromark
                    elseif v1 >= amark and v1 <= fmark then
                        v1 = v1 - amark + 10
                    elseif v1 >= Amark and v1 <= Fmark then
                        v1 = v1 - Amark + 10
                    else
                        goto noescape
                    end
                    local v2 = sbyte(s, i + 2)
                    if v2 >= zeromark and v2 <= ninemark then
                        v2 = v2 - zeromark
                    elseif v2 >= amark and v2 <= fmark then
                        v2 = v2 - amark + 10
                    elseif v2 >= Amark and v2 <= Fmark then
                        v2 = v2 - Amark + 10
                    else
                        goto noescape
                    end
                    b = 16 * v1 + v2
                    i = i + 2
                end
                ::noescape::
                if escape_buf_len < (idx + 2) then
                    realloc_buffer(idx + 2)
                end
                escape_buf[idx] = b
                idx = idx + 1
            end
            escape_buf[idx] = 0
            return ffi_string(escape_buf, idx)
        end
    end

    local function escape_by_table(s, t)
        local idx = 0
        for i = 1, #s do
            local b = sbyte(s, i)
            local e = t[b]
            if e then
                local l = #e
                if escape_buf_len < (idx + l + 2) then
                    realloc_buffer(idx + l + 2)
                end
                ffi_copy(escape_buf + idx, e)
                idx = idx + l
            else
                if escape_buf_len < (idx + 2) then
                    realloc_buffer(idx + 2)
                end
                escape_buf[idx] = b
                idx = idx + 1
            end
        end
        escape_buf[idx] = 0
        return ffi_string(escape_buf, idx)
    end

    do
        local escape_table = {}
        for i = 0, 255 do
            if string.char(i):find('[A-Za-z0-9_]') then
                escape_table[i] = false
            else
                escape_table[i] = string.format("%%%02x", i)
            end
        end

        --- Encodes a string into its escaped hexadecimal representation.
        -- @param s (String) String to escape.
        function escape.escape(s)
            assert("Expected string in argument #1.")
            return escape_by_table(s, escape_table)
        end
    end

    --- Encodes the HTML entities in a string. Helpfull to avoid XSS.
    -- @param s (String) String to escape.
    do
        local escape_chars = "\">/<'&"
        local escape_table = {
            ["&"] = "&amp;",
            ["<"] = "&lt;",
            [">"] = "&gt;",
            ['"'] = "&quot;",
            ["'"] = "&#39;",
            ["/"] = "&#47;",
        }

        local html_escape_table = {}
        for i = 0, 255 do
            html_escape_table[i] = false
        end
        for i = 1, #escape_chars do
            local b = escape_chars:byte(i)
            html_escape_table[b] = assert(escape_table[string.char(b)])
        end

        function escape.html_escape(s)
            assert("Expected string in argument #1.")
            return escape_by_table(s, html_escape_table)
        end
    end

    do
        local whitespace = {}
        for i = 0, 255 do
            if string.char(i):find("%s") then
                whitespace[i] = true
            else
                whitespace[i] = false
            end
        end

        -- Remove leading whitespace from string.
        -- @param s String
        function escape.ltrim(s)
            local n = 1
            while n <= #s and whitespace[sbyte(s, n)] do n = n + 1 end
            return s:sub(n)
        end

        -- Remove trailing and leading whitespace from string.
        -- @param s String
        function escape.rtrim(s)
            local n = #s
            while n > 0 and whitespace[sbyte(s, n)] do n = n - 1 end
            return s:sub(1, n)
        end

        function escape.trim(s)
            local nstart, nend = 1, #s
            while nstart <= nend and whitespace[sbyte(s, nstart)] do nstart = nstart + 1 end
            while nend >= nstart and whitespace[sbyte(s, nend)] do nend = nend - 1 end
            return s:sub(nstart, nend)
        end
    end
end

----- Very Fast MIME BASE64 Encoding / Decoding Routines
--------------- authored by Jeff Solinsky
do
    local ffi = require'ffi'
    local bit = jit and require "bit" or require "bit32"
    local rshift = bit.rshift
    local lshift = bit.lshift
    local bor = bit.bor
    local band = bit.band
    local floor = math.floor

    local mime64chars = ffi.new("uint8_t[64]",
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    local mime64lookup = ffi.new("uint8_t[256]")
    ffi.fill(mime64lookup, 256, 0xFF)
    for i=0,63 do
        mime64lookup[mime64chars[i]]=i
    end

    local u8arr= ffi.typeof'uint8_t[?]'
    local u8ptr=ffi.typeof'uint8_t*'

    --- Base64 decode a string or a FFI char *.
    -- @param str (String or char*) Bytearray to decode.
    -- @param sz (Number) Length of string to decode, optional if str is a Lua string
    -- @return (String) Decoded string.
    function escape.base64_decode(str, sz)
        if (type(str)=="string") and (sz == nil) then sz=#str end
        local m64, b1 -- value 0 to 63, partial byte
        local bin_arr=ffi.new(u8arr, floor(bit.rshift(sz*3,2)))
        local mptr = ffi.cast(u8ptr,bin_arr) -- position in binary mime64 output array
        local bptr = ffi.cast(u8ptr,str)
        local i = 0
        while true do
            repeat
                if i >= sz then goto done end
                m64 = mime64lookup[bptr[i]]
                i=i+1
            until m64 ~= 0xFF -- skip non-mime characters like newlines
            b1=lshift(m64, 2)
            repeat
                if i >= sz then goto done end
                m64 = mime64lookup[bptr[i]]
                i=i+1
            until m64 ~= 0xFF -- skip non-mime characters like newlines
            mptr[0] = bor(b1,rshift(m64, 4)); mptr=mptr+1
            b1 = lshift(m64,4)
            repeat
                if i >= sz then goto done end
                m64 = mime64lookup[bptr[i]]
                i=i+1
            until m64 ~= 0xFF -- skip non-mime characters like newlines
            mptr[0] = bor(b1,rshift(m64, 2)); mptr=mptr+1
            b1 = lshift(m64,6)
            repeat
                if i >= sz then goto done end
                m64 = mime64lookup[bptr[i]]
                i=i+1
            until m64 ~= 0xFF -- skip non-mime characters like newlines
            mptr[0] = bor(b1, m64); mptr=mptr+1
        end
    ::done::
        return ffi.string(bin_arr, (mptr-bin_arr))
    end


    local mime64shorts=ffi.new('uint16_t[4096]')
    for i=0,63 do
        for j=0,63 do
            local v
            if ffi.abi("le") then
                v=mime64chars[j]*256+mime64chars[i]
            else
                v=mime64chars[i]*256+mime64chars[j]
            end
            mime64shorts[i*64+j]=v
        end
    end

    local u16arr = ffi.typeof"uint16_t[?]"
    local crlf16 = ffi.new("uint16_t[1]")
    if ffi.abi("le") then
        crlf16[0] = (0x0A*256)+0x0D
    else
        crlf16[0] = (0x0D*256)+0x0A
    end
    local eq=string.byte('=')
    --- Base64 encode binary data of a string or a FFI char *.
    -- @param str (String or char*) Bytearray to encode.
    -- @param sz (Number) Length of string to encode, optional if str is a Lua string
    -- @param disable_break (Bool) Do not break result with newlines, optional
    -- @return (String) Encoded base64 string.
    function escape.base64_encode(str, sz, disable_break)
        if (type(str)=="string") and (sz == nil) then sz=#str end
        local outlen = floor(sz*2/3)
        outlen = outlen + floor(outlen/19)+3
        local m64arr=ffi.new(u16arr,outlen)
        local l,p,v=0,0
        local bptr = ffi.cast(u8ptr,str)
        local c = disable_break and -1 or 38 -- put a new line after every 76 characters
        local i,k=0,0
        ::while_3bytes::
            if i+3>sz then goto break3 end
            v=bor(lshift(bptr[i],16),lshift(bptr[i+1],8),bptr[i+2])
            i=i+3
            ::encode_last3::
            if c==k then
                m64arr[k]=crlf16[0]
                k=k+1
                c=k+38 -- 76 /2 = 38
            end
            m64arr[k]=mime64shorts[rshift(v,12)]
            m64arr[k+1]=mime64shorts[band(v,4095)]
            k=k+2
            goto while_3bytes
        ::break3::
        if l>0 then
            -- Add trailing equal sign padding
            if l==1 then
                -- 1 byte encoded needs two trailing equal signs
                m64arr[k-1]=bor(lshift(eq,8),eq)
            else
                -- 2 bytes encoded needs one trailing equal sign
                (ffi.cast(u8ptr,m64arr))[lshift(k,1)-1]=eq
            end
        else
            l=sz-i -- get remaining len (1 or 2 bytes)
            if l>0 then
                v=lshift(bptr[i],16)
                if l==2 then v=bor(v,lshift(bptr[i+1],8)) end
                goto encode_last3
            end
        end
        return ffi.string(m64arr,lshift(k,1))
    end
end

return escape
