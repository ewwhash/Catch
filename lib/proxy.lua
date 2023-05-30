local chacha20, base64 = ... 
local handles, cache, invoke = {}, {}, (component or require and require("component") or error("no component library")).invoke

------------------------------------------------------------------------------ Misc ------------------------------------------------------------------------------

local function encrypt(data, key, nonce)
    local encrypted = {}

    for i = 1, math.ceil(#data / 64) do
        table.insert(encrypted, chacha20.encrypt(key, i, nonce, data:sub(i * 64 - 63, i * 64)))
    end
    
    return table.concat(encrypted)
end

local function segments(path)
    local parts, current, up = {}
    for part in path:gmatch("[^\\/]+") do
        current, up = part:find("^%.?%.$")
        if current then
            if up == 2 then
                table.remove(parts)
            end
        else
            table.insert(parts, part)
        end
    end
    return parts
end

local function prettyPath(path)
    return "/" .. table.concat(segments(path), "/")
end

local function mergeString(str, from, value)
    return table.concat{str:sub(1, from), value, str:sub(from + #value, #str)}
end

------------------------------------------------------------------------------ Filesystem ------------------------------------------------------------------------------

local function getEncryptedPath(key, nonce, workingDirectory, path)
    local parts = segments(path)
    
    for i = 1, #parts do
        parts[i] = base64.encode(encrypt(parts[i], key, nonce))
    end

    return workingDirectory .. table.concat(parts, "/")
end

local function decryptFromByte(address, key, nonce, handle, byte, count)
    local startBlock = math.floor(byte / 64) + 1
    local startByte = math.floor(byte / 64) * 64
    local needToRead

    if count then
        needToRead = math.ceil((byte + count) / 64) * 64 - startByte
    else
        needToRead = math.huge
    end

    if byte > cache[handles[handle].path].size then
        return {}, 0, startByte, startBlock
    else
        local rawData, readed, chunk, tmpHandle, close = {}, 0

        if handles[handle].mode == "r" or handles[handle].mode == "rb" then
            tmpHandle = handle
        else
            tmpHandle = invoke(address, "open", handles[handle].mappedPath, "r")
            close = true
        end

        invoke(address, "seek", tmpHandle, "set", startByte)

        while true do
            chunk = invoke(address, "read", tmpHandle, needToRead - #rawData)

            if chunk then
                table.insert(rawData, chunk)
                readed = readed + #chunk
            else
                break
            end

            if readed >= needToRead then
                break
            end
        end

        if close then
            invoke(address, "close", tmpHandle)
        end
        local data = {}

        if readed > 0 then
            local rawDataAsStr = table.concat(rawData)

            for i = 1, math.ceil(readed / 64) do
                local block = i + startBlock - 1
                table.insert(data, chacha20.encrypt(key, block, nonce, rawDataAsStr:sub(i * 64 - 63, i * 64)))
            end
        end

        return data, readed, startByte, startBlock
    end
end

local function spaceUsed(address)
    return invoke(address, "spaceUsed")
end

local function open(address, key, nonce, workingDirectory, path, mode)
    checkArg(1, path, "string")
    checkArg(2, mode, "string", "nil")
    path = prettyPath(path)
    mode = mode or "r"
    local mappedPath = getEncryptedPath(key, nonce, workingDirectory, path)
    local handle = invoke(address, "open", mappedPath, mode)
    
    if handle then
        if not cache[path] then
            cache[path] = {
                size = invoke(address, "size", mappedPath),
                handlesOpened = 1
            }
        end

        handles[handle] = {
            path = path,
            mode = mode,
            mappedPath = mappedPath,
            offset = 0
        }

        return handle
    end

    return nil, path
end

local function seek(address, key, nonce, workingDirectory, handle, whence, offset)
    checkArg(1, handle, "number", "table")
    checkArg(2, whence, "string")
    checkArg(3, offset, "number")
    
    if handles[handle] then
        local newOffset

        if whence == "set" then
            newOffset = offset
        elseif whence == "cur" then
            newOffset = handles[handle].offset + offset
        elseif whence == "end" then
            newOffset = cache[handles[handle].path].size + offset
        else
            error("invalid mode")
        end

        if newOffset > -1 then
            handles[handle].offset = newOffset
        else
            return nil, "Negative seek offset"
        end

        return newOffset
    end

    return nil, "bad file descriptor"
end

local function makeDirectory(address, key, nonce, workingDirectory, path)
    checkArg(1, path, "string")
    return invoke(address, "makeDirectory", getEncryptedPath(key, nonce, workingDirectory, path))
end

local function exists(address, key, nonce, workingDirectory, path)
    checkArg(1, path, "string")
    return invoke(address, "exists", getEncryptedPath(key, nonce, workingDirectory, path))
end

local function isReadOnly(address)
    return invoke(address, "isReadOnly")
end

local function write(address, key, nonce, workingDirectory, handle, value)
    checkArg(1, handle, "number", "table")
    checkArg(2, value, "string")

    if handles[handle] then
        local data, dataLength, startByte, startBlock = decryptFromByte(address, key, nonce, handle, handles[handle].offset)

        data = mergeString(table.concat(data), handles[handle].offset - startByte, value)
        local encrypted = {}

        for i = 1, math.ceil(#data / 64) do
            local block = i + startBlock - 1
            table.insert(encrypted, chacha20.encrypt(key, block, nonce, data:sub(i * 64 - 63, i * 64)))
        end

        encrypted = table.concat(encrypted)

        invoke(address, "seek", handle, "set", startByte)
        invoke(address, "write", handle, encrypted)

        handles[handle].offset = handles[handle].offset + #value
        cache[handles[handle].path].size = startByte + #encrypted

        return true
    end

    return nil, "bad file descriptor"
end

local function spaceTotal(address)
    return invoke(address, "spaceTotal")
end

local function isDirectory(address, key, nonce, workingDirectory, path)
    checkArg(1, path, "string")
    return invoke(address, "isDirectory", getEncryptedPath(key, nonce, workingDirectory, path))
end

local function rename(address, key, nonce, workingDirectory, from, to)
    checkArg(1, from, "string")
    checkArg(2, to, "string")
    from, to = prettyPath(from), prettyPath(to)
    return invoke(address, "rename", getEncryptedPath(key, nonce, workingDirectory, from), getEncryptedPath(key, nonce, workingDirectory, to))
end

local function list(address, key, nonce, workingDirectory, path)
    checkArg(1, path, "string")
    local mappedPath = getEncryptedPath(key, nonce, workingDirectory, path)
    local files = invoke(address, "list", mappedPath)

    if files then
        for i = 1, #files do
            local file, count = files[i]:gsub("/", "")
            files[i] = encrypt(base64.decode(file), key, nonce) .. (count > 0 and "/" or "")
        end

        return files
    end
end

local function lastModified(address, key, nonce, workingDirectory, path)
    checkArg(1, path, "string")
    return invoke(address, "lastModified", getEncryptedPath(key, nonce, workingDirectory, path))
end

local function getLabel(address)
    return invoke(address, "getLabel")
end

local function remove(address, key, nonce, workingDirectory, path)
    checkArg(1, path, "string")
    return invoke(address, "remove", getEncryptedPath(key, nonce, workingDirectory, path))
end

local function close(address, key, nonce, workingDirectory, handle)
    checkArg(1, handle, "number", "table")

    if handles[handle] then
        invoke(address, "close", handle)
        cache[handles[handle].path].handlesOpened = cache[handles[handle].path].handlesOpened - 1
        if cache[handles[handle].path].handlesOpened == 0 then
            cache[handles[handle].path] = nil
        end
        handles[handle] = nil
        return
    end

    return nil, "bad file descriptor"
end

local function size(address, key, nonce, workingDirectory, path)
    checkArg(1, path, "string")
    return invoke(address, "size", getEncryptedPath(key, nonce, workingDirectory, path))
end

local function read(address, key, nonce, workingDirectory, handle, count)
    checkArg(1, handle, "number", "table")
    checkArg(2, count, "number")
    count = count > 2048 and 2048 or count

    if handles[handle] and handles[handle].mode == "r" or handles[handle].mode == "rb" then
        if handles[handle].offset >= cache[handles[handle].path].size then
            return nil
        end

        local data, dataLength, startByte = decryptFromByte(address, key, nonce, handle, handles[handle].offset, count)
        local from = handles[handle].offset - startByte
        data = table.concat(data):sub(handles[handle].offset - startByte + 1, from + count)
        handles[handle].offset = handles[handle].offset + count
        return data
    end

    return nil, "bad file descriptor"
end

local function setLabel(address, key, nonce, workingDirectory, label)
    checkArg(1, label, "string")
    return invoke(address, "setLabel", label)
end

local function getProxy(address, key, nonce, workingDirectory)
    return {
        address = address,
        spaceUsed = function(...)
            return spaceUsed(address, key, nonce, workingDirectory, ...)
        end,
        open = function(...)
            return open(address, key, nonce, workingDirectory, ...)
        end,
        seek = function(...)
            return seek(address, key, nonce, workingDirectory, ...)
        end,
        makeDirectory = function(...)
            return makeDirectory(address, key, nonce, workingDirectory, ...)
        end,
        exists = function(...)
            return exists(address, key, nonce, workingDirectory, ...)
        end,
        isReadOnly = function(...)
            return isReadOnly(address, key, nonce, workingDirectory, ...)
        end,
        write = function(...)
            return write(address, key, nonce, workingDirectory, ...)
        end,
        spaceTotal = function(...)
            return spaceTotal(address, key, nonce, workingDirectory, ...)
        end,
        isDirectory = function(...)
            return isDirectory(address, key, nonce, workingDirectory, ...)
        end,
        rename = function(...)
            return rename(address, key, nonce, workingDirectory, ...)
        end,
        list = function(...)
            return list(address, key, nonce, workingDirectory, ...)
        end,
        lastModified = function(...)
            return lastModified(address, key, nonce, workingDirectory, ...)
        end,
        getLabel = function(...)
            return getLabel(address, key, nonce, workingDirectory, ...)
        end,
        remove = function(...)
            return remove(address, key, nonce, workingDirectory, ...)
        end,
        close = function(...)
            return close(address, key, nonce, workingDirectory, ...)
        end,
        size = function(...)
            return size(address, key, nonce, workingDirectory, ...)
        end,
        read = function(...)
            return read(address, key, nonce, workingDirectory, ...)
        end,
        setLabel = function(...)
            return setLabel(address, key, nonce, workingDirectory, ...)
        end
    }
end

-- local drive = getProxy(require'component'.get('485'), 'local a,b,c,d,e=table.insert,tab', "local functi", "/encrypted/")
-- local filesystem = require("filesystem")
-- local mountPoint = "/mnt/catch-" .. drive.address:sub(1, 3)
-- filesystem.umount(mountPoint)
-- filesystem.mount(drive, mountPoint)
-- print("Mount point " .. mountPoint)

return {
    getProxy = getProxy
}
