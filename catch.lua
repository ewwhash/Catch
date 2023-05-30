local component = component or require and require("component") or error("no component library")
local computer = computer or require and require("computer") or error("no computer library")
local unicode = unicode or require and require("unicode") or error("no unicode library")
computer.setArchitecture("Lua 5.3")

local config = {
    workingDirectory = "/catch/",
    headerPath = "/.catch_header",
    iterTime = 5000, -- Default iter time
    scale = 1 -- UI scale (Only for stand-alone version, not working on tablets)
}

local pbkdf2 = load([[local a,b,c,d,e,f,g,h,i,j,k=string.len,string.gsub,string.format,string.byte,string.char,string.rep,table.concat,math.ceil,(computer or require and require("computer")or error("no computer library")).pullSignal,{},{}local function l(m,n)return m<<n&0xFFFFFFFF|(m>>32-n)end;local function o(m,p,q)return q~(m&(p~q))end;local function r(m,p,q)return m&(p|q)|(p&q)end;local function s(m,p,q,t)return m*0x1000000+p*0x10000+q*0x100+t end;local function u(m)local v,w,x,y=m%256;m=(m-v)/256;w=m%256;m=(m-w)/256;x=m%256;y=(m-x)/256;return y,x,w,v end;local function z(A)return A:gsub("..",function(B)return e(tonumber(B,16))end)end;local function C(D)local E,F,G,H,I,J,K,L,M,N=e(0x80),#D+1+8,0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0,{}M=("\0"):rep(-F%64)N=e(0,0,0,0,u(#D*8))D=D..E..M..N;assert(#D%64==0)for O=1,#D,64 do local P,m,p,q,t,Q=O,G,H,I,J,K;for R=0,15 do L[R]=s(d(D,P,P+3))P=P+4 end;for R=16,79 do L[R]=l(L[R-3]~L[R-8]~L[R-14]~L[R-16],1)end;for R=0,79 do local S,T;if R<=19 then S=o(p,q,t)T=0x5A827999 elseif R<=39 then S=p~q~t;T=0x6ED9EBA1 elseif R<=59 then S=r(p,q,t)T=0x8F1BBCDC else S=p~q~t;T=0xCA62C1D6 end;local U=(l(m,5)+S+Q+T+L[R])%0x100000000;Q=t;t=q;q=l(p,30)p=m;m=U end;G=(G+m)%0x100000000;H=(H+p)%0x100000000;I=(I+q)%0x100000000;J=(J+t)%0x100000000;K=(K+Q)%0x100000000 end;return("%08x%08x%08x%08x%08x"):format(G,H,I,J,K)end;local function V(D)return z(C(D))end;for R=0,0xff do j[e(R)]=e(0x5c~R)k[e(R)]=e(0x36~R)end;local function W(X,Y)if#X>64 then X=V(X)end;local Z,_=X:gsub('.',k)..f(e(0x36),64-#X),X:gsub('.',j)..f(e(0x5c),64-#X)return C(_..V(Z..Y))end;local function a0(D)local a1={}for R=1,a(D)do a1[R]=d(D,R)end;return a1 end;local function a2(a3)local a1={}for R=1,#a3 do a1[R]=e(a3[R])end;a1=g(a1)return a1 end;local function a4(a5,a6)local a7,a8={}for R=1,a6 do a8=a6+1-R;a7[a8]=e(a5&255)a5=a5>>8 end;a7=g(a7)return a7 end;return{deriveKey=function(a9,aa,ab,ac,ad,ae)local af,ag,ah,a7,ai="",ad,h(ab/20)ae(0)for R=1,ah do a7,ai=a0(aa..a4(R,4)),{}for aj=1,ac do a7=a0(z(W(a9,a2(a7))))if aj>1 then for T,ak in pairs(ai)do ai[T]=ak~a7[T]end else ai=a7 end;ag=ag-1;if ag==0 then if ae then ae(math.ceil((aj/ac+R-1)/ah*100))end;ag=ad;i(0)end end;af=af..a2(ai)end;ae(100)return af:sub(1,ab)end}]])()
local chacha20 = load([[local a,b=table.insert,table.concat;local function c(d,e,f,g,h)local i,j,k,l=d[e],d[f],d[g],d[h]local m;i=i+j&0xffffffff;m=l~i;l=m<<16|(m>>16)&0xffffffff;k=k+l&0xffffffff;m=j~k;j=m<<12|(m>>20)&0xffffffff;i=i+j&0xffffffff;m=l~i;l=m<<8|(m>>24)&0xffffffff;k=k+l&0xffffffff;m=j~k;j=m<<7|(m>>25)&0xffffffff;d[e],d[f],d[g],d[h]=i,j,k,l;return d end;local n={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}local o={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}local p=function(q,r,s)local d=n;local t=o;d[1],d[2],d[3],d[4]=0x61707865,0x3320646e,0x79622d32,0x6b206574;for u=1,8 do d[u+4]=q[u]end;d[13]=r;for u=1,3 do d[u+13]=s[u]end;for u=1,16 do t[u]=d[u]end;for v=1,10 do c(t,1,5,9,13)c(t,2,6,10,14)c(t,3,7,11,15)c(t,4,8,12,16)c(t,1,6,11,16)c(t,2,7,12,13)c(t,3,8,9,14)c(t,4,5,10,15)end;for u=1,16 do d[u]=d[u]+t[u]&0xffffffff end;return d end;local w="<I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4"local function x(q,r,s,y,z)local A=#y-z+1;if A<64 then local B=string.sub(y,z)y=B..string.rep('\0',64-A)z=1 end;local C=table.pack(string.unpack(w,y,z))local D=p(q,r,s)for u=1,16 do C[u]=C[u]~D[u]end;local E=string.pack(w,table.unpack(C))if A<64 then E=string.sub(E,1,A)end;return E end;local F=function(q,r,s,y)local G=table.pack(string.unpack("<I4I4I4I4I4I4I4I4",q))local H=table.pack(string.unpack("<I4I4I4",s))local m={}local z=1;while z<=#y do a(m,x(G,r,H,y,z))z=z+64;r=r+1 end;local I=b(m)return I end;return{encrypt=F}]])()
local base64 = load([[local a='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_'local function b(c)return(c:gsub('.',function(d)local e,a='',d:byte()for f=8,1,-1 do e=e..(a%2^f-a%2^(f-1)>0 and'1'or'0')end;return e end)..'0000'):gsub('%d%d%d?%d?%d?%d?',function(d)if#d<6 then return''end;local g=0;for f=1,6 do g=g+(d:sub(f,f)=='1'and 2^(6-f)or 0)end;return a:sub(g+1,g+1)end)..({'','==','='})[#c%3+1]end;local function h(c)c=string.gsub(c,'[^'..a..'=]','')return c:gsub('.',function(d)if d=='='then return''end;local e,i='',a:find(d)-1;for f=6,1,-1 do e=e..(i%2^f-i%2^(f-1)>0 and'1'or'0')end;return e end):gsub('%d%d%d?%d?%d?%d?%d?%d?',function(d)if#d~=8 then return''end;local g=0;for f=1,8 do g=g+(d:sub(f,f)=='1'and 2^(8-f)or 0)end;return string.char(g)end)end;return{encode=b,decode=h}]])()
local catch = load([[local a,b=...local c,d,e={},{},(component or require and require("component")or error("no component library")).invoke;local function f(g,h,i)local j={}for k=1,math.ceil(#g/64)do table.insert(j,a.encrypt(h,k,i,g:sub(k*64-63,k*64)))end;return table.concat(j)end;local function l(m)local n,o,p={}for q in m:gmatch("[^\\/]+")do o,p=q:find("^%.?%.$")if o then if p==2 then table.remove(n)end else table.insert(n,q)end end;return n end;local function r(m)return"/"..table.concat(l(m),"/")end;local function s(t,u,v)return table.concat{t:sub(1,u),v,t:sub(u+#v,#t)}end;local function w(h,i,x,m)local n=l(m)for k=1,#n do n[k]=b.encode(f(n[k],h,i))end;return x..table.concat(n,"/")end;local function y(z,h,i,A,B,C)local D=math.floor(B/64)+1;local E=math.floor(B/64)*64;local F;if C then F=math.ceil((B+C)/64)*64-E else F=math.huge end;if B>d[c[A].path].size then return{},0,E,D else local G,H,I,J,K={},0;if c[A].mode=="r"or c[A].mode=="rb"then J=A else J=e(z,"open",c[A].mappedPath,"r")K=true end;e(z,"seek",J,"set",E)while true do I=e(z,"read",J,F-#G)if I then table.insert(G,I)H=H+#I else break end;if H>=F then break end end;if K then e(z,"close",J)end;local g={}if H>0 then local L=table.concat(G)for k=1,math.ceil(H/64)do local M=k+D-1;table.insert(g,a.encrypt(h,M,i,L:sub(k*64-63,k*64)))end end;return g,H,E,D end end;local function N(z)return e(z,"spaceUsed")end;local function O(z,h,i,x,m,P)checkArg(1,m,"string")checkArg(2,P,"string","nil")m=r(m)P=P or"r"local Q=w(h,i,x,m)local A=e(z,"open",Q,P)if A then if not d[m]then d[m]={size=e(z,"size",Q),handlesOpened=1}end;c[A]={path=m,mode=P,mappedPath=Q,offset=0}return A end;return nil,m end;local function R(z,h,i,x,A,S,T)checkArg(1,A,"number","table")checkArg(2,S,"string")checkArg(3,T,"number")if c[A]then local U;if S=="set"then U=T elseif S=="cur"then U=c[A].offset+T elseif S=="end"then U=d[c[A].path].size+T else error("invalid mode")end;if U>-1 then c[A].offset=U else return nil,"Negative seek offset"end;return U end;return nil,"bad file descriptor"end;local function V(z,h,i,x,m)checkArg(1,m,"string")return e(z,"makeDirectory",w(h,i,x,m))end;local function W(z,h,i,x,m)checkArg(1,m,"string")return e(z,"exists",w(h,i,x,m))end;local function X(z)return e(z,"isReadOnly")end;local function Y(z,h,i,x,A,v)checkArg(1,A,"number","table")checkArg(2,v,"string")if c[A]then local g,Z,E,D=y(z,h,i,A,c[A].offset)g=s(table.concat(g),c[A].offset-E,v)local j={}for k=1,math.ceil(#g/64)do local M=k+D-1;table.insert(j,a.encrypt(h,M,i,g:sub(k*64-63,k*64)))end;j=table.concat(j)e(z,"seek",A,"set",E)e(z,"write",A,j)c[A].offset=c[A].offset+#v;d[c[A].path].size=E+#j;return true end;return nil,"bad file descriptor"end;local function _(z)return e(z,"spaceTotal")end;local function a0(z,h,i,x,m)checkArg(1,m,"string")return e(z,"isDirectory",w(h,i,x,m))end;local function a1(z,h,i,x,u,a2)checkArg(1,u,"string")checkArg(2,a2,"string")u,a2=r(u),r(a2)return e(z,"rename",w(h,i,x,u),w(h,i,x,a2))end;local function a3(z,h,i,x,m)checkArg(1,m,"string")local Q=w(h,i,x,m)local a4=e(z,"list",Q)if a4 then for k=1,#a4 do local a5,C=a4[k]:gsub("/","")a4[k]=f(b.decode(a5),h,i)..(C>0 and"/"or"")end;return a4 end end;local function a6(z,h,i,x,m)checkArg(1,m,"string")return e(z,"lastModified",w(h,i,x,m))end;local function a7(z)return e(z,"getLabel")end;local function a8(z,h,i,x,m)checkArg(1,m,"string")return e(z,"remove",w(h,i,x,m))end;local function K(z,h,i,x,A)checkArg(1,A,"number","table")if c[A]then e(z,"close",A)d[c[A].path].handlesOpened=d[c[A].path].handlesOpened-1;if d[c[A].path].handlesOpened==0 then d[c[A].path]=nil end;c[A]=nil;return end;return nil,"bad file descriptor"end;local function a9(z,h,i,x,m)checkArg(1,m,"string")return e(z,"size",w(h,i,x,m))end;local function aa(z,h,i,x,A,C)checkArg(1,A,"number","table")checkArg(2,C,"number")C=C>2048 and 2048 or C;if c[A]and c[A].mode=="r"or c[A].mode=="rb"then if c[A].offset>=d[c[A].path].size then return nil end;local g,Z,E=y(z,h,i,A,c[A].offset,C)local u=c[A].offset-E;g=table.concat(g):sub(c[A].offset-E+1,u+C)c[A].offset=c[A].offset+C;return g end;return nil,"bad file descriptor"end;local function ab(z,h,i,x,ac)checkArg(1,ac,"string")return e(z,"setLabel",ac)end;local function ad(z,h,i,x)return{address=z,spaceUsed=function(...)return N(z,h,i,x,...)end,open=function(...)return O(z,h,i,x,...)end,seek=function(...)return R(z,h,i,x,...)end,makeDirectory=function(...)return V(z,h,i,x,...)end,exists=function(...)return W(z,h,i,x,...)end,isReadOnly=function(...)return X(z,h,i,x,...)end,write=function(...)return Y(z,h,i,x,...)end,spaceTotal=function(...)return _(z,h,i,x,...)end,isDirectory=function(...)return a0(z,h,i,x,...)end,rename=function(...)return a1(z,h,i,x,...)end,list=function(...)return a3(z,h,i,x,...)end,lastModified=function(...)return a6(z,h,i,x,...)end,getLabel=function(...)return a7(z,h,i,x,...)end,remove=function(...)return a8(z,h,i,x,...)end,close=function(...)return K(z,h,i,x,...)end,size=function(...)return a9(z,h,i,x,...)end,read=function(...)return aa(z,h,i,x,...)end,setLabel=function(...)return ab(z,h,i,x,...)end}end;return{getProxy=ad}]])(chacha20, base64)

------------------------------------------------------------------------------------------------------------------------------------------------

local function encrypt(data, key, nonce)
    local encrypted = {}

    for i = 1, math.ceil(#data / 64) do
        table.insert(encrypted, chacha20.encrypt(key, i, nonce, data:sub(i * 64 - 63, i * 64)))
    end

    return table.concat(encrypted)
end

local function randomString(length)
	local str = {}

	for i = 1, length do
		table.insert(str, string.char(math.random(97, 122)))
	end

	return table.concat(str)
end

local function unserialize(data)
    local chunk, err = load("return " .. data)

    if chunk then
        return chunk()
    end

    return false, err
end

local function rawRead(invoke, address, path)
    local success = invoke(address, "open", path)
    local handle, data, chunk = success, ""

    if handle then
        while true do
            chunk = invoke(address, "read", handle, math.huge)

            if chunk then
                data = data .. chunk
            else
                break
            end
        end

        invoke(address, "close", handle)
        return data
    end

    return false
end

local function rawWrite(invoke, address, path, data)
    local handle = invoke(address, "open", path, "w")
    invoke(address, "write", handle, data)
    invoke(address, "close", handle)
end

local function processSubdir(invoke, address, path, oldPath, onFile)
    local list = invoke(address, "list", path)

    if list then
        for i = 1, #list do
            local name, count = list[i]:gsub("/", "")
            local isDirectory = count > 0 and true or false
            local newName = onFile(name, isDirectory, path, oldPath) or name

            if isDirectory then
                processSubdir(invoke, address, path .. newName.. "/", oldPath .. name .. "/", onFile)
            end
        end
    end
end

local function processFileFallback(invoke, address, fullPath, spaceUsed, encrypted, key, nonce, encryptingStatus)
    local rawHandle = invoke(address, "open", fullPath, "r")
    local encryptedHandle = invoke(address, "open", fullPath, "a")
    local block = 1
    invoke(address, "seek", encryptedHandle, "set", 0)

    while true do
        local chunk = invoke(address, "read", rawHandle, math.huge)

        if chunk then
            encryptingStatus(math.min(100, math.ceil(encrypted / spaceUsed * 100)), true)

            for i = 1, math.ceil(#chunk / 64) do
                invoke(address, "write", encryptedHandle, chacha20.encrypt(key, block, nonce, chunk:sub(i * 64 - 63, i * 64)))
                block = block + 1
            end

            encrypted = encrypted + #chunk
        else
            break
        end
    end

    invoke(address, "close", rawHandle)
    invoke(address, "close", encryptedHandle)
    return encrypted
end

local function processFile(invoke, address, fullPath, encrypted, key, nonce)
    rawWrite(invoke, address, fullPath, encrypt(rawRead(invoke, address, fullPath), key, nonce))
    return encrypted + invoke(address, "size", fullPath)
end

local function processFileXOR(invoke, address, fullPath, spaceUsed, encrypted, key, nonce, encryptingStatus, lowMemoryStatus)
    local success, result = pcall(processFile, invoke, address, fullPath, encrypted, key, nonce)

    if success then
        return result
    else -- Low memory fallback
        lowMemoryStatus()
        for i = 1, 10 do -- Collecting garbage
            computer.pullSignal(0)
        end

        return processFileFallback(invoke, address, fullPath, spaceUsed, encrypted, key, nonce, encryptingStatus), true
    end
end

local function encryptDrive(address, key, nonce, header, encryptingStatus, lowMemoryStatus)
    local spaceUsed, encrypted = 0, 0
    encryptingStatus(0)
    processSubdir(component.invoke, address, "/", "/", function(name, isDirectory, path)
        spaceUsed = spaceUsed + component.invoke(address, "size", path .. name)
    end)

    processSubdir(component.invoke, address, "/", "/", function(name, isDirectory, path, decryptedPath)
        encryptingStatus(math.min(100, math.ceil(encrypted / spaceUsed * 100)))
        local encryptedName = base64.encode(encrypt(name, key, nonce))
        local fullPath = path .. name
        local encryptedPath = path .. encryptedName

        if not isDirectory then
            encrypted = processFileXOR(component.invoke, address, fullPath, spaceUsed, encrypted, key, nonce, encryptingStatus, lowMemoryStatus)
        end

        component.invoke(address, "rename", fullPath, encryptedPath)
        return encryptedName
    end)

    local list = component.invoke(address, "list", "/")
    component.invoke(address, "makeDirectory", config.workingDirectory)

    for i = 1, #list do
        component.invoke(address, "rename", list[i], config.workingDirectory .. list[i])
    end

    rawWrite(component.invoke, address, "/init.lua", rawRead(component.invoke, computer.tmpAddress(), "/catch_init.lua"))
    rawWrite(component.invoke, address, config.headerPath, header)
    encryptingStatus(100)
end


local function decryptDrive(invoke, address, key, nonce, decryptingStatus, lowMemoryStatus)
    local spaceUsed, decrypted = 0, 0
    decryptingStatus(0)
    processSubdir(invoke, address, config.workingDirectory, "/", function(name, isDirectory, path)
        spaceUsed = spaceUsed + invoke(address, "size", path .. name)
    end)

    processSubdir(invoke, address, config.workingDirectory, "/", function(name, isDirectory, path)
        local decryptedName = encrypt(base64.decode(name), key, nonce)
        decryptingStatus(math.min(100, math.ceil(decrypted / spaceUsed * 100)))
        local fullPath = path .. name
        local decryptedPath = path .. decryptedName

        if not isDirectory then
            decrypted = processFileXOR(invoke, address, fullPath, spaceUsed, decrypted, key, nonce, decryptingStatus, lowMemoryStatus)
        end

        invoke(address, "rename", fullPath, decryptedPath, key, nonce)
        return decryptedName
    end)

    invoke(address, "remove", config.headerPath)
    invoke(address, "remove", "/init.lua")
    local list = invoke(address, "list", config.workingDirectory)

    for i = 1, #list do
        invoke(address, "rename", config.workingDirectory .. list[i], "/" .. list[i])
    end

    if #invoke(address, "list", config.workingDirectory) == 0 then
        invoke(address, "remove", config.workingDirectory)
    end
    decryptingStatus(100)
end

local function getHeader(key, nonce, iterTime)
    return ("{nonce='%s',magic='%s',iterTime=%s}"):format(
        nonce,
        base64.encode(encrypt("magic", key, nonce)),
        iterTime
    )
end

local function prepare(address, passphrase, deriving)
    local header, err = unserialize(assert(rawRead(component.invoke, address, config.headerPath), config.headerPath .. " doesn't exists"))

    if header then
        local key = pbkdf2.deriveKey(passphrase, header.nonce, 32, header.iterTime, 500, deriving)
        header.magic = base64.decode(header.magic)

        if header.magic == encrypt("magic", key, header.nonce) then
            return key, header.nonce
        end

        return false
    end

    error(err)
end

--------------------------------------------------------------------------------------------------------------------------------------------------

local function overrideInvoke(proxy, passphrase, key, nonce)
    local invoke = component.invoke
    proxy.getCatchProperties = function(password)
        if password == passphrase then
            return {
                direct_invoke = invoke,
                key = key,
                nonce = nonce,
            }
        end

        return false
    end

    component.invoke = function(address, method, ...)
        checkArg(1, address, "string")
        checkArg(2, method, "string")

        if address == proxy.address then
            if proxy[method] then
                return proxy[method](...)
            end

            error("no such method")
        end

        return invoke(address, method, ...)
    end
end

local function openos(...)
    local filesystem = require("filesystem")
    local term = require("term")
    local gpu = component.getPrimary("gpu")
    local options = select(2, require("shell").parse(...))
    local address, key, nonce, rootDir

    if options.h or options.help then
        return print(("Usage: catch [-u --umount] [-e --encrypt] [-d --decrypt] [--iter-time=N (default: %s)] [--passphrase=passphrase] [--drive=UUID]"):format(config.iterTime))
    end

    options["iter-time"] = tonumber(options["iter-time"]) or config.iterTime

    local function read(mask)
        if mask then
            local text = require("term").read{pwchar = "•"}
            return text and text:gsub("\n", "") or os.exit()
        end

        return io.read() or os.exit()
    end

    local function progressBar(percent)
        local y = select(2, term.getCursor())
        gpu.setForeground(0xffffff)
        gpu.fill(1, y, 160, 1, " ")
        gpu.set(1, y, ("["))
        gpu.set(32 - 2, y, "]")
        gpu.set(2, y, ("="):rep(math.floor(math.min(percent, 100) / 100 * (32 - 5))) .. ">")
        gpu.set(32, y, percent .. "%")
    end

    local function getPassphrase(verify)
        local passphrase

        if options.passphrase and type(options.passphrase) == "string" and #options.passphrase > 0 then
            return options.passphrase
        end

        repeat
            io.write(("Enter passphrase for %s: "):format(address:sub(1, 3)))
            passphrase = read(true)
            io.write("\n")
        until passphrase ~= ""

        if verify then
            io.write("Verify passphrase: ")
            if passphrase == read(true) then
                io.write("\n")
                return passphrase
            end

            print("\nPassphrases do not match")
            os.exit()
        end

        return passphrase
    end


    local function openDrive()
        local y = select(2, term.getCursor())
        local filesystem = require("filesystem")
        local mountPoint = "/mnt/catch-" .. address:sub(1, 3)
        local proxy = catch.getProxy(address, key, nonce, config.workingDirectory)
        filesystem.umount(mountPoint)
        filesystem.mount(proxy, mountPoint)
        print("Mount point " .. mountPoint)
    end

    if options.drive then
        if #options.drive == 0 then
            return io.stderr:write("Option 'drive' is empty (use --help or -h for help)")
        end

        address = component.get(options.drive)

        if not address then
            return io.stderr:write(("No drive %s (use --help or -h for help)"):format(options.drive))
        end
    else
        address = filesystem.get(os.getenv("PWD")).address
    end

    rootDir = filesystem.get("/").address == address and true or false

    if options.umount or options.u then
        return filesystem.umount("/mnt/catch-" .. address:sub(1, 3))
    end

    if options.encrypt or options.e then
        if rootDir and pcall(component.invoke, address, "getCatchProperties") then
            return io.stderr:write("Can't encrypt already encrypted root filesystem")
        end
        if component.invoke(address, "exists", config.headerPath) then
            return io.stderr:write("Can't encrypt already encrypted drive")
        end
        print("This will encrypt " .. (rootDir and "root filesystem" or "drive " .. address))
        local passphrase = getPassphrase(true)
        component.invoke(computer.tmpAddress(), "remove", "/")
        os.execute("cp -f " .. os.getenv("_") .. " /tmp/catch_init.lua")
        print("Deriving key...")
        nonce = randomString(12)
        key = pbkdf2.deriveKey(passphrase, nonce, 32, options["iter-time"], 500, function(percent) progressBar(percent) end)
        print("\nEncrypting...")

        if math.ceil((component.invoke(address, "spaceTotal") - component.invoke(address, "spaceUsed")) / 1024) > 64 then
            encryptDrive(address, key, nonce, getHeader(key, nonce, options["iter-time"]), function(percent) progressBar(percent) end, function()
                gpu.setForeground(0xff0000)
                gpu.set(37, select(2, term.getCursor()), "LOW MEMORY")
            end)
            io.write("\n")

            if rootDir then
                return overrideInvoke(catch.getProxy(address, key, nonce, config.workingDirectory), passphrase, key, nonce)
            end

            return openDrive()
        end

        io.stderr:write("Not enough space, aborting")
    end

    if rootDir and pcall(component.invoke, address, "getCatchProperties") then
        if options.decrypt or options.d then
            print("This will decrypt root filesystem")
            local properties = component.invoke(address, "getCatchProperties", getPassphrase())

            if properties then
                print("Decrypting...")
                decryptDrive(properties.direct_invoke, address, properties.key, properties.nonce, function(percent) progressBar(percent) end, function()
                    gpu.setForeground(0xff0000)
                    gpu.set(37, select(2, term.getCursor()), "LOW MEMORY")
                end)
                component.invoke = properties.direct_invoke
                return io.write("\n")
            end

            return io.stderr:write("Invalid passphrase")
        end

        io.stderr:write("Can't open already decrypted root filesystem")
    end

    if component.invoke(address, "exists", config.headerPath) then
        if options.decrypt or options.d then
            print("This will decrypt drive " .. address)
        end
        local passphrase = getPassphrase()
        print("Deriving key...")
        key, nonce = prepare(address, passphrase, function(percent) progressBar(percent) end)
        io.write("\n")

        if not key then
            return io.stderr:write("No key available with this passphrase")
        end

        if options.decrypt or options.d then
            print("Decrypting...")
            decryptDrive(component.invoke, address, key, nonce, function(percent) progressBar(percent) end, function()
                gpu.setForeground(0xff0000)
                gpu.set(37, select(2, term.getCursor()), "LOW MEMORY")
            end)
            filesystem.umount("/mnt/catch-" .. address:sub(1, 3))
            return io.write("\n")
        end

        return openDrive()
    end

    io.stderr:write(("Can't open drive %s, %s doesn't exists"):format(address:sub(1, 3), config.headerPath))
end

local function mineos(...)
    local GUI = require("GUI")
    local system = require("System")
    local filesystem = require("Filesystem")
    local rootfs = filesystem.get("/")
    local currentScriptPath = system.getCurrentScript()
    local isEnabled = pcall(component.invoke, rootfs.address, "getCatchProperties")
    local currentScriptProxy = filesystem.get(currentScriptPath)
    local thirdparty = currentScriptProxy.address ~= rootfs.address

    if thirdparty and (...) ~= "rootfs" then
        local workspace = system.getWorkspace()
        local container = GUI.addBackgroundContainer(workspace, true, true, "Enter passphrase for " .. currentScriptProxy.address:sub(1, 3))
        local input = container.layout:addChild(GUI.input(2, 2, 36, 3, 0xEEEEEE, 0x555555, 0x999999, 0xFFFFFF, 0x2D2D2D, "", "", nil, "•"))
        input:startInput()
        input.onInputFinished = function()
            if #input.text == 0 then
                return container:remove()
            end

            container.label.text = "Deriving key"
            local passphrase = input.text
            input:remove()
            local progressBar = container.layout:addChild(GUI.progressBar(1, 1, 40, 0x66DB80, 0x0, 0xE1E1E1, 0, true))
            local key, nonce = prepare(currentScriptProxy.address, passphrase, function(percent)
                progressBar.value = percent
                workspace:draw()
            end)

            if key then
                local mountPoint = "/Mounts/Catch-" .. currentScriptProxy.address:sub(1, 3) .. "/"
                local proxy = catch.getProxy(currentScriptProxy.address, key, nonce, config.workingDirectory)
                filesystem.unmount(mountPoint)
                filesystem.mount(proxy, mountPoint)
                GUI.alert("Mount point " .. mountPoint)
                container:remove()
                local handler

                handler = require("event").addHandler(function(e1, e2, e3)
                    if e1 == "component_removed" and e2 == proxy.address then
                        filesystem.unmount(proxy)
                        computer.pushSignal("component_removed")
                        require("event").removeHandler(handler)
                    end
                end)

                return computer.pushSignal("component_added")
            end

            GUI.alert("No key available with this passphrase")
        end
    else
        local workspace, window = system.addWindow(GUI.titledWindow(1, 1, 52, 17, "Catch", true))
        if thirdparty then
            window.menu = {}
        end
        window.actionButtons.maximize.hidden = true
        window.actionButtons.minimize.hidden = thirdparty
        window:addChild(GUI.image(22, 4, require("Image").fromString([[08040000FF 0000FF 0081FF⣴0081FF⠶0081FF⠶0081FF⣦0000FF 0000FF 0000FF 0081FF⢀FF8100⣿0081FF⣀0081FF⣀FF8100⣿0081FF⡀0000FF 0000FF 0081FF⢸0081FF⣿FF8100⣿FF8100⣿0081FF⣿0081FF⡇0000FF 0000FF 0081FF⢸0081FF⣿FF8100⣿FF8100⣿0081FF⣿0081FF⡇0000FF ]])))
        local encryptionSwitch = window:addChild(GUI.switchAndLabel(14, 10, 25, 8, 0x66DB80, 0xE1E1E1, 0xFFFFFF, 0xA5A5A5, "Encryption:", isEnabled))

        encryptionSwitch.switch.onStateChanged = function()
            local container = GUI.addBackgroundContainer(workspace, true, true, "Enter passphrase for " .. rootfs.address:sub(1, 3))
            local input = container.layout:addChild(GUI.input(2, 2, 36, 3, 0xEEEEEE, 0x555555, 0x999999, 0xFFFFFF, 0x2D2D2D, "", "", nil, "•"))
            input:startInput()
            input.onInputFinished = function()
                if #input.text == 0 then
                    container:remove()
                    workspace:draw()
                    return encryptionSwitch.switch:setState(not encryptionSwitch.switch.state)
                end

                local passphrase = input.text
                input:remove()
                if isEnabled then
                    local properties = component.invoke(rootfs.address, "getCatchProperties", passphrase)

                    if properties then
                        container.label.text = "Decrypting"
                        local progressBar = container.layout:addChild(GUI.progressBar(1, 1, 40, 0x66DB80, 0x0, 0xE1E1E1, 0, true))
                        local lowMemory = container.layout:addChild(GUI.text(1, 1, 0xff0000, "LOW MEMORY"))
                        lowMemory.hidden = true
                        workspace:draw()

                        decryptDrive(properties.direct_invoke, rootfs.address, properties.key, properties.nonce, function(percent, isLowMemory)
                            lowMemory.hidden = isLowMemory
                            progressBar.value = percent
                            workspace:draw()
                        end, function()
                            lowMemory.hidden = false
                            workspace:draw()
                        end)
                        component.invoke = properties.direct_invoke
                        isEnabled = false
                    else
                        GUI.alert("Invalid passphrase")
                    end

                    return container:remove()
                end

                container.label.text = "Deriving key"
                local progressBar = container.layout:addChild(GUI.progressBar(1, 1, 40, 0x66DB80, 0x0, 0xE1E1E1, 0, true))
                workspace:draw()
                local nonce = randomString(12)
                local key = pbkdf2.deriveKey(passphrase, nonce, 32, config.iterTime, 500, function(percent)
                    progressBar.value = percent
                    workspace:draw()
                end)
                rawWrite(component.invoke, computer.tmpAddress(), "/catch_init.lua", filesystem.read(currentScriptPath))
                container.label.text = "Encrypting"
                local lowMemory = container.layout:addChild(GUI.text(1, 1, 0xff0000, "LOW MEMORY"))
                lowMemory.hidden = true
                progressBar.value = 0
                workspace:draw()

                if math.ceil((rootfs.spaceTotal() - rootfs.spaceUsed()) / 1024) > 64 then
                    encryptDrive(rootfs.address, key, nonce, getHeader(key, nonce, config.iterTime), function(percent, isLowMemory)
                        lowMemory.hidden = isLowMemory
                        progressBar.value = percent
                        workspace:draw()
                    end, function()
                        lowMemory.hidden = false
                        workspace:draw()
                    end)
                    overrideInvoke(catch.getProxy(rootfs.address, key, nonce, config.workingDirectory), passphrase, key, nonce)
                    isEnabled = true
                    return container:remove()
                end

                GUI.alert("Not enough space, aborting")
            end

            workspace:draw()
        end

        window:addChild(GUI.textBox(8, 14, 40, 1, nil, 0xA5A5A5, {"Catch secures the data on your disk by encrypting its contents automatically"}, 1, 0, 0, true, true))
    end
end

local function standalone(...)
    local text, cursorPosition, textCutFrom, cursorBlinkState, hidden, gpu, width, height, colorScheme, monochrome, inputWidth, address, key, nonce = "", 1, 1, 1, 2

    local colors = {
        monochrome = {
            background = 0x0,
            foreground = 0xffffff,
            inputBackground = 0xffffff,
            inputForeground = 0x0,
            cursor = 0x0,
            progressBar = 0x0,
            filledProgressBar = 0xffffff
        },
        other = {
            background = 0x1e1e1e,
            foreground = 0xffffff,
            inputBackground = 0xffffff,
            inputForeground = 0x000000,
            cursor = 0x00a8ff,
            progressBar = 0xc7c7c7,
            filledProgressBar = 0xffffff
        }
    }

    local function set(x, y, string, background, foreground)
        gpu.setBackground(background or colorScheme.background)
        gpu.setForeground(foreground or colorScheme.foreground)
        gpu.set(x, y, string)
    end

    local function centrize(len)
        return math.floor(width / 2 - len / 2) + 1
    end

    local function centrizedSet(y, text, foreground)
        gpu.setBackground(colorScheme.background)
        gpu.fill(1, y, width, 1, " ")
        set(centrize(unicode.len(text)), y, text, nil, foreground or colorScheme.foreground)
    end

    local function sleep(timeout, breakCode, onBreak)
        local deadline = computer.uptime() + (timeout or math.huge)

        repeat
            local signalType, _, _, code = computer.pullSignal(deadline - computer.uptime())

            if signalType == "key_down" and (code == breakCode or breakCode == 0) then
                return onBreak and onBreak()
            end
        until computer.uptime() < deadline
    end

    local function clear()
        gpu.setBackground(colorScheme.background)
        gpu.fill(1, 1, width, height, " ")
    end

    local function status(text, onBreak)
        clear()
        centrizedSet(height / 2, text)
        sleep(math.huge, 0, onBreak)
    end

    local function progressBar(percent)
        set(centrize(31), height / 2 + 1, ("━"):rep(31), nil, colorScheme.progressBar)
        set(centrize(31), height / 2 + 1, ("━"):rep(math.floor(math.min(percent, 100) / 100 * 31)), colorScheme.background, colorScheme.filledProgressBar)
    end

    local function setCursorPosition(newPosition)
        if newPosition < 1 then
            newPosition = 1
        elseif newPosition > unicode.len(text) + 1 then
            newPosition = unicode.len(text) + 1
        end

        if newPosition > textCutFrom + (inputWidth - 3) then
            textCutFrom = textCutFrom + newPosition - (textCutFrom + (inputWidth - 3))
        elseif newPosition < textCutFrom then
            textCutFrom = newPosition
        end

        cursorPosition = newPosition
    end

    local function bindGPU()
        gpu = component.list("gpu")()

        if gpu then
            local screen = component.list("screen")()
            gpu = component.proxy(gpu)
            if gpu.maxDepth() == 1 then
                monochrome = true
                colorScheme = colors.monochrome
            else
                colorScheme = colors.other
            end
            width, height = gpu.maxResolution()

            if not gpu.getScreen() then
                gpu.bind(screen)
            end

            gpu.setBackground(colorScheme.background)
            gpu.fill(1, 1, width, height, " ")

            if not component.list("tablet")() and not monochrome then
                local aspectWidth, aspectHeight, proportion = component.invoke(screen, "getAspectRatio")
                proportion = 2*(16*aspectWidth-4.5)/(16*aspectHeight-4.5)
                if proportion > width / height then
                    height = width / proportion
                else
                    width = height * proportion
                end

                local scale = gpu.getDepth() <= 4 and 1 or config.scale
                width, height = math.floor(width * scale), math.floor(height * scale)
            end

            gpu.fill(1, 1, width, height, " ")
            return gpu.setResolution(width, height)
        end

        error("No GPU")
    end

    bindGPU()
    address = component.invoke(component.list("eeprom")(), "getData")

    if component.invoke(address, "exists", config.headerPath) then
        inputWidth = monochrome and 30 or 40

        while true do
            clear()
            centrizedSet(monochrome and height / 2 - 1 or height / 2 - 2, "A password is required to access " .. address:sub(1, 3))
            gpu.setBackground(colorScheme.inputBackground)
            gpu.fill(centrize(inputWidth), height / 2 + (monochrome and 1 or 0), inputWidth, monochrome and 1 or 3, " ")
            if hidden > 1 then
                set(centrize(inputWidth) + 1, height / 2 + 1, unicode.sub(hidden == 2 and ("•"):rep(unicode.len(text)) or text, textCutFrom, textCutFrom + inputWidth - 3), colorScheme.inputBackground, colorScheme.inputForeground)
            end

            if cursorBlinkState then
                if hidden == 1 then
                    set(centrize(inputWidth) + 1, height / 2 + 1, "┃", colorScheme.inputBackground, colorScheme.cursor)
                else
                    set(centrize(inputWidth) + cursorPosition - textCutFrom + 1, height / 2 + 1, "┃", colorScheme.inputBackground, colorScheme.cursor)
                end
            end
            local signal, _, char, code = computer.pullSignal(0.4)

            if signal == "key_down" then
                if code == 28 and text ~= "" then
                    clear()
                    centrizedSet(height / 2 - 1, "Deriving key")
                    key, nonce = prepare(address, text, function(percent) progressBar(percent) end)

                    if key then
                        overrideInvoke(catch.getProxy(address, key, nonce, config.workingDirectory), text, key, nonce)
                        local bootFiles, bootCandidates, selected = {"/init.lua", "/OS.lua"}, {}, 1

                        for i = 1, #bootFiles do
                            if component.invoke(address, "exists", bootFiles[i]) then
                                table.insert(bootCandidates, bootFiles[i])
                            end
                        end

                        if #bootCandidates == 0 then
                            error("No boot files available")
                        end

                        if #bootCandidates > 1 then
                            local spaces, borderHeight, y = 6, 3, height / 2 + 1

                            while true do
                                clear()
                                centrizedSet(height / 2 - 2, "Select boot entry")
                                local elementsLineLength, x = 0

                                for i = 1, #bootCandidates do
                                    elementsLineLength = elementsLineLength + unicode.len(bootCandidates[i]) + spaces
                                end

                                elementsLineLength = elementsLineLength - spaces
                                x = centrize(elementsLineLength)

                                for i = 1, #bootCandidates do
                                    if selected == i then
                                        gpu.setBackground(colorScheme.foreground)
                                        gpu.fill(x - spaces / 2, y - math.floor(borderHeight / 2), unicode.len(bootCandidates[i]) + spaces, borderHeight, " ")
                                        set(x, y, bootCandidates[i], colorScheme.foreground, colorScheme.background)
                                    else
                                        set(x, y, bootCandidates[i], colorScheme.background, colorScheme.foreground)
                                    end

                                    x = x + unicode.len(bootCandidates[i]) + spaces
                                end

                                local signal, _, _, code = computer.pullSignal()

                                if signal == "key_down" then
                                    if code == 28 then
                                        break
                                    elseif code == 203 then
                                        selected = selected == 1 and #bootFiles or selected - 1
                                    elseif code == 205 then
                                        selected = selected == #bootFiles and 1 or selected + 1
                                    end
                                end
                            end
                        end

                        clear()
                        centrizedSet(height / 2, "Booting " .. bootCandidates[selected])

                        local data = rawRead(component.invoke, address, bootCandidates[selected])
                        assert(#data > 0, bootCandidates[selected] .. " is empty")
                        return assert(load(data, "=catch" .. bootCandidates[selected]))()
                    end

                    status("No key available with this passphrase")
                elseif code == 211 then
                    text = ""
                    setCursorPosition(1)
                elseif code == 203 then
                    setCursorPosition(cursorPosition - 1)
                elseif code == 205 then
                    setCursorPosition(cursorPosition + 1)
                elseif code == 41 then
                    if hidden == 3 then
                        hidden = 1
                    else
                        hidden = hidden + 1
                    end
                elseif code == 14 then
                    text = unicode.sub(unicode.sub(text, 1, cursorPosition - 1), 1, -2) .. unicode.sub(text, cursorPosition, -1)
                    setCursorPosition(cursorPosition - 1)
                elseif char >= 32 then
                    text = unicode.sub(text, 1, cursorPosition - 1) .. unicode.char(char) .. unicode.sub(text, cursorPosition, -1)
                    setCursorPosition(cursorPosition + 1)
                end

                cursorBlinkState = true
            elseif signal == "clipboard" then
                text = unicode.sub(text, 1, cursorPosition - 1) .. char .. unicode.sub(text, cursorPosition, -1)
                setCursorPosition(cursorPosition + unicode.len(char))
            elseif not signal then
                cursorBlinkState = not cursorBlinkState
            end
        end
    end

    status(("%s doesn't exists"):format(config.headerPath))
end

local function init(...)
    if _OSVERSION and _OSVERSION:match("OpenOS") then
        return openos(...)
    end

    if require then
        local success, system = pcall(require, "System")

        if success and system and system.getUser then -- MineOS
            return mineos(...)
        end

        error("This OS is not supported")
    end

    standalone(...)
end

init(...)
