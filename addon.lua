-- HD2-Addon: mods/tongz/mines_combined
local VERSION="1.0.1"
local SPEC={game_sha256="2E2C3B7C2500646DADD5F2B4C6E0504DBB7E7896139F64CDDC0D1813C718F51E",owner_rva=53635984,slot=15799072,stride=44,map="00000000000000000000000000000000193aaaaae2b9ed0c0200000000000000000000000000000000000000000000000000000000000000000000000000000020e3e82294340cf00900000000000000000000000000000000000000000000000000000000000000000000000000000089dd2bb4f7c92ac10400000000000000834426f862062d480300000000000000ba30ad7f404e0404010000000000000030114561b4b9ed6a05000000000000000000000000000000000000000000000000000000000000000000000000000000773d7f13692998a90a0000000000000000000000000000000000000000000000000000000000000000000000000000008eb5338e89e37dc8060000000000000000000000000000000000000000000000b214ec1887e0ae7507000000000000008d5bd16f44eaa731000000000000000052a2a92329e132bf0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005cd26e7b03fda2250c00000000000000092f6c6dbade68290800000000000000",rows={{index=9,hex="898a1a028a3de8fd6f12833acdcc4c3e0000803e9f98a0426e01000000000000000000000000000000000000"},{index=11,hex="898a1a028a3de8fd6f12833acdcc4c3e0000803e9f98a0424800000000000000000000000000000000000000"},{index=12,hex="898a1a0268eb67fb0000803fcdcc4c3ecdcc4c3e9f98a042b200000000000000010000000200000000000000"}},targets={{name="anti_personnel",index=9,offset=36,original="00000000",value="01000000"},{name="incendiary",index=11,offset=36,original="00000000",value="01000000"},{name="AT_MELTA_EXPLOSION",index=12,offset=24,original="b2000000",value="70010000"}},wait_frames=120,verify_frames=600,fingerprint="6AB3B43F:04744000:00ECDA6F:15522408"}
local create_api=(function()
-- Windows API for the mine table: plain reads, guarded 4-byte data writes, game.dll identity.
--
-- Compatibility: addons share one LuaJIT VM and LuaJIT keeps the first C prototype declared under a
-- name, so another addon's `bool ReadProcessMemory(...)` or `VirtualQuery(..., OTHER_MBI *, ...)`
-- would change our calls. Every entry point is looked up with GetProcAddress and cast to the
-- signature below; only the three bootstrap names touch shared declarations, and those are cast too.
--
-- Performance: reads are ReadProcessMemory into one static buffer (no VirtualQuery). VirtualQuery
-- and VirtualProtect run only inside writes. bcrypt is loaded only if the full file hash is needed.
return function()
    local ffi=require('ffi')
    assert(ffi.os=='Windows' and ffi.abi('64bit'),'WINDOWS_X64_REQUIRED')
    local signatures={
        kernel32={
            CloseHandle='int (*)(void *)',
            CreateFileW='void *(*)(const uint16_t *,uint32_t,uint32_t,void *,uint32_t,uint32_t,void *)',
            GetCurrentProcess='void *(*)(void)',
            GetFileSizeEx='int (*)(void *,int64_t *)',
            GetModuleFileNameW='uint32_t (*)(void *,uint16_t *,uint32_t)',
            QueryPerformanceCounter='int (*)(int64_t *)',
            QueryPerformanceFrequency='int (*)(int64_t *)',
            ReadFile='int (*)(void *,void *,uint32_t,uint32_t *,void *)',
            ReadProcessMemory='int (*)(void *,const void *,void *,size_t,size_t *)',
            VirtualProtect='int (*)(void *,size_t,uint32_t,uint32_t *)',
            VirtualQuery='size_t (*)(const void *,void *,size_t)',
            WriteProcessMemory='int (*)(void *,void *,const void *,size_t,size_t *)',
        },
        bcrypt={
            BCryptCloseAlgorithmProvider='int32_t (*)(void *,uint32_t)',
            BCryptCreateHash='int32_t (*)(void *,void **,void *,uint32_t,const void *,uint32_t,uint32_t)',
            BCryptDestroyHash='int32_t (*)(void *)',
            BCryptFinishHash='int32_t (*)(void *,void *,uint32_t,uint32_t)',
            BCryptHashData='int32_t (*)(void *,const void *,uint32_t,uint32_t)',
            BCryptOpenAlgorithmProvider='int32_t (*)(void **,const uint16_t *,const uint16_t *,uint32_t)',
        },
    }
    for _,declaration in ipairs({'void *GetModuleHandleA(const char *);',
        'void *GetProcAddress(void *,const char *);','void *LoadLibraryA(const char *);'}) do
        pcall(ffi.cdef,declaration)
    end
    local loader=ffi.load('kernel32')
    local module_handle=ffi.cast('void *(*)(const char *)',loader.GetModuleHandleA)
    local procedure=ffi.cast('void *(*)(void *,const char *)',loader.GetProcAddress)
    local load_library=ffi.cast('void *(*)(const char *)',loader.LoadLibraryA)
    local function bind(dll)
        local module=module_handle(dll..'.dll')
        if module==nil then module=load_library(dll..'.dll') end
        assert(module~=nil,'NATIVE_MODULE_MISSING_'..dll)
        local out={}
        for name,signature in pairs(signatures[dll]) do
            local address=procedure(module,name)
            assert(address~=nil,'NATIVE_MISSING_'..dll..'.'..name)
            out[name]=ffi.cast(signature,address)
        end
        return out
    end
    local k=bind('kernel32')
    local process=k.GetCurrentProcess()
    local READ_LIMIT=4096
    local buffer,count=ffi.new('uint8_t[?]',READ_LIMIT),ffi.new('size_t[1]')
    local word=ffi.new('uint64_t[1]')
    local counter,frequency=ffi.new('int64_t[1]'),ffi.new('int64_t[1]')
    k.QueryPerformanceFrequency(frequency)
    local ticks_per_ms=tonumber(frequency[0])/1000
    local api={reads=0}

    function api.clock_ms()
        k.QueryPerformanceCounter(counter)
        return tonumber(counter[0])/ticks_per_ms
    end
    function api.module(name)
        local h=module_handle(name)
        if h==nil then return nil end
        return tonumber(ffi.cast('uintptr_t',h))
    end
    function api.address(p) return p end
    function api.read(address,size)
        if type(address)~='number' or address<0x10000 or address>=0x800000000000
            or size<1 or size>READ_LIMIT or size%1~=0 then return nil end
        api.reads=api.reads+1
        if k.ReadProcessMemory(process,ffi.cast('const void *',address),buffer,size,count)==0
            or tonumber(count[0])~=size then return nil end
        return ffi.string(buffer,size)
    end
    function api.pointer(bytes,offset)
        offset=offset or 0
        if not bytes or offset<0 or offset+8>#bytes then return nil end
        ffi.copy(word,ffi.cast('const uint8_t *',bytes)+offset,8)
        local value=word[0]
        if value<0x10000 or value>=0x800000000000 then return nil end
        return tonumber(value)
    end

    -- MEMORY_BASIC_INFORMATION (x64), 48 bytes, kept as raw bytes: no shared struct name.
    local info=ffi.new('uint8_t[48]')
    local READONLY,READWRITE,PRIVATE=2,4,0x20000
    function api.page(address,size)
        if k.VirtualQuery(ffi.cast('const void *',address),info,48)~=48 then return nil end
        local base=tonumber(ffi.cast('uintptr_t *',info)[0])
        local length=tonumber(ffi.cast('size_t *',info+24)[0])
        local state=ffi.cast('uint32_t *',info+32)[0]
        if state~=0x1000 or address<base or address+size>base+length then return nil end
        return tonumber(ffi.cast('uint32_t *',info+36)[0]),tonumber(ffi.cast('uint32_t *',info+40)[0])
    end
    -- Accepts committed private pages that are plain PAGE_READWRITE or PAGE_READONLY. A read-only
    -- page is opened for the 4 bytes only and its protection is restored and re-checked at once.
    local old,ignored,written=ffi.new('uint32_t[1]'),ffi.new('uint32_t[1]'),ffi.new('size_t[1]')
    function api.write(address,bytes)
        if type(bytes)~='string' or #bytes~=4 then return false,'invalid_write_size' end
        local prot,kind=api.page(address,#bytes)
        if not prot then return false,'region_unavailable' end
        if kind~=PRIVATE or (prot~=READWRITE and prot~=READONLY) then
            return false,string.format('refused_page prot=%X type=%X',prot,kind)
        end
        local target=ffi.cast('void *',address)
        local opened=false
        if prot==READONLY then
            if k.VirtualProtect(target,#bytes,READWRITE,old)==0 then return false,'make_writable_failed' end
            opened=true
            if tonumber(old[0])~=prot then
                k.VirtualProtect(target,#bytes,old[0],ignored)
                return false,'page_protection_changed_before_write'
            end
        end
        written[0]=0
        local ok=k.WriteProcessMemory(process,target,bytes,#bytes,written)~=0 and tonumber(written[0])==#bytes
        local restored=true
        if opened then
            restored=k.VirtualProtect(target,#bytes,old[0],ignored)~=0 and api.page(address,#bytes)==prot
        end
        local after=api.read(address,#bytes)
        return ok and restored and after==bytes,
            string.format('page=%X written=%s protection_restored=%s readback=%s',prot,tostring(ok),tostring(restored),tostring(after==bytes))
    end

    local function open_module_file(address)
        local path=ffi.new('uint16_t[32768]')
        local length=k.GetModuleFileNameW(ffi.cast('void *',address),path,32768)
        assert(length>0 and length<32768,'module_path_unavailable')
        local file=k.CreateFileW(path,0x80000000,7,nil,3,0x08000000,nil)
        assert(file~=ffi.cast('void *',-1),'module_file_unavailable')
        return file
    end
    -- Build identity from the module file's PE header and size: TimeDateStamp, SizeOfImage,
    -- CheckSum, file bytes. Reads 4 KiB instead of hashing the whole file.
    function api.file_fingerprint(address)
        local file=open_module_file(address)
        local ok,result=pcall(function()
            local header,got,size=ffi.new('uint8_t[4096]'),ffi.new('uint32_t[1]'),ffi.new('int64_t[1]')
            assert(k.ReadFile(file,header,4096,got,nil)~=0 and got[0]==4096,'module_header_read_failed')
            assert(k.GetFileSizeEx(file,size)~=0,'module_size_failed')
            local function u32(at) return tonumber(ffi.cast('uint32_t *',header+at)[0]) end
            local pe=u32(0x3C)
            assert(header[0]==0x4D and header[1]==0x5A and pe>0 and pe+24+68<=4096 and u32(pe)==0x4550,'module_not_pe')
            return string.format('%08X:%08X:%08X:%d',u32(pe+8),u32(pe+24+56),u32(pe+24+64),tonumber(size[0]))
        end)
        k.CloseHandle(file)
        if not ok then error(result,0) end
        return result
    end
    -- SHA-256 of the module file (upper-case hex). Other Suzuka/Tongz addons cache {address, sha256}
    -- under these globals; a cache entry for the same module address is reused.
    local CACHES={'SuzukaVerifiedGameDllHash','TongzVerifiedGameDllHash'}
    function api.module_hash(address)
        for _,key in ipairs(CACHES) do
            local cached=rawget(_G,key)
            if type(cached)=='table' and cached.address==address and type(cached.sha256)=='string'
                and #cached.sha256==64 and not cached.sha256:find('[^0-9a-fA-F]') then
                return cached.sha256:upper(),'CACHE'
            end
        end
        local b=bind('bcrypt')
        local file=open_module_file(address)
        local algorithm,hash=ffi.new('void *[1]'),ffi.new('void *[1]')
        local ok,result=pcall(function()
            assert(b.BCryptOpenAlgorithmProvider(algorithm,ffi.new('uint16_t[7]',{83,72,65,50,53,54,0}),nil,0)==0,'sha256_unavailable')
            assert(b.BCryptCreateHash(algorithm[0],hash,nil,0,nil,0,0)==0,'sha256_create_failed')
            local chunk,got=ffi.new('uint8_t[262144]'),ffi.new('uint32_t[1]')
            while true do
                assert(k.ReadFile(file,chunk,262144,got,nil)~=0,'module_read_failed')
                if got[0]==0 then break end
                assert(b.BCryptHashData(hash[0],chunk,got[0],0)==0,'sha256_update_failed')
            end
            local digest,hex=ffi.new('uint8_t[32]'),{}
            assert(b.BCryptFinishHash(hash[0],digest,32,0)==0,'sha256_finish_failed')
            for i=0,31 do hex[#hex+1]=string.format('%02X',digest[i]) end
            return table.concat(hex)
        end)
        if hash[0]~=nil then b.BCryptDestroyHash(hash[0]) end
        if algorithm[0]~=nil then b.BCryptCloseAlgorithmProvider(algorithm[0],0) end
        k.CloseHandle(file)
        if not ok then error(result,0) end
        rawset(_G,'SuzukaVerifiedGameDllHash',{address=address,sha256=result:lower()})
        return result,'SHA256'
    end
    return api
end

end)()
local KEY='TongzMinesCombined'
if rawget(_G,KEY) then return end
local state={status='INITIALIZING',writes=0,restores=0,reapplies=0,checks=0,events={}}
rawset(_G,KEY,state)
local loader=rawget(_G,'CowboyBingusModLoader')
local api,game
local applied=nil -- {table=address} while our values are in place
local stopped=false

local function unhex(s) return (s:gsub('..',function(x) return string.char(tonumber(x,16)) end)) end
local MAP=unhex(SPEC.map)
local ORIGINAL,MODIFIED,TARGET_VALUE,TARGET_ORIGINAL={},{},{},{}
for _,row in ipairs(SPEC.rows) do ORIGINAL[row.index]=unhex(row.hex) end
local last_row=0
for _,t in ipairs(SPEC.targets) do
    local o=ORIGINAL[t.index]
    assert(o:sub(t.offset+1,t.offset+4)==unhex(t.original),'spec_original_mismatch')
    MODIFIED[t.index]=o:sub(1,t.offset)..unhex(t.value)..o:sub(t.offset+5)
    TARGET_VALUE[t],TARGET_ORIGINAL[t]=unhex(t.value),unhex(t.original)
end
for _,row in ipairs(SPEC.rows) do last_row=math.max(last_row,row.index) end
-- Index map and every row up to the last checked one, fetched with one read.
local BLOCK=#MAP+(last_row+1)*SPEC.stride
-- Old single-purpose scripts this package replaces; they share the same rows.
local LEGACY={'TongzMinesMediumTrigger','SuzukaMineDeployerSwap'}

local function event(text)
    state.events[#state.events+1]=text
    if #state.events>16 then table.remove(state.events,1) end
end

local function report()
    local f=loader and loader.open_log and loader.open_log('TongzMinesCombined.log')
    if not f then return end
    pcall(function()
        f:write('Suzuka’s Mine Boost ',VERSION,'\n')
        f:write('STATUS=',state.status,'\n')
        if state.error then f:write('ERROR=',state.error,'\n') end
        if state.identity then f:write('IDENTITY=',state.identity,' LOAD_MS=',string.format('%.2f',state.load_ms or -1),'\n') end
        f:write('WRITES=',state.writes,' RESTORES=',state.restores,' REAPPLIES=',state.reapplies,' CHECKS=',state.checks,
            ' READS=',api and api.reads or 0,'\n')
        for _,e in ipairs(state.events) do f:write('EVENT=',e,'\n') end
    end)
    f:close()
end

-- Returns table address and per-target state ('original'|'applied'), or nil and a reason.
local function locate()
    local owner=api.pointer(api.read(game+SPEC.owner_rva,8))
    local tab=owner and api.pointer(api.read(owner+SPEC.slot,8))
    if not tab then return nil,'WAITING_FOR_MINE_TABLE' end
    local block=api.read(tab,BLOCK)
    if not block or block:sub(1,#MAP)~=MAP then return nil,'TABLE_IDENTITY_MISMATCH_NO_WRITE' end
    local states={}
    for _,row in ipairs(SPEC.rows) do
        local at=#MAP+row.index*SPEC.stride
        local live=block:sub(at+1,at+SPEC.stride)
        if live==ORIGINAL[row.index] then states[row.index]='original'
        elseif MODIFIED[row.index] and live==MODIFIED[row.index] then states[row.index]='applied'
        else return nil,'MINE_ROW_MISMATCH_NO_WRITE index='..row.index end
    end
    return tab,states
end

local function field(tab,t) return tab+#MAP+t.index*SPEC.stride+t.offset end

local function apply()
    local tab,states=locate()
    if not tab then return states end
    local done={}
    for _,t in ipairs(SPEC.targets) do
        if states[t.index]=='original' then
            local ok,detail=api.write(field(tab,t),TARGET_VALUE[t])
            if not ok then
                -- A failed protection restore/readback may follow a completed write.
                done[#done+1]=t
                for _,d in ipairs(done) do
                    local current,rows=locate()
                    if current and api.address(current)==api.address(tab) and rows[d.index]=='applied' then
                        api.write(field(tab,d),TARGET_ORIGINAL[d])
                    end
                end
                local current,after=locate()
                local clean=current and api.address(current)==api.address(tab) and type(after)=='table'
                for _,d in ipairs(done) do clean=clean and after[d.index]=='original' end
                event('WRITE_FAILED '..t.name..' '..detail)
                stopped=true
                return clean and 'FAILED_ROLLED_BACK' or 'ROLLBACK_NOT_CONFIRMED'
            end
            done[#done+1]=t;state.writes=state.writes+1
            event('APPLIED '..t.name..' '..detail)
        end
    end
    if applied and applied.table~=api.address(tab) and #done>0 then
        state.reapplies=state.reapplies+1;event('REAPPLIED_AFTER_TABLE_CHANGE')
    elseif applied and #done>0 then
        state.reapplies=state.reapplies+1;event('REAPPLIED_AFTER_ROW_RESET')
    end
    applied={table=api.address(tab)}
    return 'APPLIED_COMBINED_MINES'
end

local function restore()
    if not applied then return state.status end
    local tab,states=locate()
    if not tab or api.address(tab)~=applied.table then return 'RESTORE_SKIPPED_TABLE_CHANGED' end
    local complete=true
    for _,t in ipairs(SPEC.targets) do
        if states[t.index]=='applied' then
            local ok,detail=api.write(field(tab,t),TARGET_ORIGINAL[t])
            if ok then state.restores=state.restores+1 else complete=false;event('RESTORE_FAILED '..t.name..' '..detail) end
        end
    end
    applied=nil
    return complete and 'RESTORED_ON_SHUTDOWN' or 'RESTORE_NOT_CONFIRMED'
end

local legacy_seen={}
local function check()
    if stopped then return end
    state.checks=state.checks+1
    for _,name in ipairs(LEGACY) do
        if not legacy_seen[name] and rawget(_G,name)~=nil then
            legacy_seen[name]=true;event('LEGACY_SCRIPT_ACTIVE '..name..' (disable it; rows are shared)')
        end
    end
    local previous=state.status
    local ok,result=pcall(apply)
    if not ok then state.error=tostring(result);result='ERROR' end
    if result=='TABLE_IDENTITY_MISMATCH_NO_WRITE' or result:find('^MINE_ROW_MISMATCH') then
        -- Another mod or a game change altered the table; never write over it.
        if applied then event('CONFLICT_AFTER_APPLY '..result);applied=nil end
    end
    state.status=result
    if result~=previous then report() end
end

-- Known build: PE header + file size match the verified game.dll, no 15 MB hash needed.
-- Anything else falls back to SHA-256 (shared cache first). Writes still require the exact
-- index map and the three exact rows.
local function verify_game()
    local fingerprint_ok,fingerprint=pcall(api.file_fingerprint,game)
    if fingerprint_ok and fingerprint==SPEC.fingerprint then return 'FINGERPRINT' end
    local digest,source=api.module_hash(game)
    if digest:upper()~=SPEC.game_sha256 then error('UNSUPPORTED_GAME_DLL_NO_WRITE',0) end
    return source
end

local ok,problem=pcall(function()
    assert(type(loader)=='table' and loader.api==1,'BSL_API_1_REQUIRED')
    api=create_api()
    local started=api.clock_ms and api.clock_ms()
    game=assert(api.module('game.dll'),'GAME_MODULE_UNAVAILABLE')
    state.identity=verify_game()
    state.load_ms=started and api.clock_ms()-started
end)
if not ok then
    stopped=true;state.status='DISABLED_NO_WRITE';state.error=tostring(problem)
else
    check()
end

-- Checks are scheduled from the previous check, starting off the 60/120/600-frame
-- boundaries other addons poll on, so their reads do not land on the same frame.
local PHASE=37
local previous_update=rawget(_G,'update')
if ok and not stopped then
    local frames,next_check=0,SPEC.wait_frames+PHASE
    _G.update=function(...)
        frames=frames+1
        if frames>=next_check and not stopped then
            pcall(check)
            next_check=frames+(applied and SPEC.verify_frames or SPEC.wait_frames)
        end
        if previous_update then return previous_update(...) end
    end
end
local previous_shutdown=rawget(_G,'shutdown')
_G.shutdown=function(...)
    if ok and applied then
        local done,result=pcall(restore)
        state.status=done and result or 'RESTORE_ERROR';if not done then state.error=tostring(result) end
    end
    pcall(report)
    if previous_shutdown then return previous_shutdown(...) end
end
report()
