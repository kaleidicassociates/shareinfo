import std.stdio : writeln;
import core.stdc.string : strlen;
import core.stdc.wchar_ : wcslen;
//import core.sys.windows.lmshare;
version = Unicode;
alias DWORD = uint;
alias LPDWORD = uint*;
alias LPBYTE = ubyte*;
alias PDWORD_PTR = size_t*;
alias NET_API_STATUS = uint;
alias LPWSTR = wchar*;
alias LPVOID = void*;

enum MAX_PREFERRED_LENGTH = -1;
enum ERROR_ACCESS_DENIED = 5;

version (Unicode)
{
    alias LMSTR = wchar*;
    alias LMCSTR = const(wchar)*;
}
else
{
    alias LMSTR = char*;
    alias LMCSTR = const(char)*;
}

extern (Windows) struct FILE_INFO_3 {
    DWORD fi3_id;
    DWORD fi3_permissions;
    DWORD fi3_num_locks;
    LMSTR fi3_pathname;
    LMSTR fi3_username;
}

extern (Windows) struct SESSION_INFO_2 {
    LPWSTR sesi2_cname;
    LPWSTR sesi2_username;
    DWORD  sesi2_num_opens;
    DWORD  sesi2_time;
    DWORD  sesi2_idle_time;
    DWORD  sesi2_user_flags;
    LPWSTR sesi2_cltype_name;
}

extern (Windows) struct SESSION_INFO_10 {
    LPWSTR sesi10_cname;
    LPWSTR sesi10_username;
    DWORD  sesi10_time;
    DWORD  sesi10_idle_time;
}

alias net_api_bufer_free = extern (Windows) NET_API_STATUS function (
    LPVOID Buffer
    );

alias net_file_enum = extern (Windows) NET_API_STATUS function (
    LMSTR      servername, /// null for localhost
    LMSTR      basepath,
    LMSTR      username,
    DWORD      level,
    LPBYTE     *bufptr,
    DWORD      prefmaxlen,
    LPDWORD    entriesread,
    LPDWORD    totalentries,
    PDWORD_PTR resume_handle
    );

alias net_session_enum = extern (Windows) NET_API_STATUS function (
    LPWSTR  servername,
    LPWSTR  UncClientName,
    LPWSTR  username,
    DWORD   level,
    LPBYTE  *bufptr,
    DWORD   prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
    );



extern (Windows) void* LoadLibraryA(const char* libname);
extern (Windows) void* GetProcAddress(void* moduleHandle, const char* procname);


void main()
{   
    auto libHandle = LoadLibraryA("Netapi32.dll");
    auto NetFileEnum = cast(net_file_enum)GetProcAddress(libHandle, "NetFileEnum");
    auto NetSessionEnum = cast(net_session_enum)GetProcAddress(libHandle, "NetSessionEnum");
    auto NetApiBufferFree = cast(net_api_bufer_free)GetProcAddress(libHandle, "NetApiBufferFree");
    
    //FILE_INFO_3* bufptr;
    SESSION_INFO_10* bufptr;
    uint entiresread;
    uint totalentries;
    
    //auto result = NetFileEnum(null, null, null, 3, cast(ubyte**)&bufptr, MAX_PREFERRED_LENGTH, &entiresread, &totalentries, null);
    auto result = NetSessionEnum(null, null, null, 10, cast(ubyte**)&bufptr, MAX_PREFERRED_LENGTH, &entiresread, &totalentries, null);

    scope(exit) NetApiBufferFree(bufptr);

    if (result == ERROR_ACCESS_DENIED)
    {
        writeln("You should run this program with a more priviliged user-level ... yours is insufficient");
    } else foreach(e; bufptr[0 .. totalentries])
    {
        auto username_string = cast(const)e.sesi10_username[0 .. wcslen(e.sesi10_username)];
        auto computername_string = cast(const)e.sesi10_cname[0 .. wcslen(e.sesi10_cname)];  
        writeln("Computer: ", computername_string, " User: ", username_string);
    }
    
}
