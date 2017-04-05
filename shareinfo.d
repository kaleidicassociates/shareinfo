import std.stdio : writeln, writefln;
import std.conv;
import core.stdc.string : strlen;
import core.stdc.wchar_ : wcslen;
//import core.sys.windows.lmshare;

enum AnonymousEnum(EnumType, string fqnEnumType = EnumType.stringof) = (){
  string AnonymousEnum = "enum {";
  foreach(m;__traits(allMembers, EnumType))
  {
      AnonymousEnum ~= m ~ " = " ~ fqnEnumType ~ "." ~ m ~ ",";
  }
  AnonymousEnum  ~= "}";
  return AnonymousEnum;
}();


version = Unicode;
alias DWORD = uint;
alias LPDWORD = uint*;
alias LPBYTE = ubyte*;
alias PDWORD_PTR = size_t*;
alias NET_API_STATUS = uint;
alias LPWSTR = wchar*;
alias LPVOID = void*;
alias HANDLE = void*; // not sure about this one
alias LPHANDLE = HANDLE*; 
alias LPNETRESOURCEA = NETRESOURCEA*;


struct SECURITY_DESCRIPTOR;
alias PSECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR*;
alias PPSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR*;

enum MAX_PREFERRED_LENGTH = -1;
/*
 * Usuaal windows function error_code return values
 * official list here: https://msdn.microsoft.com/en-us/library/cc231199.aspx
 * Extend this as needed
 */

enum system_error_code : uint
{
    ERROR_SUCCESS = 0,
    ERROR_ACCESS_DENIED = 5,
    ERROR_NOT_ENOUGH_MEMORY = 8,
    ERROR_BAD_NETPATH = 53,
    ERROR_MORE_DATA = 234,
    ERROR_NO_BROWSER_SERVERS_FOUND = 6118,
}
mixin(AnonymousEnum!system_error_code);

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

extern(Windows) struct SESSION_INFO_503 {
    LPWSTR                shi503_netname;
    DWORD                 shi503_type;
    LPWSTR                shi503_remark;
    DWORD                 shi503_permissions;
    DWORD                 shi503_max_uses;
    DWORD                 shi503_current_uses;
    LPWSTR                shi503_path;
    LPWSTR                shi503_passwd;
    LPWSTR                shi503_servername;
    DWORD                 shi503_reserved;
    PPSECURITY_DESCRIPTOR shi503_security_descriptor;
}

extern (Windows) struct SHARE_INFO_502 {
  LPWSTR               shi502_netname;
  DWORD                shi502_type;
  LPWSTR               shi502_remark;
  DWORD                shi502_permissions;
  DWORD                shi502_max_uses;
  DWORD                shi502_current_uses;
  LPWSTR               shi502_path;
  LPWSTR               shi502_passwd;
  DWORD                shi502_reserved;
  PSECURITY_DESCRIPTOR shi502_security_descriptor;
}

struct SERVER_INFO_101 {
    DWORD  sv101_platform_id;
    LPWSTR sv101_name;
    DWORD  sv101_version_major;
    DWORD  sv101_version_minor;
    DWORD  sv101_type;
    LPWSTR sv101_comment;
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

alias net_share_check = extern(Windows) NET_API_STATUS function (
    LPWSTR  servername,
    LPWSTR  device,
    LPDWORD type
);

alias net_share_enum = extern(Windows) NET_API_STATUS function (
    LPWSTR  servername,
    DWORD   level,
    LPBYTE  *bufptr,
    DWORD   prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
);


alias net_use_enum = extern (Windows) NET_API_STATUS function (
  LMSTR   UncServerName,
  DWORD   Level,
  LPBYTE  *BufPtr,
  DWORD   PreferedMaximumSize,
  LPDWORD EntriesRead,
  LPDWORD TotalEntries,
  LPDWORD ResumeHandle
);

alias net_server_enum = extern(Windows) NET_API_STATUS function (
    LPWSTR servername, // really LPCWSTR
    DWORD   level,
    LPBYTE  *bufptr,
    DWORD   prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    DWORD   servertype,
    LPWSTR domain,   // really LPCWSTR
    LPDWORD resume_handle
);

// ---------------------wnet functions---------------------------------
extern (Windows) struct NETRESOURCEA {
  DWORD  dwScope;
  DWORD  dwType;
  DWORD  dwDisplayType;
  DWORD  dwUsage;
  alias LPTSTR = char*;
  LPTSTR lpLocalName;
  LPTSTR lpRemoteName;
  LPTSTR lpComment;
  LPTSTR lpProvider;
}

alias wnet_open_enum_a = extern(Windows) system_error_code function (
  DWORD         dwScope,
  DWORD         dwType,
  DWORD         dwUsage,
  NETRESOURCEA  *lpNetResource,
  LPHANDLE      lphEnum // out
);

alias wnet_enum_resource_a = extern (Windows) system_error_code function (
  HANDLE  hEnum,
  LPDWORD lpcCount, //inout
  LPVOID  lpBuffer, //out
  LPDWORD lpBufferSize //inout
);

alias wnet_close_enum = extern (Windows) system_error_code function (
    HANDLE hEnum
);

extern (Windows) void* LoadLibraryA(const char* libname);
extern (Windows) void* GetProcAddress(void* moduleHandle, const char* procname);

enum Resource : uint
{
    RESOURCE_CONNECTED = 1,
    RESOURCE_GLOBALNET = 2,
    RESOURCE_REMEMBERED = 3,
}
mixin(AnonymousEnum!Resource);

enum ResourceType : uint
{
    RESOURCETYPE_ANY = 0,
    RESOURCETYPE_DISK = 1,
    RESOURCETYPE_PRINT = 2,
    RESOURCETYPE_UNKNOWN = 0xffffffff,
}
mixin(AnonymousEnum!ResourceType);

enum ResourceUsage : uint
{
    RESOURCEUSAGE_CONNECTABLE  = 1,
    RESOURCEUSAGE_CONTAINER = 2,
    RESOURCEUSAGE_RESERVED = 0x80000000,
}
mixin(AnonymousEnum!ResourceUsage);

void insufficientPermissions()
{
    writeln("You should run this program with a more privileged user-level ... yours is insufficient");
}

void main(string[] args)
{   
    auto netapi32_handle = LoadLibraryA("Netapi32.dll");
    auto mpr_handle = LoadLibraryA("Mpr.dll");
    //TODO move those functions with their typedefs into a seperate file and initialize the pointers in a shared module constructor

    auto NetFileEnum = cast(net_file_enum) GetProcAddress(netapi32_handle, "NetFileEnum");
    auto NetSessionEnum = cast(net_session_enum) GetProcAddress(netapi32_handle, "NetSessionEnum");
    auto NetApiBufferFree = cast(net_api_bufer_free) GetProcAddress(netapi32_handle, "NetApiBufferFree");
    auto NetShareCheck = cast(net_share_check) GetProcAddress(netapi32_handle, "NetShareCheck");
    auto NetShareEnum = cast(net_share_enum) GetProcAddress(netapi32_handle, "NetShareEnum");
    auto NetServerEnum = cast(net_server_enum) GetProcAddress(netapi32_handle, "NetServerEnum");
    auto NetUseEnum = cast(net_use_enum) GetProcAddress(netapi32_handle, "NetUseEnum");
    
    auto WNetOpenEnumA = cast(wnet_open_enum_a) GetProcAddress(mpr_handle, "WNetOpenEnumA");
    auto WNetEnumResourceA = cast(wnet_enum_resource_a) GetProcAddress(mpr_handle, "WNetEnumResourceA");
    auto WNetCloseEnum = cast (wnet_close_enum) GetProcAddress(mpr_handle, "WNetCloseEnum");

    //FILE_INFO_3* bufptr;
    SESSION_INFO_10* bufptr;
    uint entriesRead;
    uint totalentries;

    wstring serverName;

    if (args.length==1)
    {
        writeln("enumerating shares on local computer");
    }
    else
    {
        serverName=args[1].to!wstring~"\0"w;
        writefln("enumerating shares on server %s", serverName);
    }
    immutable(wchar)* servernamep = (serverName.length ==0) ? null : serverName.ptr;
    //auto result = NetFileEnum(null, null, null, 3, cast(ubyte**)&bufptr, MAX_PREFERRED_LENGTH, &entriesRead, &totalentries, null);
    auto result = NetSessionEnum(cast(wchar*)(servernamep), null, null, 10, cast(ubyte**)&bufptr, MAX_PREFERRED_LENGTH, &entriesRead, &totalentries, null);

    scope(exit) NetApiBufferFree(bufptr);

    if (result == ERROR_ACCESS_DENIED)
    {
        insufficientPermissions();
    } else foreach(e; bufptr[0 .. totalentries])
    {
        auto username_string = cast(const)e.sesi10_username[0 .. wcslen(e.sesi10_username)];
        auto computername_string = cast(const)e.sesi10_cname[0 .. wcslen(e.sesi10_cname)];  
        writeln("Computer: ", computername_string, " User: ", username_string);
    }

    auto device=(args.length>2) ? args[2].to!wstring~"\0" : "C"w;
    uint sharebitmap;
    result = NetShareCheck(cast(wchar*)servernamep,cast(wchar*)device,&sharebitmap);
    writefln("result of share check %s, bitmap = %s",result,sharebitmap);

    /* related docs :
     *
     * https://msdn.microsoft.com/en-us/library/windows/desktop/bb525387(v=vs.85).aspx
     * https://msdn.microsoft.com/en-us/library/windows/desktop/cc462916(v=vs.85).aspx
     */

    SESSION_INFO_503* ptr503;
	scope (exit) NetApiBufferFree (ptr503);
    result = NetShareEnum(cast(wchar*)servernamep,503,cast(ubyte**) &ptr503, MAX_PREFERRED_LENGTH, &entriesRead, &totalentries, null);
    writefln("result of net share enum %s; totalentries %s; entriesRead %s",result, totalentries, entriesRead);
    if (result == ERROR_ACCESS_DENIED)
    {
        insufficientPermissions();
    } else foreach(e; ptr503[0 .. entriesRead])
    {
        auto share_netname = cast(const)e.shi503_netname[0 .. wcslen(e.shi503_netname)];
        auto share_path = cast(const)e.shi503_path[0 .. wcslen(e.shi503_path)];  
        writeln("Netname: ", share_netname, " Path: ", share_path);
    }
	
	writeln("let's enumerate all resources on the net");
    HANDLE wnetEnumHandle;
	WNetOpenEnumA(RESOURCE_GLOBALNET, RESOURCETYPE_DISK, RESOURCEUSAGE_CONNECTABLE, null, &wnetEnumHandle);
	uint count = -1;
	uint bufferSize = 16 * 1024;
	import core.stdc.stdlib;
	NETRESOURCEA* resource = cast (NETRESOURCEA*)malloc(16 * 1024);
	scope (exit) free(resource);
	result = ERROR_ACCESS_DENIED;
	result = WNetEnumResourceA(wnetEnumHandle, &count,  cast(void*)resource, &bufferSize);
	if (result == ERROR_ACCESS_DENIED)
    {
        insufficientPermissions();
    } else foreach(e; resource[0 .. count])
    {

        auto res_localname = e.lpLocalName ? cast(const)e.lpLocalName[0 .. strlen(e.lpLocalName)] : "";
        auto res_remotename = e.lpRemoteName ? cast(const)e.lpRemoteName[0 .. strlen(e.lpRemoteName)] : "";
        writeln("localName: ", res_localname, " RemoteName: ", res_remotename);
    }
	WNetCloseEnum(wnetEnumHandle);
	
/*	
    SERVER_INFO_101 *ptrServer101;
    enum  SV_TYPE_NT =0x00001000;
    enum SV_TYPE_ALL = 0xFFFFFFFF;
    wstring domain = "OPTIONS-IT\0"w;
    wchar* domainp = cast(wchar*)domain.ptr;
    result = NetServerEnum(null,101U,cast(ubyte**) &ptrServer101, MAX_PREFERRED_LENGTH, &entriesRead, &totalentries, SV_TYPE_ALL, domainp,null);
    writefln("result of net server enum %s; totalentries %s; entriesRead %s",result, totalentries, entriesRead);
    if (result == ERROR_ACCESS_DENIED)
    {
        insufficientPermissions();
    } else foreach(e; ptrServer101[0 .. entriesRead])
    {
        auto serverResName = cast(const)e.sv101_name[0 .. wcslen(e.sv101_name)];
        auto serverComment = cast(const)e.sv101_comment[0 .. wcslen(e.sv101_comment)];  
        writeln("name: ", serverResName, "comment: ", serverComment);
    }
*/	
}

//HRESULT FindComputers(IDirectorySearch *pContainerToSearch);  //  IDirectorySearch pointer to the container to search.
