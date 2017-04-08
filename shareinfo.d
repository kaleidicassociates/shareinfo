import std.stdio : writeln, writefln, printf;
import std.conv;
import core.stdc.string : strlen;
import core.stdc.wchar_ : wcslen;
import core.stdc.stdlib : malloc, free;
import core.stdc.string : memset;

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
alias PDWORD_PTR = size_t*; // seems to like this should be uint* ?
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
    ERROR_NETWORK_ACCESS_DENIED = 65,
    ERROR_INVALID_PARAMETER = 87,
    ERROR_MORE_DATA = 234,
    ERROR_NO_MORE_ITEMS = 259,
    ERROR_EXTENDED_ERROR = 1208,
    ERROR_NO_NETWORK = 1222,
    ERROR_NO_BROWSER_SERVERS_FOUND = 6118,
}
mixin(AnonymousEnum!system_error_code);

enum resource_display_type : uint
{
    RESOURCEDISPLAYTYPE_GENERIC = 0,
    RESOURCEDISPLAYTYPE_DOMAIN = 1,
    RESOURCEDISPLAYTYPE_SERVER = 2,
    RESOURCEDISPLAYTYPE_SHARE = 3,
    RESOURCEDISPLAYTYPE_FILE = 4,
    RESOURCEDISPLAYTYPE_GROUP = 5,
    RESOURCEDISPLAYTYPE_NETWORK = 6,
    RESOURCEDISPLAYTYPE_ROOT = 7,
    RESOURCEDISPLAYTYPE_SHAREADMIN = 8,
    // extended ?
    RESOURCEDISPLAYTYPE_TREE = 9,
    RESOURCEDISPLAYTYPE_NDSCONTAINER = 10,
}
mixin(AnonymousEnum!resource_display_type);

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

alias net_api_bufer_free = extern (Windows) system_error_code function (
    LPVOID Buffer
);

alias net_file_enum = extern (Windows) system_error_code function (
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

alias net_session_enum = extern (Windows) system_error_code function (
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

alias net_share_check = extern(Windows) system_error_code function (
    LPWSTR  servername,
    LPWSTR  device,
    LPDWORD type
);

alias net_share_enum = extern(Windows) system_error_code function (
    LPWSTR  servername,
    DWORD   level,
    LPBYTE  *bufptr,
    DWORD   prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
);


alias net_use_enum = extern (Windows) system_error_code function (
    LMSTR   UncServerName,
    DWORD   Level,
    LPBYTE  *BufPtr,
    DWORD   PreferedMaximumSize,
    LPDWORD EntriesRead,
    LPDWORD TotalEntries,
    LPDWORD ResumeHandle
);

alias net_server_enum = extern(Windows) system_error_code function (
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

struct CString
{
    char* ptr;
    alias ptr this;

    const(char[]) toString() pure const
    {
        if (!ptr) return "";
        return cast(const)ptr[0 .. strlen(ptr)];
    }
}

// ---------------------wnet functions---------------------------------
extern (Windows) struct NETRESOURCEA {
    resource_scope  dwScope;
    resource_type  dwType;
    resource_display_type  dwDisplayType;
    resource_usage dwUsage;
    alias LPTSTR = char*;
    LPTSTR lpLocalName;
    LPTSTR lpRemoteName;
    LPTSTR lpComment;
    LPTSTR lpProvider;
}

template wnet_get_last_error(bool isAscii)
{
static if (isAscii)
    alias LPTSTR = CString;
else 
    static assert(0, "wget_get_last_error_w is not supported for now");

alias wnet_get_last_error = extern(Windows) system_error_code function (
    LPDWORD lpError,
    LPTSTR  lpErrorBuf,
    DWORD   nErrorBufSize,
    LPTSTR  lpNameBuf,
    DWORD   nNameBufSize
);
}
alias wnet_get_last_error_a = wnet_get_last_error!true;

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

enum resource_scope : uint
{
    RESOURCE_CONNECTED = 1,
    RESOURCE_GLOBALNET = 2,
    RESOURCE_REMEMBERED = 3,
    RESOURCE_ENUM_ALL = ushort.max, // not sure about this one 
}
mixin(AnonymousEnum!resource_scope);

enum resource_type : uint
{
    RESOURCETYPE_ANY = 0,
    RESOURCETYPE_DISK = 1,
    RESOURCETYPE_PRINT = 2,
    RESOURCETYPE_UNKNOWN = 0xffffffff,
}
mixin(AnonymousEnum!resource_type);

enum resource_usage : uint
{
    RESOURCEUSAGE_ALL = 0,
    RESOURCEUSAGE_CONNECTABLE  = 1,
    RESOURCEUSAGE_CONTAINER = 2,
    RESOURCEUSAGE_RESERVED = 0x80000000,
}
mixin(AnonymousEnum!resource_usage);

void insufficientPermissions()
{
    writeln("You should run this program with a more privileged user-level ... yours is insufficient");
}

immutable {
net_file_enum NetFileEnum;
net_session_enum NetSessionEnum;
net_api_bufer_free NetApiBufferFree;
net_share_check NetShareCheck;
net_share_enum NetShareEnum;
net_server_enum NetServerEnum;
net_use_enum NetUseEnum;

wnet_get_last_error_a WNetGetLastErrorA;
wnet_open_enum_a WNetOpenEnumA;
wnet_enum_resource_a WNetEnumResourceA;
wnet_close_enum WNetCloseEnum;
}

shared static this()
{
    auto netapi32_handle = LoadLibraryA("Netapi32.dll");
    auto mpr_handle = LoadLibraryA("Mpr.dll");

    NetFileEnum = cast(net_file_enum) GetProcAddress(netapi32_handle, "NetFileEnum");
    NetSessionEnum = cast(net_session_enum) GetProcAddress(netapi32_handle, "NetSessionEnum");
    NetApiBufferFree = cast(net_api_bufer_free) GetProcAddress(netapi32_handle, "NetApiBufferFree");
    NetShareCheck = cast(net_share_check) GetProcAddress(netapi32_handle, "NetShareCheck");
    NetShareEnum = cast(net_share_enum) GetProcAddress(netapi32_handle, "NetShareEnum");
    NetServerEnum = cast(net_server_enum) GetProcAddress(netapi32_handle, "NetServerEnum");
    NetUseEnum = cast(net_use_enum) GetProcAddress(netapi32_handle, "NetUseEnum");

    WNetGetLastErrorA = cast (wnet_get_last_error_a) GetProcAddress(mpr_handle, "WNetGetLastErrorA");
    WNetOpenEnumA = cast(wnet_open_enum_a) GetProcAddress(mpr_handle, "WNetOpenEnumA");
    WNetEnumResourceA = cast(wnet_enum_resource_a) GetProcAddress(mpr_handle, "WNetEnumResourceA");
    WNetCloseEnum = cast (wnet_close_enum) GetProcAddress(mpr_handle, "WNetCloseEnum");
}

void main(string[] args)
{   
    //TODO move those functions with their typedefs into a seperate file and initialize the pointers in a shared module constructor

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
        auto resources = kick_off();
        foreach(i,resource;resources)
        {
            writeln("resource : " ,i, " ", resource);
        }
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

struct ResourceInfo {
    NETRESOURCEA resource;
    NETRESOURCEA _parent;
}

struct owned_netresource
{
    resource_scope  dwScope;
    resource_type  dwType;
    resource_display_type  dwDisplayType;
    resource_usage dwUsage;

    string localName;
    string remoteName;
    string comment;
    string provider;

    this(NETRESOURCEA that)
    {
        dwScope = that.dwScope;
        dwType = that.dwType;
        dwDisplayType = that.dwDisplayType;
        dwUsage = that.dwUsage;

        localName = that.lpLocalName ? that.lpLocalName[0 .. strlen(that.lpLocalName)].idup : "";
        remoteName = that.lpRemoteName ? that.lpRemoteName[0 .. strlen(that.lpRemoteName)].idup : "";
        comment = that.lpComment ? that.lpComment[0 .. strlen(that.lpComment)].idup : "";
        provider = that.lpProvider ? that.lpProvider[0 .. strlen(that.lpProvider)].idup : "";
    }

/*
    string toString() pure const
    {
       string result;

       result ~= "dwScope: " ~ to!string(dwScope) ~ "\n";
       result ~= "dwType: " ~ to!string(dwType) ~ "\n";
       result ~= "dwDisplayType: " ~ to!string(dwDisplayType) ~ "\n";
       result ~= "dwUsage: " ~ to!string(dwUsage) ~ "\n";

       result ~= "localName: " ~ localName ~ "\n";
       result ~= "remoteName: " ~ remoteName ~ "\n";
       result ~= "comment: " ~ comment ~ "\n";
       result ~= "provider: " ~ provider ~ "\n";

       return result;
    }
*/
}

/*
 below code is taken directly from https://msdn.microsoft.com/en-us/library/windows/desktop/aa385341(v=vs.85).aspx
 though heavily modified.
*/

owned_netresource[] kick_off()
{
    owned_netresource[] result = [];

    LPNETRESOURCEA lpnr = null;

    if (EnumerateFunc(lpnr, &result) == false) {
        printf("Call to EnumerateFunc failed\n");
    } 

    return result;
}

bool EnumerateFunc(NETRESOURCEA *lpnr,  owned_netresource[]* resources)
{
    DWORD dwResult, dwResultEnum;
    HANDLE hEnum;
    DWORD cbBuffer = 16384;     // 16K is a good size
    DWORD cEntries = -1;        // enumerate all possible entries
    LPNETRESOURCEA lpnrLocal;    // pointer to enumerated structures
    DWORD i;
    //
    // Call the WNetOpenEnum function to begin the enumeration.
    //
    dwResult = WNetOpenEnumA(RESOURCE_GLOBALNET, // all network resources
                            RESOURCETYPE_ANY,   // all resources
                            0,  // enumerate all resources
                            lpnr,       // null first time the function is called
                            &hEnum);    // handle to the resource
    if (dwResult == ERROR_EXTENDED_ERROR) {
        printExtendedError();
        return false;
    }
    else if (dwResult != ERROR_SUCCESS) {
        printf("WnetOpenEnum failed with error %d\n", dwResult);
        return false;
    }
    //
    // Call the GlobalAlloc function to allocate resources.
    //
    lpnrLocal = cast(LPNETRESOURCEA) malloc(cbBuffer);
    if (lpnrLocal == null) {
        printf("malloc failedn", dwResult);
//      NetErrorHandler(hwnd, dwResult, (LPSTR)"WNetOpenEnum");
        return false;
    }

    do {
        //
        // Initialize the buffer.owned_resouce
        //
        memset(lpnrLocal, 0, cbBuffer);
        //
        // Call the WNetEnumResource function to continue
        //  the enumeration.
        //
        dwResultEnum = WNetEnumResourceA(hEnum,  // resource handle
                                        &cEntries,      // defined locally as -1
                                        lpnrLocal,      // LPNETRESOURCE
                                        &cbBuffer);     // buffer size
        //
        // If the call succeeds, loop through the structures.
        //
        if (dwResultEnum == ERROR_SUCCESS) {
            for (i = 0; i < cEntries; i++) {
                // Call an application-defined function to
                //  display the contents of the NETRESOURCE structures.
                //
                *resources ~= owned_netresource(lpnrLocal[i]);

                // If the NETRESOURCE structure represents a container resource, 
                //  call the EnumerateFunc function recursively.

                if (RESOURCEUSAGE_CONTAINER == (lpnrLocal[i].dwUsage
                                                & RESOURCEUSAGE_CONTAINER))
                    if (!EnumerateFunc(&lpnrLocal[i], resources))
                        printf("EnumerateFunc returned false\n");
            }
        }
        // Process errors.
        //
        else if (dwResultEnum == ERROR_NO_MORE_ITEMS) 
        {
           // do nothing this is alright
        }
        else if (dwResultEnum == ERROR_EXTENDED_ERROR)
        {
            printExtendedError();
            break;
        }
        else
        {
                   printf("WNetEnumResource failed with error %d\n", dwResultEnum);
//      NetErrorHandler(hwnd, dwResultEnum, (LPSTR)"WNetEnumResource");
            break;
        }

    }
    //
    // End do.
    //
    while (dwResultEnum != ERROR_NO_MORE_ITEMS);
    //
    // Call the GlobalFree function to free the memory.
    //
    free(lpnrLocal);
    //
    // Call WNetCloseEnum to end the enumeration.
    //
    dwResult = WNetCloseEnum(hEnum);

    if (dwResult != ERROR_SUCCESS) {
        //
        // Process errors.
        //
        printf("WNetCloseEnum failed with error %d\n", dwResult);
//    NetErrorHandler(hwnd, dwResult, (LPSTR)"WNetCloseEnum");
        return false;
    }

    return true;
}

//HRESULT FindComputers(IDirectorySearch *pContainerToSearch);  //  IDirectorySearch pointer to the container to search.

void printExtendedError()
{
    char[256] errorMessageBuffer;
    char[256] providerNameBuffer;
    uint extended_error_code;
    writeln("Extended Error");

    WNetGetLastErrorA(&extended_error_code, // error code
        CString(&errorMessageBuffer[0]),  // buffer for error description 
        errorMessageBuffer.sizeof,  // size of error buffer
        CString(&providerNameBuffer[0]),     // buffer for provider name 
        providerNameBuffer.sizeof
    );
    writeln(CString(&errorMessageBuffer[0]));    
}
