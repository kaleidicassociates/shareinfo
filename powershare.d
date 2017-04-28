import std.algorithm;
import std.stdio : writeln, writefln;
import std.conv;
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

struct SECURITY_DESCRIPTOR;
alias PSECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR*;
alias PPSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR*;

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

wstring fromZString(wchar* s)
{
    return s[0.. wcslen(s)].idup;
}

struct SessionInfo
{
    wstring computerName;
    wstring userName;
    uint time;
    uint idleTime;

    // auto username_string = (e.sesi10_username[0 .. wcslen(e.sesi10_username)]).idup;
    // auto computername_string = (e.sesi10_cname[0 .. wcslen(e.sesi10_cname)]).idup;

    this(SESSION_INFO_10 info)
    {
        this.computerName = info.sesi10_cname.fromZString;
        this.userName = info.sesi10_username.fromZString;
        this.time = info.sesi10_time;
        this.idleTime = info.sesi10_idle_time;
    }
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

wstring fromZ(LPWSTR s)
{
    if(s is null)
        return "";
    return (cast(const)s[0..wcslen(s)]).to!wstring;
}

enum ShareInfoSubType
{
    diskDrive = 0,
    printQueue = 1,
    comunicationDevice = 2,
    interProcessCommunication = 3,
}
bool isSpecialShareInfoType(long shareInfoType)
{
    return (shareInfoType && 0x80000000);
}
bool isTemporaryShareType(long shareInfoType)
{
    return (shareInfoType && 0x40000000);
}
struct ShareInfo
{
    wstring netname;
    ShareInfoSubType type;
    bool isSpecialShare;
    bool isTemporaryShare;
    wstring remark;
    long permissions;
    long maxUses;
    long currentUses;
    wstring path;
    wstring passwd;
    wstring serverName;

    this(SESSION_INFO_503 si)
    {
        this.netname = si.shi503_netname.fromZ;
        this.type = cast(ShareInfoSubType) (si.shi503_type & 0xffff);
        this.isSpecialShare = si.shi503_type.isSpecialShareInfoType;
        this.isTemporaryShare = si.shi503_type.isTemporaryShareType;
        this.remark = si.shi503_remark.fromZ;
        this.permissions = si.shi503_permissions;
        this.maxUses = si.shi503_max_uses;
        this.currentUses = si.shi503_current_uses;
        this.path = si.shi503_path.fromZ;
        this.passwd = si.shi503_passwd.fromZ;
        this.serverName = si.shi503_servername.fromZ;
        // put(ret, format("security descriptor: %s\n" ~ si.shi503_security_descriptor));
    }
}
string prettyPrint(ShareInfo shareInfo)
{
    import std.array:Appender,put;
    Appender!string ret;
    import std.string;
    put(ret, leftJustify("netname:",20));
    put(ret,shareInfo.netname~"\n");

    put(ret, leftJustify("type:",20));
    put(ret,shareInfo.type.to!string~"\n");

    put(ret, leftJustify("remark:",20));
    put(ret,shareInfo.remark~"\n");

    put(ret, leftJustify("permissions:",20));
    put(ret,shareInfo.permissions.to!string~"\n");

    put(ret, leftJustify("maxUses:",20));
    put(ret,shareInfo.maxUses.to!string~"\n");

    put(ret, leftJustify("currentUses:",20));
    put(ret,shareInfo.currentUses.to!string~"\n");

    put(ret, leftJustify("path:",20));
    put(ret,shareInfo.path~"\n");

    put(ret, leftJustify("passwd:",20));
    put(ret,shareInfo.passwd~"\n");

    put(ret, leftJustify("serverName:",20));
    put(ret,shareInfo.serverName~"\n");

    return ret.data;
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

extern (Windows) void* LoadLibraryA(const char* libname);
extern (Windows) void* GetProcAddress(void* moduleHandle, const char* procname);


void insufficientPermissions()
{
    writeln("You should run this program with a more privileged user-level ... yours is insufficient");
}

import std.stdio;
import std.file;
import std.process;
import std.string;
import std.algorithm;
import std.array:array;

enum script =
`
$DirSearcher = New-Object System.DirectoryServices.DirectorySearcher([adsi]'')
$DirSearcher.Filter = '(objectClass=Computer)'
$DirSearcher.FindAll().GetEnumerator() | ForEach-Object { $_.Properties.name }
`;

enum script2 = 
`
Get-Acl %s | select-object -property access | convertTo-json
`;



enum powerShellPath=`%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe`;

string[] enumerateComputers()
{
    std.file.write("script.ps1",script);
    auto pid=spawnShell(powerShellPath ~ " -executionpolicy bypass -File script.ps1 > computers.txt");
    wait(pid);
    auto computers=cast(string)(std.file.read("computers.txt"));
    auto computerList = computers.split.map!(line=>line.strip).array.filter!(line=>line.length>0).array;
    return computerList;
}

struct AccessRight
{
    string identityReference;
    long fileSystemRights;
    bool isInherited;
    long inheritanceFlags;
    long accessControlType;
    long propagationFlags;
}

enum AccessRightType
{
    // Grants the right to read data from the file. For a directory, this value grants the right to list the contents of the directory.
    FILE_LIST_DIRECTORY = 1,
    // Grants the right to write data to the file. For a directory, this value grants the right to create a file in the directory.
    FILE_ADD_FILE = 2,
    // Grants the right to append data to the file. For a directory, this value grants the right to create a subdirectory.
    FILE_ADD_SUBDIRECTORY = 4,
    // Grants the right to read extended attributes.
    FILE_READ_EA = 8,
    // Grants the right to write extended attributes.
    FILE_WRITE_EA = 16,
    // Grants the right to execute a file. For a directory, the directory can be traversed.
    FILE_TRAVERSE = 32,
    // Grants the right to delete a directory and all of the files it contains (its children), even if the files are read-only.
    FILE_DELETE_CHILD = 64,
    // Grants the right to read file attributes.
    FILE_READ_ATTRIBUTES = 128,
    //    Grants the right to change file attributes.
    FILE_WRITE_ATTRIBUTES = 256,
    // Grants delete access.
    DELETE = 65536,
    // Grants read access to the security descriptor and owner.
    READ_CONTROL = 131072,
    // Grants write access to the discretionary access control list (DACL).
    WRITE_DAC= 262144,
    // Assigns the write owner.
    WRITE_OWNER = 524288,
    SYNCHRONIZE = 1048576,
}

string[] rightsToString(long accessRights)
{
    import std.traits:EnumMembers;
    string[] ret;
    foreach(entry;EnumMembers!AccessRightType)
    {
        if (accessRights && entry)
        {
            ret~=entry.to!string;
        }
    }
    return ret;
}

auto enumerateAccess(string shareName)
{
    import std.json;
    auto scriptFilled = format(script2,shareName);
    std.file.write("script2.ps1",scriptFilled);
    auto pid=spawnShell(powerShellPath ~ " -executionpolicy bypass -File script2.ps1 > accessrights.txt");
    wait(pid);
    auto accessText=cast(string)(std.file.read("accessrights.txt"));
    AccessRight[] rets;
    try
    {
        auto json = parseJSON(accessText);
        foreach(entry;json["Access"].array)
        {
            foreach(cell;entry.object.keys)
            {
                writefln("%s:%s",cell,entry.object[cell].to!string);
            }
            AccessRight ret;
            ret.identityReference = entry.object["IdentityReference"].to!string;
            ret.fileSystemRights = entry.object["FileSystemRights"].integer;
            //ret.isInherited = entry.object["IsInherited"].boolean;
            ret.inheritanceFlags = entry.object["InheritanceFlags"].integer;
            ret.accessControlType = entry.object["AccessControlType"].integer;
            ret.propagationFlags = entry.object["PropagationFlags"].integer;
            rets~=ret;
        }
    }
    catch(JSONException e)
    {
        writefln("no valid response for %s",shareName);
    }
    return rets;
}


typeof(LoadLibraryA("Netapi32.dll")) libHandle;
net_file_enum NetFileEnum;
net_session_enum NetSessionEnum;
net_api_bufer_free NetApiBufferFree;
net_share_check NetShareCheck;
net_share_enum NetShareEnum;
net_server_enum NetServerEnum;
net_use_enum NetUseEnum;

void createLibraryHandles()
{
    libHandle = LoadLibraryA("Netapi32.dll");
    //TODO move those functions with their typedefs into a seperate file and initialize the pointers in a shared module constructor

    NetFileEnum = cast(net_file_enum) GetProcAddress(libHandle, "NetFileEnum");
    NetSessionEnum = cast(net_session_enum) GetProcAddress(libHandle, "NetSessionEnum");
    NetApiBufferFree = cast(net_api_bufer_free) GetProcAddress(libHandle, "NetApiBufferFree");
    NetShareCheck = cast(net_share_check) GetProcAddress(libHandle, "NetShareCheck");
    NetShareEnum = cast(net_share_enum) GetProcAddress(libHandle, "NetShareEnum");
    NetServerEnum = cast(net_server_enum) GetProcAddress(libHandle, "NetServerEnum");
    NetUseEnum = cast(net_use_enum) GetProcAddress(libHandle, "NetUseEnum");    
}

void main(string[] args)
{   
    createLibraryHandles();
    string[] servers;
    wstring serverName;
    ShareInfo[][string] shareInfos;

    int start=-1,end=-1;
    
    if (args.length==1 || args.length ==3 )
    {
        writeln("enumerating shares on all computers");
        servers=enumerateComputers().sort().array;
        if (args.length ==3)
        {
            start = args[1].to!int;
            end = args[2].to!int;
        }
    }
    else
    {
        serverName=args[1].to!wstring~"\0"w;
        writefln("enumerating shares on server %s", serverName);
        servers=[serverName.to!string];
    }
    if (end==-1)
        end = servers.length;
    end=min(servers.length,end);
    if (start==-1)
        start = 1;
    foreach(i,server;servers[start-1..end])
    {
        bool skip = false;
        if (!(server.startsWith("SYM")))
            skip=true;
        string skipping = (skip)? " - skipping":" ";
        writefln("server: %s/%s : %s %s", i+start,servers.length,server, skipping);
        if(skip)
        {
            stderr.writeln("* skipping %s because it does not begin with SYM",server);
            continue;
        }

        SessionInfo[] getSessionInfos(string server)
        {
            SessionInfo[] ret;
            uint entriesRead;
            uint totalentries;
            SESSION_INFO_10* bufptr;
            auto serverName = (server~ "\0").to!wstring;
            immutable(wchar)* servernamep = (serverName.length ==0) ? null : serverName.ptr;
            //auto result = NetFileEnum(null, null, null, 3, cast(ubyte**)&bufptr, MAX_PREFERRED_LENGTH, &entriesRead, &totalentries, null);
            auto result = NetSessionEnum(cast(wchar*)(servernamep), null, null, 10, cast(ubyte**)&bufptr, MAX_PREFERRED_LENGTH, &entriesRead, &totalentries, null);

            if (result == ERROR_ACCESS_DENIED)
            {
                stderr.writeln("ERROR_ACCESS_DENIED - insufficient permissions for %s", server);
            } else if (result==53)
            {
                stderr.writeln("RESULT 53 for %s",server);
            }
            else if (result==0 && totalentries >0)
            {
                foreach(e; bufptr[0 .. totalentries])
                {
                    auto info = SessionInfo(e);
                    ret ~=info;
                    writeln("Computer: ", info.computerName, " User: ", info.userName);
                }
            }
            else
            {
                writefln("unknown error for %s netsessionenum: %s",serverName,result);
            }

            if (bufptr !is null)
            {
                NetApiBufferFree(bufptr);
                bufptr=null;
            }
            return ret;
        }

        auto infos = getSessionInfos(server);
        

        ShareInfo[] getShareInfos(string server)
        {
            ShareInfo[] ret;
            uint entriesRead;
            uint totalentries;
            /* related docs :
            *
            * https://msdn.microsoft.com/en-us/library/windows/desktop/bb525387(v=vs.85).aspx
            * https://msdn.microsoft.com/en-us/library/windows/desktop/cc462916(v=vs.85).aspx
            */
            SESSION_INFO_503* ptr503;
            auto serverName = (server~ "\0").to!wstring;
            immutable(wchar)* servernamep = (serverName.length ==0) ? null : serverName.ptr;
            auto result = NetShareEnum(cast(wchar*)servernamep,503,cast(ubyte**) &ptr503, MAX_PREFERRED_LENGTH, &entriesRead, &totalentries, null);
            writefln("result of net share enum %s; totalentries %s; entriesRead %s",result, totalentries, entriesRead);
            if (result == ERROR_ACCESS_DENIED)
            {
                insufficientPermissions();
            } else if(result==0 || result==53)
            {
                foreach(e; ptr503[0 .. entriesRead])
                {
                    auto shareInfo = ShareInfo(e);
                    ret ~=shareInfo;
                    writeln(shareInfo.prettyPrint);
                    //writeln("Netname: ", share_netname, " Path: ", share_path);
                    /+                auto rights = enumerateAccess((`\\`~serverName[0..serverName.length-1]~`\` ~e.shi503_netname.fromZ).to!string.idup);
                    foreach(right;rights)
                    {
                    writefln("%s: %s",right.identityReference,right.fileSystemRights.rightsToString);
                    }
                    +/
                }
            }
            else
            {
                writefln("unknown error accessing %s netshareenum: %s",serverName,result);
            }

            if (ptr503 !is null)
            {
                NetApiBufferFree(ptr503);
                ptr503=null;
            }
            return ret;
        }

        shareInfos[server] = getShareInfos(server);
    }

    /+    SERVER_INFO_101 *ptrServer101;
    enum  SV_TYPE_NT =0x00001000;
    enum SV_TYPE_ALL = 0xFFFFFFFF;
    wstring domain = "options-it\0"w;
    wchar* domainp = cast(wchar*)domain.ptr;
    auto result = NetServerEnum(null,101U,cast(ubyte**) &ptrServer101, MAX_PREFERRED_LENGTH, &entriesRead, &totalentries, SV_TYPE_ALL, domainp,null);
    writefln("result of net server enum %s; totalentries %s; entriesRead %s",result, totalentries, entriesRead);
    if (result == ERROR_ACCESS_DENIED)
    {
    insufficientPermissions();
    } else foreach(e; ptrServer101[0 .. entriesRead])
    {
    auto serverResName = cast(const)e.sv101_name[0 .. wcslen(e.sv101_name)];
    auto serverComment = cast(const)e.sv101_comment[0 .. wcslen(e.sv101_comment)];  
    writeln("name: ", serverResName, " comment: ", serverComment);
    }
    if (ptrServer101 !is null)
    {
    NetApiBufferFree(ptrServer101);
    ptrServer101=null;
    }+/
    foreach(server; shareInfos.keys)
    {
        foreach(i,infos; shareInfos[server].filteredShareInfos)
        {
            writefln("%s,%s",server,infos);
        }
    }
}


/**
    filter shares to exclude:
        non diskDrive types
        C/D/E drives
        Orchestra logs
        Admin
        Print
*/
auto filteredShareInfos(ShareInfo[] shareInfos)
{
    import std.algorithm:filter,canFind;
    import std.array:array;
    return shareInfos.filter!(shareInfo => shareInfo.type == ShareInfoSubType.diskDrive &&
                              !canFind(["C$"w,"D$"w,"E$"w,"F$"w,"G$"w,"L$"w,"H$"w,"ORCHESTRALOGS"w,"OrchesTrade"w,"OrchestradeUpgrades"w,"ADMIN$"w,"print$"w],shareInfo.netname))
        .array;
}
