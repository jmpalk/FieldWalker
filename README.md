# FieldWalker
A .NET tool for gathering credentials from known locations and files on Windows hosts, using WMI. Inspired by [SessionGopher](https://github.com/Arvanaghi/SessionGopher). 
FieldWalker will search for credentials stored by the following programs:
+ FileZilla
+ WinSCP
+ mRemoteNG
+ PuTTY
+ SuperPuTTY
+ RDP
  
FieldWalker will also search for ssh keys in the form of `id_rsa` files and PuTTY `.ppk` files, and will examine Microsoft Answer files (e.g., `unattend.xml`) to identify stored credentials. 

FieldWalker will run on the local computer with the credentials of the currently-authenticated user, or the user can supply credentials and a remote host to target to search that host using WMI.

## Usage
```> FieldWalker.exe -u someuser -p theirpassword -d TARGETDOMAIN -t server1 -o C:\temp\
> FieldWalker -h
Flags:
-h - Show this help message
-u - username for authentication
-p - password for authentication
-d - domain for authentication
-c - if using '-t' or '-l', also target the localhost
-t - remote host to target (incompatible with '-l')
-l - comma-separated list of remote hosts to target (incompatible with '-t')
-o - output directory for writing .ppk and id_rsa files
-v - generate more output
-d - generate a lot of debugging output
```

## ToDo
+ Automatically decrypt mRemoteNG credentials
+ Search for VNC credentials
+ Add "Find interesting files" functionality to search more broadly for files containing keywords
+ Add CIM support

