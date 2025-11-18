using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.IO;
using System.Net;

namespace TokenCreator
{
    class Program
    {
        #region WinAPI Imports
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        // Logon Types
        const int LOGON32_LOGON_INTERACTIVE = 2;
        const int LOGON32_LOGON_NETWORK = 3;
        const int LOGON32_LOGON_NEW_CREDENTIALS = 9;

        // Logon Provider
        const int LOGON32_PROVIDER_WINNT50 = 3;

        // Token Access
        const uint TOKEN_QUERY = 0x0008;

        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenStatistics = 10
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_STATISTICS
        {
            public LUID TokenId;
            public LUID AuthenticationId;
            public long ExpirationTime;
            public int TokenType;
            public int ImpersonationLevel;
            public int DynamicCharged;
            public int DynamicAvailable;
            public int GroupCount;
            public int PrivilegeCount;
            public LUID ModifiedId;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }
        #endregion

        static void Main(string[] args)
        {
            Console.WriteLine("=======================================================");
            Console.WriteLine("     Universal Token Creator & Network Authenticator");
            Console.WriteLine("=======================================================\n");

            if (args.Length < 3)
            {
                ShowUsage();
                return;
            }

            string username = args[0];
            string password = args[1];
            string domain = args[2];
            int logonType = args.Length > 3 ? int.Parse(args[3]) : LOGON32_LOGON_NEW_CREDENTIALS;

            Console.WriteLine($"[*] Username: {domain}\\{username}");
            Console.WriteLine($"[*] Logon Type: {GetLogonTypeName(logonType)} ({logonType})");
            Console.WriteLine($"[*] Current Identity: {WindowsIdentity.GetCurrent().Name}\n");

            // Create token
            IntPtr hToken = IntPtr.Zero;
            Console.WriteLine("[1] Creating token from credentials...");
            
            if (!LogonUser(username, domain, password, logonType, LOGON32_PROVIDER_WINNT50, out hToken))
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine($"[-] LogonUser failed!");
                Console.WriteLine($"[-] Error Code: {error}");
                Console.WriteLine($"[-] Error: {GetErrorMessage(error)}");
                return;
            }

            Console.WriteLine($"[+] Token created successfully!");
            Console.WriteLine($"[*] Token Handle: 0x{hToken.ToString("X")}\n");

            try
            {
                // Display token info
                DisplayTokenInfo(hToken);

                // Impersonate
                Console.WriteLine("\n[2] Impersonating user token...");
                if (!ImpersonateLoggedOnUser(hToken))
                {
                    Console.WriteLine($"[-] Impersonation failed. Error: {Marshal.GetLastWin32Error()}");
                    return;
                }

                Console.WriteLine($"[+] Successfully impersonating!");
                Console.WriteLine($"[*] Impersonated Identity: {WindowsIdentity.GetCurrent().Name}");
                Console.WriteLine($"[*] Authentication Type: {WindowsIdentity.GetCurrent().AuthenticationType}");
                Console.WriteLine($"[*] Impersonation Level: {WindowsIdentity.GetCurrent().ImpersonationLevel}\n");

                // Interactive mode - test network access
                Console.WriteLine("=======================================================");
                Console.WriteLine("  Token Active - Test Network Authentication");
                Console.WriteLine("=======================================================\n");
                Console.WriteLine("The token is now active. All network operations will use");
                Console.WriteLine($"the credentials: {domain}\\{username}\n");

                InteractiveMenu(domain, username);

                // Revert
                Console.WriteLine("\n[*] Reverting to original identity...");
                RevertToSelf();
                Console.WriteLine($"[+] Reverted to: {WindowsIdentity.GetCurrent().Name}");
            }
            finally
            {
                if (hToken != IntPtr.Zero)
                {
                    CloseHandle(hToken);
                    Console.WriteLine("[*] Token handle closed.");
                }
            }
        }

        static void InteractiveMenu(string domain, string username)
        {
            while (true)
            {
                Console.WriteLine("\n--- Network Authentication Test Menu ---");
                Console.WriteLine("1. Test SMB Share Access");
                Console.WriteLine("2. Test Network Path Listing");
                Console.WriteLine("3. Test UNC Path Access");
                Console.WriteLine("4. Test Remote Registry (if accessible)");
                Console.WriteLine("5. Custom Network Test");
                Console.WriteLine("6. Keep Token Active (Drop to Command Prompt)");
                Console.WriteLine("7. Exit (Revert Token)");
                Console.Write("\nChoice: ");

                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        TestSMBShare();
                        break;
                    case "2":
                        TestNetworkPath();
                        break;
                    case "3":
                        TestUNCPath();
                        break;
                    case "4":
                        TestRemoteAccess();
                        break;
                    case "5":
                        CustomNetworkTest();
                        break;
                    case "6":
                        KeepTokenActive(domain, username);
                        break;
                    case "7":
                        return;
                    default:
                        Console.WriteLine("[-] Invalid choice");
                        break;
                }
            }
        }

        static void TestSMBShare()
        {
            Console.Write("\n[*] Enter UNC path (e.g., \\\\SERVER\\share): ");
            string path = Console.ReadLine();

            try
            {
                Console.WriteLine($"[*] Testing access to: {path}");
                
                if (Directory.Exists(path))
                {
                    Console.WriteLine("[+] Share is accessible!");
                    Console.WriteLine("\n[*] Attempting to list contents...");
                    
                    string[] items = Directory.GetFileSystemEntries(path);
                    Console.WriteLine($"[+] Found {items.Length} items:\n");
                    
                    int displayCount = Math.Min(items.Length, 20);
                    for (int i = 0; i < displayCount; i++)
                    {
                        string itemName = Path.GetFileName(items[i]);
                        bool isDir = Directory.Exists(items[i]);
                        Console.WriteLine($"  {(isDir ? "[DIR] " : "[FILE]")} {itemName}");
                    }
                    
                    if (items.Length > 20)
                    {
                        Console.WriteLine($"\n  ... and {items.Length - 20} more items");
                    }
                }
                else
                {
                    Console.WriteLine("[-] Share not accessible or doesn't exist");
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[-] Access denied - credentials may not have permission");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }

        static void TestNetworkPath()
        {
            Console.Write("\n[*] Enter server name (e.g., SERVER01): ");
            string server = Console.ReadLine();

            Console.WriteLine($"\n[*] Testing common shares on: {server}");
            
            string[] commonShares = { "C$", "ADMIN$", "IPC$", "SYSVOL", "NETLOGON", "Share" };
            
            foreach (string share in commonShares)
            {
                string uncPath = $"\\\\{server}\\{share}";
                try
                {
                    if (Directory.Exists(uncPath))
                    {
                        Console.WriteLine($"[+] {uncPath} - Accessible");
                    }
                    else
                    {
                        Console.WriteLine($"[-] {uncPath} - Not accessible");
                    }
                }
                catch
                {
                    Console.WriteLine($"[-] {uncPath} - Access denied or error");
                }
            }
        }

        static void TestUNCPath()
        {
            Console.Write("\n[*] Enter full UNC path: ");
            string path = Console.ReadLine();

            try
            {
                Console.WriteLine($"[*] Testing: {path}");
                
                if (File.Exists(path))
                {
                    Console.WriteLine("[+] File exists and is accessible");
                    FileInfo fi = new FileInfo(path);
                    Console.WriteLine($"[*] Size: {fi.Length} bytes");
                    Console.WriteLine($"[*] Modified: {fi.LastWriteTime}");
                }
                else if (Directory.Exists(path))
                {
                    Console.WriteLine("[+] Directory exists and is accessible");
                    DirectoryInfo di = new DirectoryInfo(path);
                    Console.WriteLine($"[*] Created: {di.CreationTime}");
                    Console.WriteLine($"[*] Items: {di.GetFileSystemInfos().Length}");
                }
                else
                {
                    Console.WriteLine("[-] Path does not exist or is not accessible");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }

        static void TestRemoteAccess()
        {
            Console.Write("\n[*] Enter remote computer name: ");
            string computer = Console.ReadLine();

            Console.WriteLine($"\n[*] Testing remote access to: {computer}");
            
            // Test admin share
            string adminPath = $"\\\\{computer}\\C$";
            Console.Write($"[*] Testing {adminPath}... ");
            try
            {
                if (Directory.Exists(adminPath))
                {
                    Console.WriteLine("Accessible!");
                }
                else
                {
                    Console.WriteLine("Not accessible");
                }
            }
            catch
            {
                Console.WriteLine("Access denied");
            }

            // Test computer reachability
            Console.Write($"[*] Testing network connectivity... ");
            try
            {
                System.Net.NetworkInformation.Ping ping = new System.Net.NetworkInformation.Ping();
                var reply = ping.Send(computer, 1000);
                if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                {
                    Console.WriteLine($"Online ({reply.RoundtripTime}ms)");
                }
                else
                {
                    Console.WriteLine("Unreachable");
                }
            }
            catch
            {
                Console.WriteLine("Unable to ping");
            }
        }

        static void CustomNetworkTest()
        {
            Console.WriteLine("\n[*] Custom Network Test");
            Console.WriteLine("[*] Enter any network command to test authentication\n");
            Console.WriteLine("Examples:");
            Console.WriteLine("  dir \\\\SERVER\\Share");
            Console.WriteLine("  type \\\\SERVER\\Share\\file.txt");
            Console.WriteLine("  net use \\\\SERVER\\Share");
            Console.WriteLine("  copy file.txt \\\\SERVER\\Share\\");
            Console.Write("\n> ");
            
            string command = Console.ReadLine();
            
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (!string.IsNullOrEmpty(output))
                    {
                        Console.WriteLine("\n[Output]");
                        Console.WriteLine(output);
                    }

                    if (!string.IsNullOrEmpty(error))
                    {
                        Console.WriteLine("\n[Error]");
                        Console.WriteLine(error);
                    }

                    Console.WriteLine($"\n[*] Exit Code: {process.ExitCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }

        static void KeepTokenActive(string domain, string username)
        {
            Console.WriteLine("\n=======================================================");
            Console.WriteLine("  Token Remains Active - Interactive Mode");
            Console.WriteLine("=======================================================\n");
            Console.WriteLine($"[*] Token is active for: {domain}\\{username}");
            Console.WriteLine("[*] All network operations will use these credentials");
            Console.WriteLine("[*] You can now:");
            Console.WriteLine("    - Access network shares: dir \\\\server\\share");
            Console.WriteLine("    - Copy files: copy file.txt \\\\server\\share\\");
            Console.WriteLine("    - Map drives: net use Z: \\\\server\\share");
            Console.WriteLine("    - Use any network tool (psexec, wmic, etc.)");
            Console.WriteLine("\n[!] Press ENTER when done to revert token...\n");
            Console.ReadLine();
        }

        static void DisplayTokenInfo(IntPtr hToken)
        {
            Console.WriteLine("[*] Token Information:");
            
            int tokenInformationLength = Marshal.SizeOf(typeof(TOKEN_STATISTICS));
            IntPtr tokenInformation = Marshal.AllocHGlobal(tokenInformationLength);

            try
            {
                if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenStatistics, 
                    tokenInformation, tokenInformationLength, out tokenInformationLength))
                {
                    TOKEN_STATISTICS stats = (TOKEN_STATISTICS)Marshal.PtrToStructure(
                        tokenInformation, typeof(TOKEN_STATISTICS));

                    Console.WriteLine($"    Token ID: 0x{stats.TokenId.HighPart:X8}{stats.TokenId.LowPart:X8}");
                    Console.WriteLine($"    Auth ID: 0x{stats.AuthenticationId.HighPart:X8}{stats.AuthenticationId.LowPart:X8}");
                    Console.WriteLine($"    Token Type: {(stats.TokenType == 1 ? "Primary" : "Impersonation")}");
                    Console.WriteLine($"    Privilege Count: {stats.PrivilegeCount}");
                    Console.WriteLine($"    Group Count: {stats.GroupCount}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tokenInformation);
            }
        }

        static void ShowUsage()
        {
            Console.WriteLine("Universal Token Creator - Create tokens for ANY network authentication\n");
            Console.WriteLine("Usage:");
            Console.WriteLine("  TokenCreator.exe <username> <password> <domain> [logonType]\n");
            Console.WriteLine("Arguments:");
            Console.WriteLine("  username   - Username to authenticate");
            Console.WriteLine("  password   - User password");
            Console.WriteLine("  domain     - Domain name (use '.' for local)");
            Console.WriteLine("  logonType  - Optional: 2=Interactive, 3=Network, 9=NewCredentials (default: 9)\n");
            Console.WriteLine("Examples:");
            Console.WriteLine("  TokenCreator.exe admin P@ssw0rd DOMAIN");
            Console.WriteLine("  TokenCreator.exe sqluser Password123 CORP 9");
            Console.WriteLine("  TokenCreator.exe .\\localadmin P@ss . 9\n");
            Console.WriteLine("What you can do with the token:");
            Console.WriteLine("  - Access SMB/CIFS shares (\\\\server\\share)");
            Console.WriteLine("  - Connect to SQL Server with Windows Auth");
            Console.WriteLine("  - Use WMI for remote management");
            Console.WriteLine("  - Execute remote commands (psexec, wmic)");
            Console.WriteLine("  - Map network drives");
            Console.WriteLine("  - Access remote registries");
            Console.WriteLine("  - ANY network operation requiring authentication\n");
            Console.WriteLine("How it works:");
            Console.WriteLine("  1. Creates token from provided credentials");
            Console.WriteLine("  2. Impersonates that token in current process");
            Console.WriteLine("  3. All network operations now use those credentials");
            Console.WriteLine("  4. Local operations still use your original identity");
            Console.WriteLine("  5. Token reverted when you exit\n");
            Console.WriteLine("Note: Use logon type 9 (NEW_CREDENTIALS) for network-only auth.");
            Console.WriteLine("      This keeps your local identity but uses new creds for network.");
        }

        static string GetLogonTypeName(int logonType)
        {
            switch (logonType)
            {
                case LOGON32_LOGON_INTERACTIVE:
                    return "Interactive";
                case LOGON32_LOGON_NETWORK:
                    return "Network";
                case LOGON32_LOGON_NEW_CREDENTIALS:
                    return "NewCredentials (Network-Only)";
                default:
                    return "Unknown";
            }
        }

        static string GetErrorMessage(int errorCode)
        {
            switch (errorCode)
            {
                case 1326:
                    return "Invalid username or password";
                case 1385:
                    return "Logon type not granted to user";
                case 1314:
                    return "Privilege not held (need admin for some logon types)";
                case 1311:
                    return "No such user exists";
                case 1909:
                    return "Account is locked out";
                case 1330:
                    return "Password has expired";
                case 1331:
                    return "Account is disabled";
                case 5:
                    return "Access denied";
                default:
                    return $"Error code: {errorCode}";
            }
        }
    }
}
