/******************************************************************************
Copyright Andreas Nick 2021

This is a PowerShell module for recording performance data close to the hardware. 
Similar to the task manager, this module is supposed to provide very fast 
information about the CPU usage percentage.
*******************************************************************************/



using System;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Collections;

namespace NITProcessTools
{

    [Cmdlet(VerbsCommon.Get, "NITProcessCpuLoad")]
    [OutputType(typeof(ProcessInformationRecord))]
    public class GetNITProcessCpuLoad : PSCmdlet
    {
        // Many Informations for Kernal based procedures are from /www.pinvoke.net
        // https://www.pinvoke.net/default.aspx/psapi.getprocessmemoryinfo
        //inner enum used only internally
        [Flags]
        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }

        //inner struct used only internally
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct PROCESSENTRY32
        {
            const int MAX_PATH = 260;
            internal uint dwSize;
            internal uint cntUsage;
            internal uint th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal uint th32ModuleID;
            internal uint cntThreads;
            internal uint th32ParentProcessID;
            internal int pcPriClassBase;
            internal uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExeFile;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class inProcess
        {
            internal IntPtr Handle;
            public uint ID;
            public string UserName;
            public string Domain;
            public int BasePriority;
            public double PercentProcessorTime;
            public ulong UsedMemory;
            public uint ThreadCount;
            public ulong UpTime;
            public string ExeName;
            public uint ParentPID;
            public ulong DiskOperationsPrev;
            public ulong DiskOperations;
            public uint DiskUsage;
            public uint TreeDepth;
        }


        /*
        [StructLayout(LayoutKind.Sequential, Size = 40)]
        private struct PROCESS_MEMORY_COUNTERS
        {
            public uint cb;             // The size of the structure, in bytes (DWORD).
            public uint PageFaultCount;         // The number of page faults (DWORD).
            public uint PeakWorkingSetSize;     // The peak working set size, in bytes (SIZE_T).
            public uint WorkingSetSize;         // The current working set size, in bytes (SIZE_T).
            public uint QuotaPeakPagedPoolUsage;    // The peak paged pool usage, in bytes (SIZE_T).
            public uint QuotaPagedPoolUsage;    // The current paged pool usage, in bytes (SIZE_T).
            public uint QuotaPeakNonPagedPoolUsage; // The peak nonpaged pool usage, in bytes (SIZE_T).
            public uint QuotaNonPagedPoolUsage;     // The current nonpaged pool usage, in bytes (SIZE_T).
            public uint PagefileUsage;          // The Commit Charge value in bytes for this process (SIZE_T). Commit Charge is the total amount of memory that the memory manager has committed for a running process.
            public uint PeakPagefileUsage;      // The peak value in bytes of the Commit Charge during the lifetime of this process (SIZE_T).
        } */

        [StructLayout(LayoutKind.Sequential, Size = 72)]
        private struct PROCESS_MEMORY_COUNTERS
        {
            public uint cb;
            public uint PageFaultCount;
            public ulong PeakWorkingSetSize;
            public ulong WorkingSetSize;
            public ulong QuotaPeakPagedPoolUsage;
            public ulong QuotaPagedPoolUsage;
            public ulong QuotaPeakNonPagedPoolUsage;
            public ulong QuotaNonPagedPoolUsage;
            public ulong PagefileUsage;
            public ulong PeakPagefileUsage;
        }

        //Use these for DesiredAccess
        private const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        private const uint STANDARD_RIGHTS_READ = 0x00020000;
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_QUERY_SOURCE = 0x0010;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_ADJUST_GROUPS = 0x0040;
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private const uint TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;
        private const uint TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID;


        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }

        private enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        
        private struct TOKEN_GROUPS
        {
            public uint GroupCount;
            [MarshalAs(UnmanagedType.ByValArray)] public SID_AND_ATTRIBUTES[] Groups;
        }
        

        [StructLayout(LayoutKind.Sequential)]
        private struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        
        private struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }
        

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint DateTimeLow;
            public uint DateTimeHigh;
        }

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        private struct LARGE_INTEGER
        {
            [FieldOffset(0)] public long QuadPart;
            [FieldOffset(0)] public uint LowPart;
            [FieldOffset(4)] public int HighPart;
        }

        private struct process_times
        {
            internal FILETIME CreationTime, ExitTime, KernelTime, UserTime;

        };
        private struct system_times
        {
            internal FILETIME IdleTime, KernelTime, UserTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        };

        [StructLayout(LayoutKind.Explicit)]
        internal struct _PROCESSOR_INFO_UNION
        {
            [FieldOffset(0)]
            internal uint dwOemId;
            [FieldOffset(0)]
            internal ushort wProcessorArchitecture;
            [FieldOffset(2)]
            internal ushort wReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_INFO
        {
            internal _PROCESSOR_INFO_UNION uProcessorInfo;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort dwProcessorLevel;
            public ushort dwProcessorRevision;
        }


        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool LookupAccountSid(string lpSystemName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, System.Text.StringBuilder lpName, ref uint cchName, System.Text.StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr CreateToolhelp32Snapshot([In] uint dwFlags, [In] uint th32ProcessID);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle([In] IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [DllImport("psapi.dll", SetLastError = true)]
        static extern bool GetProcessMemoryInfo(IntPtr hProcess, out PROCESS_MEMORY_COUNTERS counters, uint size);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetSystemTimes(
            out FILETIME lpIdleTime,
            out FILETIME lpKernelTime,
            out FILETIME lpUserTime
            );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetProcessTimes(IntPtr hProcess, out FILETIME
        lpCreationTime, out FILETIME lpExitTime, out FILETIME lpKernelTime, out FILETIME lpUserTime);

        [DllImport("kernel32.dll")]
        static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS lpIoCounters);

        [DllImport("kernel32.dll")]
        static extern void GetSystemTimeAsFileTime(out FILETIME lpSystemTimeAsFileTime);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        internal static extern void GetSystemInfo([MarshalAs(UnmanagedType.Struct)] ref SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = false)]
        private static extern bool QueryPerformanceFrequency(out long lpPerformanceFreq);

        static ulong SubtractTimes(FILETIME A, FILETIME B)
        {

            LARGE_INTEGER lA, lB;
            lA.QuadPart = 0;
            lB.QuadPart = 0;
            lA.LowPart = A.DateTimeLow;
            lA.HighPart = (int)A.DateTimeHigh;
            lB.LowPart = B.DateTimeLow;
            lB.HighPart = (int)B.DateTimeHigh;
            return (ulong)(lA.QuadPart - lB.QuadPart);
        }

        //Return Values
        public class ProcessInformationRecord
        {
            public string Name { get; set; }
            public string FQDN { get; set; }
            public string CPUName { get; set; }
            public ArrayList ProcessList { get; set; }
            public double CPUUsage { get; set; }
            public uint CPUCorerCount { get; set; }
            //public double Frequency { get; set; }
        }


        private Uri uploadURL;
        private int updateTime = 150; //milliseconds

        [Parameter]
        public Uri UploadURL { get => uploadURL; set => uploadURL = value; }

        [Parameter]
        public int UpdateTime { get => updateTime; set => updateTime = value; }

        protected override void ProcessRecord()
        {

            int MAX_INTPTR_BYTE_ARR_SIZE = 512;
            IntPtr handleToSnapshot = IntPtr.Zero;
            byte[] sidBytes;
            System.Text.StringBuilder name = new System.Text.StringBuilder();
            uint cchName = (uint)name.Capacity;
            System.Text.StringBuilder referencedDomainName = new System.Text.StringBuilder();
            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
            SID_NAME_USE sidUse;
            uint RunningProcessCount = 0;

            ArrayList proclist = new ArrayList();

            try
            {
                PROCESSENTRY32 procEntry = new PROCESSENTRY32();
                procEntry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
                handleToSnapshot = CreateToolhelp32Snapshot((uint)SnapshotFlags.Process, 0);
                if (Process32First(handleToSnapshot, ref procEntry))
                {
                    do
                    {
                        inProcess mypro = new inProcess();
                        mypro.ID = procEntry.th32ProcessID;
                        mypro.ThreadCount = procEntry.cntThreads;
                        mypro.BasePriority = procEntry.pcPriClassBase;
                        mypro.ParentPID = procEntry.th32ParentProcessID;
                        mypro.ExeName = procEntry.szExeFile;
                        mypro.UserName = "SYSTEM";

                        if (procEntry.th32ProcessID != 0)
                        {
                            mypro.Handle = OpenProcess(0x00001000, false, procEntry.th32ProcessID);
                            if (null != mypro.Handle)
                            {
                                // PROCESS_MEMORY_COUNTERS ProcMemCounters;
                                PROCESS_MEMORY_COUNTERS pr;


                                pr.cb = (uint)Marshal.SizeOf(typeof(PROCESS_MEMORY_COUNTERS));


                                bool res = GetProcessMemoryInfo(mypro.Handle, out pr, pr.cb);
                                // Console.WriteLine("Get Memory Info : " + Marshal.GetLastWin32Error());

                                if (res)
                                {
                                    mypro.UsedMemory = pr.WorkingSetSize;
                                    // Console.WriteLine(pr.WorkingSetSize);
                                }
                                IntPtr tokenHandle;
                                res = OpenProcessToken(mypro.Handle, TOKEN_READ, out tokenHandle);
                                if (res)
                                {
                                    uint tokenInfoLength = 0;
                                    res = GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInfoLength, out tokenInfoLength);
                                    IntPtr tokenInfo = Marshal.AllocHGlobal((int)tokenInfoLength);
                                    res = GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser, tokenInfo, tokenInfoLength, out tokenInfoLength);  // get the token info
                                    // Get the User SID
                                    if (res)
                                    {
                                        TOKEN_USER tokenUser = (TOKEN_USER)Marshal.PtrToStructure(tokenInfo, typeof(TOKEN_USER));
                                        sidBytes = new byte[MAX_INTPTR_BYTE_ARR_SIZE];  // Since I don't yet know how to be more precise w/ the size of the byte arr, it is being set to 512
                                        Marshal.Copy(tokenUser.User.Sid, sidBytes, 0, MAX_INTPTR_BYTE_ARR_SIZE);  // get a byte[] representation of the SID
                                        name.EnsureCapacity((int)cchName);
                                        referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                                        res = LookupAccountSid(null, sidBytes, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse);
                                        if (res)
                                        {
                                            mypro.UserName = name.ToString();
                                            mypro.Domain = referencedDomainName.ToString();
                                        }
                                        proclist.Add(mypro);
                                    }
                                    Marshal.FreeHGlobal(tokenInfo);
                                    res = CloseHandle(tokenHandle);
                                }
                            }
                        }

                    } while (Process32Next(handleToSnapshot, ref procEntry));

                }
                else
                {
                    throw new ApplicationException(string.Format("Failed with win32 error code {0}", Marshal.GetLastWin32Error()));
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Can't get the process.", ex);
            }
            finally
            {
                CloseHandle(handleToSnapshot);
            }


            system_times PrevSysTimes = new system_times();
            GetSystemTimes(out PrevSysTimes.IdleTime, out PrevSysTimes.KernelTime, out PrevSysTimes.UserTime);
            process_times[] ProcessTime = new process_times[proclist.Count];


            for (int index = 0; index < proclist.Count; index++)
            {
                if (null != ((inProcess)proclist[index]).Handle)
                {
                    GetProcessTimes(((inProcess)proclist[index]).Handle, out ProcessTime[index].CreationTime, out ProcessTime[index].ExitTime,
                         out ProcessTime[index].KernelTime, out ProcessTime[index].UserTime);

                    IO_COUNTERS IoCounters;
                    if (GetProcessIoCounters(((inProcess)proclist[index]).Handle, out IoCounters))
                    {
                        ((inProcess)proclist[index]).DiskOperationsPrev = IoCounters.ReadTransferCount + IoCounters.WriteTransferCount;
                    }
                }


            }

            // System.Threading.Thread.Sleep(UpdateTime);
            Sleep((uint)UpdateTime);

            //Second Measure
            system_times SysTimes = new system_times();
            GetSystemTimes(out SysTimes.IdleTime, out SysTimes.KernelTime, out SysTimes.UserTime);

            ulong SysTimesKernelTime = ((ulong)SysTimes.KernelTime.DateTimeHigh << 32) + SysTimes.KernelTime.DateTimeLow;
            ulong PrevSysTimesKernelTime = ((ulong)PrevSysTimes.KernelTime.DateTimeHigh << 32) + PrevSysTimes.KernelTime.DateTimeLow;
            ulong SysKernelDiff = SysTimesKernelTime - PrevSysTimesKernelTime;

            ulong SysTimesUserTime = ((ulong)SysTimes.UserTime.DateTimeHigh << 32) + SysTimes.UserTime.DateTimeLow;
            ulong PrevSysTimesUserTime = ((ulong)PrevSysTimes.UserTime.DateTimeHigh << 32) + PrevSysTimes.UserTime.DateTimeLow;
            ulong SysUserDiff = SysTimesUserTime - PrevSysTimesUserTime;

            ulong SysTimesIdelTime = ((ulong)SysTimes.IdleTime.DateTimeHigh << 32) + SysTimes.IdleTime.DateTimeLow;
            ulong PrevSysTimesIdelTime = ((ulong)PrevSysTimes.IdleTime.DateTimeHigh << 32) + PrevSysTimes.IdleTime.DateTimeLow;
            ulong SysIdleDiff = SysTimesIdelTime - PrevSysTimesIdelTime;

            process_times NextProcessTime = new process_times();
            RunningProcessCount = 0;

            for (int index = 0; index < proclist.Count; index++)
            {
                if (null != ((inProcess)proclist[index]).Handle)
                {
                    GetProcessTimes(((inProcess)proclist[index]).Handle, out NextProcessTime.CreationTime, out NextProcessTime.ExitTime, out NextProcessTime.KernelTime, out NextProcessTime.UserTime);

                    ulong NPTime = ((ulong)NextProcessTime.KernelTime.DateTimeHigh << 32) + NextProcessTime.KernelTime.DateTimeLow;
                    ulong PPTime = ((ulong)ProcessTime[index].KernelTime.DateTimeHigh << 32) + ProcessTime[index].KernelTime.DateTimeLow;
                    ulong ProcKernelDiff = NPTime - PPTime;

                    ulong NUTime = ((ulong)NextProcessTime.UserTime.DateTimeHigh << 32) + NextProcessTime.UserTime.DateTimeLow;
                    ulong PUTime = ((ulong)ProcessTime[index].UserTime.DateTimeHigh << 32) + ProcessTime[index].UserTime.DateTimeLow;
                    ulong ProcUserDiff = NUTime - PUTime;

                    ulong TotalSys = SysKernelDiff + SysUserDiff;
                    ulong TotalProc = ProcKernelDiff + ProcUserDiff;

                    if (TotalSys > 0)
                    {

                        double cpuusage = (double)(100.0 * TotalProc / TotalSys);

                        //calculation errors occur
                        if (cpuusage > 99.00) { cpuusage = 99.00; };

                        ((inProcess)proclist[index]).PercentProcessorTime = cpuusage;

                        if (((inProcess)proclist[index]).PercentProcessorTime >= 0.01)
                        {
                            RunningProcessCount++;
                        }
                    }

                    FILETIME SysTime;
                    GetSystemTimeAsFileTime(out SysTime);
                    ((inProcess)proclist[index]).UpTime = SubtractTimes(SysTime, NextProcessTime.CreationTime) / 10000;

                    IO_COUNTERS IoCounters;
                    if (GetProcessIoCounters(((inProcess)proclist[index]).Handle, out IoCounters))
                    {
                        ((inProcess)proclist[index]).DiskOperations = IoCounters.ReadTransferCount + IoCounters.WriteTransferCount;
                        ulong Op = ((inProcess)proclist[index]).DiskOperationsPrev * (1000 / (ulong)UpdateTime);
                        ((inProcess)proclist[index]).DiskUsage = (uint)(((inProcess)proclist[index]).DiskOperations - Op);
                    }
                    CloseHandle(((inProcess)proclist[index]).Handle);
                    ((inProcess)proclist[index]).Handle = (IntPtr)0;
                }
            }

            // CRITICAL_SECTION ?

            ulong STime = SysKernelDiff + SysUserDiff;
            double CPUUsage;

            if (STime > 0)
            {
                double Percentage = (STime - SysIdleDiff) / (double)STime;
                CPUUsage = Math.Min(Percentage, 1.0) * 100.0;
            }
            else
            {
                CPUUsage = 0;
            }

            //CPU Cores, Freuency and name
            SYSTEM_INFO sinfo = new SYSTEM_INFO();
            GetSystemInfo(ref sinfo);

            uint numCore = sinfo.dwNumberOfProcessors;

            //long freq;
            //QueryPerformanceFrequency(out freq);
            //System.Console.WriteLine("Debug :" + freq);

            ProcessInformationRecord retval = new ProcessInformationRecord
            {
                Name = Environment.MachineName,
                FQDN = System.Net.Dns.GetHostEntry(Environment.MachineName).HostName,
                ProcessList = proclist,
                CPUUsage = CPUUsage,
                CPUName = (string)Microsoft.Win32.Registry.GetValue(@"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0\", "ProcessorNameString", null),
                CPUCorerCount = numCore
                //Frequency = (double) ((double) freq )

            };

            WriteObject(retval);

        }
    }
}
