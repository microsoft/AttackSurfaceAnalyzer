using System.Runtime.InteropServices;
using System;

// Adapted from https://stackoverflow.com/questions/6596327/how-to-check-if-a-file-is-signed-in-c/6597017#6597017
// and https://docs.microsoft.com/en-us/windows/desktop/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
// and https://www.pinvoke.net/default.aspx/wintrust.winverifytrust

namespace AttackSurfaceAnalyzer.Libs
{
    internal static class AuthenticodeTools
    {



        enum WinVerifyTrustResult : uint
        {
            Success = 0,
            ProviderUnknown = 0x800b0001,           // Trust provider is not recognized on this system
            ActionUnknown = 0x800b0002,         // Trust provider does not support the specified action
            SubjectFormUnknown = 0x800b0003,        // Trust provider does not support the form specified for the subject
            SubjectNotTrusted = 0x800b0004,         // Subject failed the specified verification action
            FileNotSigned = 0x800B0100,         // TRUST_E_NOSIGNATURE - File was not signed
            SubjectExplicitlyDistrusted = 0x800B0111,   // Signer's certificate is in the Untrusted Publishers store
            SignatureOrFileCorrupt = 0x80096010,    // TRUST_E_BAD_DIGEST - file was probably corrupt
            SubjectCertExpired = 0x800B0101,        // CERT_E_EXPIRED - Signer's certificate was expired
            SubjectCertificateRevoked = 0x800B010C,     // CERT_E_REVOKED Subject's certificate was revoked
            UntrustedRoot = 0x800B0109          // CERT_E_UNTRUSTEDROOT - A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider.
        }

        [DllImport("Wintrust.dll", PreserveSig = true, SetLastError = false)]
        private static extern uint WinVerifyTrust(IntPtr hWnd, IntPtr pgActionID, IntPtr pWinTrustData);
        public static string WinVerifyTrust(string fileName)
        {

                

        Guid wintrust_action_generic_verify_v2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
            uint result = 0;
            using (WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO(fileName,
                                                                        Guid.Empty))
            using (UnmanagedPointer guidPtr = new UnmanagedPointer(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid))),
                                                                   AllocMethod.HGlobal))
            using (UnmanagedPointer wvtDataPtr = new UnmanagedPointer(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA))),
                                                                      AllocMethod.HGlobal))
            {
                WINTRUST_DATA data = new WINTRUST_DATA(fileInfo);
                IntPtr pGuid = guidPtr;
                IntPtr pData = wvtDataPtr;
                Marshal.StructureToPtr(wintrust_action_generic_verify_v2,
                                       pGuid,
                                       true);
                Marshal.StructureToPtr(data,
                                       pData,
                                       true);
                result = WinVerifyTrust(IntPtr.Zero,
                                        pGuid,
                                        pData);

            }
            switch ((WinVerifyTrustResult)result)
            {
                case WinVerifyTrustResult.Success:
                    return "Valid";
                case WinVerifyTrustResult.ProviderUnknown:
                    return "ProviderUnknown";
                case WinVerifyTrustResult.ActionUnknown:
                    return "ActionUnknown";
                case WinVerifyTrustResult.SubjectFormUnknown:
                    return "SubjectFormUnknown";
                case WinVerifyTrustResult.SubjectNotTrusted:
                    return "SubjectNotTrusted";
                case WinVerifyTrustResult.FileNotSigned:
                    return "FileNotSigned";
                case WinVerifyTrustResult.SubjectExplicitlyDistrusted:
                    return "SubjectExplicitlyDistrusted";
                case WinVerifyTrustResult.SignatureOrFileCorrupt:
                    return "SignatureOrFileCorrupt";
                case WinVerifyTrustResult.SubjectCertExpired:
                    return "SubjectCertExpired";
                case WinVerifyTrustResult.SubjectCertificateRevoked:
                    return "SubjectCertificateRevoked";
                case WinVerifyTrustResult.UntrustedRoot:
                    return "UntrustedRoot";
                default:
                    // The UI was disabled in dwUIChoice or the admin policy 
                    // has disabled user trust. lStatus contains the 
                    // publisher or time stamp chain error.
                    return result.ToString();
            }
        }
    }

    internal struct WINTRUST_FILE_INFO : IDisposable
    {

        public WINTRUST_FILE_INFO(string fileName, Guid subject)
        {

            cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));

            pcwszFilePath = fileName;



            if (subject != Guid.Empty)
            {

                pgKnownSubject = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));

                Marshal.StructureToPtr(subject, pgKnownSubject, true);

            }

            else
            {

                pgKnownSubject = IntPtr.Zero;

            }

            hFile = IntPtr.Zero;

        }

        public uint cbStruct;

        [MarshalAs(UnmanagedType.LPTStr)]

        public string pcwszFilePath;

        public IntPtr hFile;

        public IntPtr pgKnownSubject;



        #region IDisposable Members



        public void Dispose()
        {

            Dispose(true);

        }



        private void Dispose(bool disposing)
        {

            if (pgKnownSubject != IntPtr.Zero)
            {

                Marshal.DestroyStructure(this.pgKnownSubject, typeof(Guid));

                Marshal.FreeHGlobal(this.pgKnownSubject);

            }

        }



        #endregion

    }

    enum AllocMethod
    {
        HGlobal,
        CoTaskMem
    };
    enum UnionChoice
    {
        File = 1,
        Catalog,
        Blob,
        Signer,
        Cert
    };
    enum UiChoice
    {
        All = 1,
        NoUI,
        NoBad,
        NoGood
    };
    enum RevocationCheckFlags
    {
        None = 0,
        WholeChain
    };
    enum StateAction
    {
        Ignore = 0,
        Verify,
        Close,
        AutoCache,
        AutoCacheFlush
    };
    enum TrustProviderFlags
    {
        UseIE4Trust = 1,
        NoIE4Chain = 2,
        NoPolicyUsage = 4,
        RevocationCheckNone = 16,
        RevocationCheckEndCert = 32,
        RevocationCheckChain = 64,
        RecovationCheckChainExcludeRoot = 128,
        Safer = 256,
        HashOnly = 512,
        UseDefaultOSVerCheck = 1024,
        LifetimeSigning = 2048
    };
    enum UIContext
    {
        Execute = 0,
        Install
    };

    [StructLayout(LayoutKind.Sequential)]

    internal struct WINTRUST_DATA : IDisposable
    {

        public WINTRUST_DATA(WINTRUST_FILE_INFO fileInfo)
        {

            this.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));

            pInfoStruct = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));

            Marshal.StructureToPtr(fileInfo, pInfoStruct, false);

            this.dwUnionChoice = UnionChoice.File;



            pPolicyCallbackData = IntPtr.Zero;

            pSIPCallbackData = IntPtr.Zero;



            dwUIChoice = UiChoice.NoUI;

            fdwRevocationChecks = RevocationCheckFlags.None;

            dwStateAction = StateAction.Ignore;

            hWVTStateData = IntPtr.Zero;

            pwszURLReference = IntPtr.Zero;

            dwProvFlags = TrustProviderFlags.Safer;



            dwUIContext = UIContext.Execute;

        }



        public uint cbStruct;

        public IntPtr pPolicyCallbackData;

        public IntPtr pSIPCallbackData;

        public UiChoice dwUIChoice;

        public RevocationCheckFlags fdwRevocationChecks;

        public UnionChoice dwUnionChoice;

        public IntPtr pInfoStruct;

        public StateAction dwStateAction;

        public IntPtr hWVTStateData;

        private IntPtr pwszURLReference;

        public TrustProviderFlags dwProvFlags;

        public UIContext dwUIContext;



        #region IDisposable Members



        public void Dispose()
        {

            Dispose(true);

        }



        private void Dispose(bool disposing)
        {

            if (dwUnionChoice == UnionChoice.File)
            {

                WINTRUST_FILE_INFO info = new WINTRUST_FILE_INFO();

                Marshal.PtrToStructure(pInfoStruct, info);

                info.Dispose();

                Marshal.DestroyStructure(pInfoStruct, typeof(WINTRUST_FILE_INFO));

            }



            Marshal.FreeHGlobal(pInfoStruct);

        }



        #endregion

    }

    internal sealed class UnmanagedPointer : IDisposable
    {

        private IntPtr m_ptr;

        private AllocMethod m_meth;

        internal UnmanagedPointer(IntPtr ptr, AllocMethod method)
        {

            m_meth = method;

            m_ptr = ptr;

        }



        ~UnmanagedPointer()
        {

            Dispose(false);

        }



        #region IDisposable Members

        private void Dispose(bool disposing)
        {

            if (m_ptr != IntPtr.Zero)
            {

                if (m_meth == AllocMethod.HGlobal)
                {

                    Marshal.FreeHGlobal(m_ptr);

                }

                else if (m_meth == AllocMethod.CoTaskMem)
                {

                    Marshal.FreeCoTaskMem(m_ptr);

                }

                m_ptr = IntPtr.Zero;

            }



            if (disposing)
            {

                GC.SuppressFinalize(this);

            }

        }



        public void Dispose()
        {

            Dispose(true);

        }



        #endregion



        public static implicit operator IntPtr(UnmanagedPointer ptr)
        {

            return ptr.m_ptr;

        }

    }
}
