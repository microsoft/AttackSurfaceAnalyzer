// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Serilog;
using System;
using System.Runtime.InteropServices;
// Adapted from
// https://www.pinvoke.net/default.aspx/wintrust.winverifytrust

namespace AttackSurfaceAnalyzer.Libs
{
    #region WinTrustData struct field enums
    enum WinTrustDataUIChoice : uint
    {
        All = 1,
        None = 2,
        NoBad = 3,
        NoGood = 4
    }

    enum WinTrustDataRevocationChecks : uint
    {
        None = 0x00000000,
        WholeChain = 0x00000001
    }

    enum WinTrustDataChoice : uint
    {
        File = 1,
        Catalog = 2,
        Blob = 3,
        Signer = 4,
        Certificate = 5
    }

    enum WinTrustDataStateAction : uint
    {
        Ignore = 0x00000000,
        Verify = 0x00000001,
        Close = 0x00000002,
        AutoCache = 0x00000003,
        AutoCacheFlush = 0x00000004
    }

    [FlagsAttribute]
    enum WinTrustDataProvFlags : uint
    {
        UseIe4TrustFlag = 0x00000001,
        NoIe4ChainFlag = 0x00000002,
        NoPolicyUsageFlag = 0x00000004,
        RevocationCheckNone = 0x00000010,
        RevocationCheckEndCert = 0x00000020,
        RevocationCheckChain = 0x00000040,
        RevocationCheckChainExcludeRoot = 0x00000080,
        SaferFlag = 0x00000100,        // Used by software restriction policies. Should not be used.
        HashOnlyFlag = 0x00000200,
        UseDefaultOsverCheck = 0x00000400,
        LifetimeSigningFlag = 0x00000800,
        CacheOnlyUrlRetrieval = 0x00001000,      // affects CRL retrieval and AIA retrieval
        DisableMD2andMD4 = 0x00002000      // Win7 SP1+: Disallows use of MD2 or MD4 in the chain except for the root 
    }

    enum WinTrustDataUIContext : uint
    {
        Execute = 0,
        Install = 1
    }
    #endregion

    #region WinTrust structures
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    class WinTrustFileInfo
    {
        UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustFileInfo));
        IntPtr pszFilePath;                     // required, file name to be verified
        IntPtr hFile = IntPtr.Zero;             // optional, open handle to FilePath
        IntPtr pgKnownSubject = IntPtr.Zero;    // optional, subject type if it is known

        public WinTrustFileInfo(String _filePath)
        {
            pszFilePath = Marshal.StringToCoTaskMemAuto(_filePath);
        }
        ~WinTrustFileInfo()
        {
            Marshal.FreeCoTaskMem(pszFilePath);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    class WinTrustData
    {
        UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustData));
        IntPtr PolicyCallbackData = IntPtr.Zero;
        IntPtr SIPClientData = IntPtr.Zero;
        // required: UI choice
        WinTrustDataUIChoice UIChoice = WinTrustDataUIChoice.None;
        // required: certificate revocation check options
        WinTrustDataRevocationChecks RevocationChecks = WinTrustDataRevocationChecks.None;
        // required: which structure is being passed in?
        WinTrustDataChoice UnionChoice = WinTrustDataChoice.File;
        // individual file
        IntPtr FileInfoPtr;
        WinTrustDataStateAction StateAction = WinTrustDataStateAction.Ignore;
        IntPtr StateData = IntPtr.Zero;
        String URLReference = null;
        WinTrustDataProvFlags ProvFlags = WinTrustDataProvFlags.RevocationCheckChainExcludeRoot;
        WinTrustDataUIContext UIContext = WinTrustDataUIContext.Execute;

        // constructor for silent WinTrustDataChoice.File check
        public WinTrustData(String _fileName)
        {
            // On Win7SP1+, don't allow MD2 or MD4 signatures
            if ((Environment.OSVersion.Version.Major > 6) ||
                ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor > 1)) ||
                ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor == 1) && !String.IsNullOrEmpty(Environment.OSVersion.ServicePack)))
            {
                ProvFlags |= WinTrustDataProvFlags.DisableMD2andMD4;
            }

            WinTrustFileInfo wtfiData = new WinTrustFileInfo(_fileName);
            FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustFileInfo)));
            Marshal.StructureToPtr(wtfiData, FileInfoPtr, false);
        }
        ~WinTrustData()
        {
            Marshal.FreeCoTaskMem(FileInfoPtr);
        }
    }
    #endregion
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

    sealed class WinTrust
    {
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        // GUID of the action to perform
        private const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        static extern WinVerifyTrustResult WinVerifyTrust(
            [In] IntPtr hwnd,
            [In] [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
            [In] WinTrustData pWVTData
        );

        // call WinTrust.WinVerifyTrust() to check embedded file signature
        public static string VerifyEmbeddedSignature(string filename)
        {
            WinTrustFileInfo winTrustFileInfo = null;
            WinTrustData winTrustData = null;

            try
            {
                // specify the WinVerifyTrust function/action that we want
                Guid action = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);

                // instantiate our WinTrustFileInfo and WinTrustData data structures
                winTrustFileInfo = new WinTrustFileInfo(filename);
                winTrustData = new WinTrustData(filename);

                // call into WinVerifyTrust
                WinVerifyTrustResult result = WinVerifyTrust(INVALID_HANDLE_VALUE, action, winTrustData);
                switch (result)
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
            catch (Exception e)
            {
                Log.Debug("{0} error decoding signature on {1}", e.GetType().ToString(), filename);
            }
            return "Unknown";
        }
        private WinTrust() { }
    }
}
