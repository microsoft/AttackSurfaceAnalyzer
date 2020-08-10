using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.OAT;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class AsaRule : Rule
    {
        public AsaRule(string Name) : base(Name)
        {
        }

        public List<CHANGE_TYPE> ChangeTypes { get; set; } = new List<CHANGE_TYPE>() { CHANGE_TYPE.CREATED, CHANGE_TYPE.DELETED, CHANGE_TYPE.MODIFIED };

        public ANALYSIS_RESULT_TYPE Flag
        {
            get
            {
                return _flag;
            }
            set
            {
                _flag = value;
                Severity = (int)value;
            }
        }

        public List<PLATFORM> Platforms { get; set; } = new List<PLATFORM>() { PLATFORM.LINUX, PLATFORM.MACOS, PLATFORM.WINDOWS };

        public RESULT_TYPE ResultType
        {
            get
            {
                return _resultType;
            }
            set
            {
                _resultType = value;
                Target = ResultTypeToTargetName(value);
            }
        }

        private ANALYSIS_RESULT_TYPE _flag;

        private RESULT_TYPE _resultType;

        private static string? ResultTypeToTargetName(RESULT_TYPE value)
        {
            switch (value)
            {
                case RESULT_TYPE.CERTIFICATE:
                    return typeof(CertificateObject).Name;

                case RESULT_TYPE.COM:
                    return typeof(ComObject).Name;

                case RESULT_TYPE.DRIVER:
                    return typeof(DriverObject).Name;

                case RESULT_TYPE.FILE:
                    return typeof(FileSystemObject).Name;

                case RESULT_TYPE.FILEMONITOR:
                    return typeof(FileMonitorObject).Name;

                case RESULT_TYPE.FIREWALL:
                    return typeof(FirewallObject).Name;

                case RESULT_TYPE.GROUP:
                    return typeof(GroupAccountObject).Name;

                case RESULT_TYPE.KEY:
                    return typeof(CryptographicKeyObject).Name;

                case RESULT_TYPE.LOG:
                    return typeof(EventLogObject).Name;

                case RESULT_TYPE.PORT:
                    return typeof(OpenPortObject).Name;

                case RESULT_TYPE.PROCESS:
                    return typeof(ProcessObject).Name;

                case RESULT_TYPE.REGISTRY:
                    return typeof(RegistryObject).Name;

                case RESULT_TYPE.SERVICE:
                    return typeof(ServiceObject).Name;

                case RESULT_TYPE.TPM:
                    return typeof(TpmObject).Name;

                case RESULT_TYPE.USER:
                    return typeof(UserAccountObject).Name;

                case RESULT_TYPE.WIFI:
                    return typeof(WifiObject).Name;

                default:
                    return null;
            }
        }
    }
}