using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract]
    public class WifiObject : CollectObject
    {
        public WifiObject(string SSID)
        {
            this.SSID = SSID;
        }

        public override RESULT_TYPE ResultType => RESULT_TYPE.WIFI;

        [ProtoMember(1)]
        public string? Authentication { get; set; }

        [ProtoMember(2)]
        public string? Encryption { get; set; }

        public override string Identity
        {
            get
            {
                return SSID;
            }
        }

        [ProtoMember(3)]
        public string? Password { get; set; }
        [ProtoMember(4)]
        public string SSID { get; set; }
    }
}