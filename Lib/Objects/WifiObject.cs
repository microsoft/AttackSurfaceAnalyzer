namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class WifiObject : CollectObject
    {
        public WifiObject(string SSID)
        {
            this.SSID = SSID;
            this.ResultType = Types.RESULT_TYPE.WIFI;
        }

        public string? Authentication { get; set; }

        public string? Encryption { get; set; }

        public override string Identity
        {
            get
            {
                return SSID;
            }
        }

        public string? Password { get; set; }
        public string SSID { get; set; }
    }
}