namespace AttackSurfaceAnalyzer.Utils
{
    class DataWriter
    {
        public static void Write(object o)
        {
            Logger.Instance.Error("Received Object {0}", o);
        }
    }
}