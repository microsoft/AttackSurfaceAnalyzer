using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Utils
{
    public class AsaAnalyzer : Analyzer
    {
        public static (bool,object?) ParseCustomAsaProperties(object? obj, string index)
        {
            switch (obj)
            {
                case Dictionary<(TpmAlgId, uint), byte[]> algDict:
                    var elements = Convert.ToString(index, CultureInfo.InvariantCulture)?.Trim('(').Trim(')').Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    if (Enum.TryParse(typeof(TpmAlgId), elements.First(), out object? result) &&
                        result is TpmAlgId Algorithm && uint.TryParse(elements.Last(), out uint Index) &&
                        algDict.TryGetValue((Algorithm, Index), out byte[]? byteArray))
                    {
                        return (true,byteArray);
                    }
                    else
                    {
                        return (true,null);
                    }
            }
            return (false,null);
        }
        public AsaAnalyzer() : base(ParseCustomAsaProperties)
        {

        }
        //// TODO:
        //                // This should be provided by the caller as a custom parser
        //                

    }
}
