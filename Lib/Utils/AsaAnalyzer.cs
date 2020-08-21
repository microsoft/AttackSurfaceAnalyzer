using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.OAT;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Tpm2Lib;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public class AsaAnalyzer : Analyzer
    {
        public AsaAnalyzer(AnalyzerOptions? opts = null) : base(opts)
        {
            CustomPropertyExtractionDelegates.Add(ParseCustomAsaProperties);
            CustomObjectToValuesDelegates.Add(ParseCustomAsaObjectValues);
        }

        public static (bool Processed, IEnumerable<string> valsExtracted, IEnumerable<KeyValuePair<string, string>> dictExtracted) ParseCustomAsaObjectValues(object? obj)
        {
            if (obj is Dictionary<(TpmAlgId, uint), byte[]> algDict)
            {
                return (true, Array.Empty<string>(), algDict.ToList().Select(x => new KeyValuePair<string, string>(x.Key.ToString(), Convert.ToBase64String(x.Value))).ToList());
            }
            return (false, Array.Empty<string>(), Array.Empty<KeyValuePair<string, string>>());
        }

        public static (bool, object?) ParseCustomAsaProperties(object? obj, string index)
        {
            switch (obj)
            {
                case Dictionary<(TpmAlgId, uint), byte[]> algDict:
                    var elements = Convert.ToString(index, CultureInfo.InvariantCulture)?.Trim('(').Trim(')').Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    if (Enum.TryParse(typeof(TpmAlgId), elements.First(), out object? result) &&
                        result is TpmAlgId Algorithm && uint.TryParse(elements.Last(), out uint Index) &&
                        algDict.TryGetValue((Algorithm, Index), out byte[]? byteArray))
                    {
                        return (true, byteArray);
                    }
                    else
                    {
                        return (true, null);
                    }
            }
            return (false, null);
        }

        public IEnumerable<Rule> Analyze(IEnumerable<Rule> rules, CompareResult compareResult)
        {
            if (compareResult == null)
            {
                return Array.Empty<Rule>();
            }

            return Analyze(rules, compareResult.Base, compareResult.Compare);
        }
    }
}