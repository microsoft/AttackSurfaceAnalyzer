using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;

namespace AttackSurfaceAnalyzer.Objects;

public class AsaResults
{
    public AsaResults(Dictionary<string, string> metadata, Dictionary<string, ConcurrentBag<CompareResult>> results)
    {
        Metadata = metadata;
        Results = results;
    }

    public AsaResults()
    {
        Metadata = new Dictionary<string, string>();
        Results = new Dictionary<string, ConcurrentBag<CompareResult>>();
    }
    
    public Dictionary<string, string> Metadata { get; set; }
    public Dictionary<string, ConcurrentBag<CompareResult>> Results { get; set; }
}