using System.Collections.Generic;
using System.Linq;
using Microsoft.CST.AttackSurfaceAnalyzer.Collectors;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests;

/// <summary>
/// Test that the compare logic generates the correct diffs for various object configurations
/// </summary>
[TestClass]
public class DiffTests
{
    [DataRow("owner1", "owner2", 1)]
    [DataRow(null, "owner2", 1)]
    [DataRow("owner1", null, 1)]
    [DataRow("owner1", "owner1", 0)]
    [DataTestMethod]
    public void TestStringDiff(string owner1, string owner2, int expectedNumFindings)
    {
        var loc1 = "Location1";
        var fileObject1 = new FileSystemObject(loc1) { Owner = owner1 };
        var fileObject2 = new FileSystemObject(loc1) { Owner = owner2 };
        var diffs = BaseCompare.GenerateDiffs(fileObject1, fileObject2);
        Assert.AreEqual(expectedNumFindings, diffs.Count);
        if (expectedNumFindings > 0)
        {
            Assert.AreEqual(fileObject1.Owner, diffs[0].Before);
            Assert.AreEqual(fileObject2.Owner, diffs[0].After);
        }
    }
    
    [DataRow(new[]{"owner1"}, new[]{"owner2"}, 1)]
    [DataRow(new[]{"owner1", "owner2"}, new[]{"owner2"}, 1)]
    [DataRow(new[]{"owner1"}, new[]{"owner1", "owner2"}, 1)]
    [DataRow(new string[]{}, new[]{"owner2"}, 1)]
    [DataRow(new[]{"owner1"}, new string[]{}, 1)]
    [DataRow(new[]{"owner1"}, new[]{"owner1"}, 0)]
    [DataTestMethod]
    public void TestListStringDiff(string[] owner1, string[] owner2, int expectedNumFindings)
    {
        var addrList1 = new List<string>();
        addrList1.AddRange(owner1);
        var addrList2 = new List<string>();
        addrList2.AddRange(owner2);
        var fileObject1 = new FirewallObject("Something") { LocalAddresses  = addrList1 };
        var fileObject2 = new FirewallObject("Something") { LocalAddresses  = addrList2 };
        var diffs = BaseCompare.GenerateDiffs(fileObject1, fileObject2);
        Assert.AreEqual(expectedNumFindings, diffs.Count);
        if (expectedNumFindings > 0)
        {
            Assert.AreEqual(fileObject1.LocalAddresses, diffs[0].Before);
            Assert.AreEqual(fileObject2.LocalAddresses, diffs[0].After);
        }
    }
    
    [DataRow("key1", "value1", "key2", "value2", 1)]
    [DataRow("key1", "value1", "key2", "value1", 1)]
    [DataRow("key1", "value1", "key1", "value2", 1)]
    [DataRow("key2", "value1", "key2", "value2", 1)]
    [DataRow("key2", "value2", "key2", "value2", 0)]
    [DataRow("key1", "value1", "key1", "value1", 0)]
    [DataRow("key1", null, "key2", "value2", 1)]
    [DataRow("key1", "value1", "key2", null, 1)]
    [DataRow(null, null, "key2", "value2", 1)]
    [DataRow("key1", "value1", null, null, 1)]
    [DataTestMethod]
    public void TestDictionaryStringString(string key1, string value1, string key2, string value2, int expectedNumFindings)
    {
        var addrList1 = new Dictionary<string, string>();
        if (key1 != null)
        {
            addrList1.Add(key1, value1);
        }
        var addrList2 = new Dictionary<string, string>();
        if (key2 != null)
        {
            addrList2.Add(key2, value2);
        }
        var fileObject1 = new FileSystemObject("Something") { Permissions = addrList1 };
        var fileObject2 = new FileSystemObject("Something") { Permissions = addrList2 };
        var diffs = BaseCompare.GenerateDiffs(fileObject1, fileObject2);
        Assert.AreEqual(expectedNumFindings, diffs.Count);
        if (expectedNumFindings > 0)
        {
            Assert.AreEqual(fileObject1.Permissions, diffs[0].Before);
            Assert.AreEqual(fileObject2.Permissions, diffs[0].After);
        }
    }
    
    [DataRow("key1", new[]{"value1"}, "key2", new[]{"value2"}, 1)]
    [DataRow("key1", new[]{"value1"}, "key2", new[]{"value1"}, 1)]
    [DataRow("key1", new[]{"value1"}, "key1", new[]{"value2"}, 1)]
    [DataRow("key2", new[]{"value1"}, "key2", new[]{"value2"}, 1)]
    [DataRow("key2", new[]{"value2"}, "key2", new[]{"value2"}, 0)]
    [DataRow("key1", new[]{"value1"}, "key1", new[]{"value1"}, 0)]
    [DataRow("key1", new[]{"value1", "value2"}, "key1", new[]{"value1"}, 1)]
    [DataRow("key1", new[]{"value1"}, "key1", new[]{"value1", "value2"}, 1)]
    [DataRow("key1", new string[]{}, "key2", new[]{"value2"}, 1)]
    [DataRow("key1", new string[]{"value1"}, "key2", new string[]{}, 1)]
    [DataRow(null, null, "key2", new []{"value2"}, 1)]
    [DataRow("key1", new []{"value1"}, null, null, 1)]
    [DataTestMethod]
    public void TestDictionaryStringListString(string key1, string[] value1, string key2, string[] value2, int expectedNumFindings)
    {
        var addrList1 = new Dictionary<string, List<string>>();
        if (key1 != null)
        {
            addrList1.Add(key1, value1.ToList());
        }
        var addrList2 = new Dictionary<string, List<string>>();
        if (key2 != null)
        {
            addrList2.Add(key2, value2.ToList());
        }
        var fileObject1 = new RegistryObject("Something", RegistryView.Default) { Permissions = addrList1 };
        var fileObject2 = new RegistryObject("Something", RegistryView.Default) { Permissions = addrList2 };
        var diffs = BaseCompare.GenerateDiffs(fileObject1, fileObject2);
        Assert.AreEqual(expectedNumFindings, diffs.Count);
        if (expectedNumFindings > 0)
        {
            Assert.AreEqual(fileObject1.Permissions, diffs[0].Before);
            Assert.AreEqual(fileObject2.Permissions, diffs[0].After);
        }
    }
}