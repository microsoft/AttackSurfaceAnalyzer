// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Runtime.Loader;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    /// <summary>
    ///     Tests for <see cref="MonoPosixAssemblyResolver" />, which provides the fallback used to
    ///     load Mono.Posix.NETStandard on RIDs (such as win-arm64) for which the package ships no
    ///     runtime asset.
    /// </summary>
    [TestClass]
    public class MonoPosixAssemblyResolverTests
    {
        [TestMethod]
        public void FindAssemblyPathReturnsNullForUnrelatedAssembly()
        {
            var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName())).FullName;
            try
            {
                Assert.IsNull(MonoPosixAssemblyResolver.FindAssemblyPath(dir, "System.Text.Json"));
            }
            finally
            {
                Directory.Delete(dir, true);
            }
        }

        [TestMethod]
        public void FindAssemblyPathReturnsNullWhenNoRuntimeAssetShipped()
        {
            var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName())).FullName;
            try
            {
                Assert.IsNull(MonoPosixAssemblyResolver.FindAssemblyPath(dir, MonoPosixAssemblyResolver.MonoPosixAssemblyName));
            }
            finally
            {
                Directory.Delete(dir, true);
            }
        }

        [TestMethod]
        public void FindAssemblyPathLocatesShippedRuntimeAsset()
        {
            var baseDir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName())).FullName;
            try
            {
                // Simulate the shipped layout for an RID other than the (missing) win-arm64.
                var ridDir = Path.Combine(baseDir, "runtimes", "win-x64", "lib", "netstandard2.0");
                Directory.CreateDirectory(ridDir);
                var expected = Path.Combine(ridDir, $"{MonoPosixAssemblyResolver.MonoPosixAssemblyName}.dll");
                File.WriteAllText(expected, string.Empty);

                var found = MonoPosixAssemblyResolver.FindAssemblyPath(baseDir, MonoPosixAssemblyResolver.MonoPosixAssemblyName);

                Assert.AreEqual(expected, found);
            }
            finally
            {
                Directory.Delete(baseDir, true);
            }
        }

        [TestMethod]
        public void ResolverIsRegisteredAndMonoPosixLoads()
        {
            // The module initializer should have registered the resolver, and Mono.Posix.NETStandard
            // should be loadable (either via the default host on supported RIDs or via the fallback).
            var assembly = AssemblyLoadContext.Default.LoadFromAssemblyName(
                new System.Reflection.AssemblyName(MonoPosixAssemblyResolver.MonoPosixAssemblyName));

            Assert.IsNotNull(assembly);
            Assert.IsNotNull(assembly.GetType("Mono.Unix.UnixFileInfo"));
        }
    }
}
