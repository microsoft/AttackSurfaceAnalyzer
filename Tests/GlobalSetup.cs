using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel, Workers = 0)]
[assembly: ClassCleanupExecution(ClassCleanupBehavior.EndOfClass)]

[TestClass]
public static class GlobalSetup
{
    [AssemblyInitialize]
    public static void AssemblySetup(TestContext _)
    {
        Logger.Setup(false, true);
        Strings.Setup();
    }
}