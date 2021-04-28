using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Cli
{
    public class SandboxState
    {
        /// <summary>
        /// A Dictionary of FullName of object (with namespace)
        /// to list of that objects of that Type
        /// </summary>
        public Dictionary<string, List<object>> Objects { get; set; } = new Dictionary<string, List<object>>();

        public SandboxState()
        {
        }

        public SandboxState(Dictionary<string, List<object>> objects)
        {
            Objects = objects;
        }
    }
}
