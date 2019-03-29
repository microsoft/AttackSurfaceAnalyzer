// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Utils
{
    public class SqliteHelper
    {
        public static string Escape(string s)
        {
            if (s == null)
            {
                return null;
            }
            return s.Replace("'", "''");
        }
    }
}