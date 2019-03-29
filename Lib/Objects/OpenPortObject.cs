// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Text;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.ObjectTypes
{
    public class OpenPortObject : IComparable
    {
        public string address;
        public string family;
        public string type;
        public string port;
        public string processName;

        public string RowKey { get
            {
                return CryptoHelpers.CreateHash(this.ToString());
            }
        }

        public int CompareTo(object obj)
        {
            if (obj == null) { return 1; }
            if (this == obj) { return 0; }

            OpenPortObject other = (OpenPortObject)obj;
            int? result = this.address?.CompareTo(other.address);

            if (result == 0 || !result.HasValue)
            {
                result = this.family?.CompareTo(other.family);
            }
            if (result == 0 || !result.HasValue)
            {
                result = this.type?.CompareTo(other.type);
            }
            if (result == 0 || !result.HasValue)
            {
                result = this.port?.CompareTo(other.port);
            }
            if (result == 0 || !result.HasValue)
            {
                result = this.processName?.CompareTo(other.processName);
            }

            if (result.HasValue)
            {
                if (this.port == "135" && other.port == "135")
                {
                    Logger.Instance.Info("Comparing {0} to {1}, result={2}", this.ToString(), obj.ToString(), result);
                }
                return result.Value;
            }
            else
            {
                return 1;
            }
        }
        public override bool Equals(object obj)
        {
            return this.CompareTo(obj) == 0;
        }

        public override int GetHashCode()
        {
            int? code = 0;
            code += (17 * this.address?.GetHashCode());
            code += (23 * this.family?.GetHashCode());
            code += (29 * this.type?.GetHashCode());
            code += (37 * this.port?.GetHashCode());
            code += (41 * this.processName?.GetHashCode());
            if (code.HasValue)
            {
                return code.Value;
            }
            else
            {
                return 0;
            }
        }
        public override string ToString()
        {
            return string.Format("Family={0}, Address={1}, Type={2}, Port={3}, ProcessName={4}", family, address, type, port, processName);
        }

        public string ToJson()
        {
            var _address = JsonConvert.ToString(address);
            var _family = JsonConvert.ToString(family);
            var _type = JsonConvert.ToString(type);
            var _port = JsonConvert.ToString(port);
            var _processName = JsonConvert.ToString(processName);

            var sb = new StringBuilder();
            sb.Append("{");
            sb.AppendFormat("\"_address\":{0},", _address);
            sb.AppendFormat("\"_family\":{0},", _family);
            sb.AppendFormat("\"_type\":{0},", _type);
            sb.AppendFormat("\"_port\":{0},", _port);
            sb.AppendFormat("\"_processName\":{0}", _processName);
            sb.AppendLine("}");
            return sb.ToString();
        }
    }
}