// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Text;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.ObjectTypes
{
    public class ServiceObject
    {
        public string ServiceName { get; set; }
        public string StartType { get; set; }
        public string DisplayName { get; set; }
        public string CurrentState { get; set; }

        public string GetUniqueHash()
        {
            return CryptoHelpers.CreateHash(this.ToString());
        }

        public override string ToString()
        {
            return string.Format("ServiceType={0}, StartType={1}, DisplayName={2}, CurrentState={3}", ServiceName, StartType, DisplayName, CurrentState);
        }

        public string ToJson()
        {
            var _service_name = JsonConvert.ToString(ServiceName);
            var _start_type = JsonConvert.ToString(StartType);
            var _display_name = JsonConvert.ToString(DisplayName);
            var _current_state = JsonConvert.ToString(CurrentState);

            var sb = new StringBuilder();
            sb.Append("{");
            sb.AppendFormat("\"service_name\":{0},", _service_name);
            sb.AppendFormat("\"start_type\":{0},", _start_type);
            sb.AppendFormat("\"display_name\":{0},", _display_name);
            sb.AppendFormat("\"current_state\":{0}", _current_state);
            sb.AppendLine("}");
            return sb.ToString();
        }
    }
}