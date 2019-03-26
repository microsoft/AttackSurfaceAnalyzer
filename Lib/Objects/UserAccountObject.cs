using System.Collections.Generic;
using System.Linq;
using System.Text;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.ObjectTypes
{ 
    public class UserAccountObject
    {
        public string AccountType;
        public string Caption;
        public string Description;
        public string Disabled;
        public string Domain;
        public string FullName;
        public string InstallDate;
        public string LocalAccount;
        public string Lockout;
        public string Name;
        public string PasswordChangeable;
        public string PasswordExpires;
        public string PasswordRequired;
        public string SID;
        public string UID;
        public string GID;
        public string Inactive;
        public string HomeDirectory;
        public string Shell;
        public string PasswordStorageAlgorithm;

        public Dictionary<string, string> Properties;

        public string RowKey
        {
            get
            {
                return CryptoHelpers.CreateHash(this.ToString());
            }
        }

        public string PropertiesString()
        {
            if (this.Properties == null)
            {
                return "";
            }

            var sb = new StringBuilder();
            foreach (var prop in Properties.Keys)
            {
                sb.AppendFormat("{0}={1}&", prop, Properties[prop]?.ToString());
            }
            return sb.ToString();
        }

        public override string ToString()
        {
            var self = this;
            var fields = this.GetType().GetFields().Select(field => field).ToList();

            var sb = new StringBuilder();
            foreach (var field in fields)
            {
                // @HACK There has to be a better way of doing this comparison
                if (field.FieldType == "".GetType())
                {
                    sb.AppendFormat("{0}={1}&", field.Name, field.GetValue(self));
                }
            }

            sb.Append(PropertiesString());
            return sb.ToString();
        }
        public string ToJson()
        {
            var _account_type = JsonConvert.ToString(AccountType);
            var _caption = JsonConvert.ToString(Caption);
            var _description = JsonConvert.ToString(Description);
            var _disabled = JsonConvert.ToString(Disabled);
            var _domain = JsonConvert.ToString(Domain);
            var _full_name = JsonConvert.ToString(FullName);
            var _install_date = JsonConvert.ToString(InstallDate);
            var _local_account = JsonConvert.ToString(LocalAccount);
            var _lockout = JsonConvert.ToString(Lockout);
            var _name = JsonConvert.ToString(Name);
            var _password_changeable = JsonConvert.ToString(PasswordChangeable);
            var _password_expires = JsonConvert.ToString(PasswordExpires);

            var sb = new StringBuilder();
            sb.Append("{");
            sb.AppendFormat("\"account_type\":{0},", _account_type);
            sb.AppendFormat("\"caption\":{0},", _caption);
            sb.AppendFormat("\"description\":{0},", _description);
            sb.AppendFormat("\"disabled\":{0},", _disabled);
            sb.AppendFormat("\"domain\":{0},", _domain);
            sb.AppendFormat("\"full_name\":{0},", _full_name);
            sb.AppendFormat("\"install_date\":{0},", _install_date);
            sb.AppendFormat("\"local_account\":{0},", _local_account);
            sb.AppendFormat("\"lockout\":{0},", _lockout);
            sb.AppendFormat("\"name\":{0},", _name);
            sb.AppendFormat("\"password_changeable\":{0},", _password_changeable);
            sb.AppendFormat("\"password_expires\":{0}", _password_expires);
            sb.AppendLine("}");
            return sb.ToString();
        }
    }
}