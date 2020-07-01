using System.Collections.Generic;
using System.Linq;

namespace KeyVault.ConsoleApp
{
    public class VaultSetting
    {
        public VaultSetting(string clientId, string clientSecret, string tenantId, string keyVaultName)
        {
            if (!IsValid(clientId, clientSecret, tenantId, keyVaultName))
            {
                return;
            }

            ClientId = clientId;
            ClientSecret = clientSecret;
            TenantId = tenantId;
            KeyVaultName = keyVaultName;
        }

        public bool HasError
        {
            get
            {
                return Errors.Any();
            }
        }
        public IEnumerable<string> Errors { get; private set; }
        public string ClientId { get; }
        public string ClientSecret { get; }
        public string TenantId { get; }
        public string KeyVaultName { get; }

        private bool IsValid(string clientId, string clientSecret, string tenantId, string keyVaultName)
        {
            var errors = new List<string>();

            if (string.IsNullOrEmpty(clientId))
            {
                errors.Add("Client ID not found.");
            }
            if (string.IsNullOrEmpty(clientSecret))
            {
                errors.Add("Client Secret not found.");
            }
            if (string.IsNullOrEmpty(tenantId))
            {
                errors.Add("Tenant ID not found.");
            }
            if (string.IsNullOrEmpty(keyVaultName))
            {
                errors.Add("Key Vault Name not found.");
            }

            Errors = errors;
            return !HasError;
        }
    }
}
