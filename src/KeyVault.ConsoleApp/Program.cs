using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;

namespace KeyVault.ConsoleApp
{
    class Program
    {
        private const string EnvironmentVariableAzureClientId = "KeyVault_ConsoleApp_Azure_Client_Id";
        private const string EnvironmentVariableAzureClientSecret = "KeyVault_ConsoleApp_Azure_Client_Secret";
        private const string EnvironmentVariableAzureTenantId = "KeyVault_ConsoleApp_Azure_Tenant_Id";
        private const string EnvironmentVariableAzureKeyVaultName = "KeyVault_ConsoleApp_Azure_Key_Vault_Name";
        private const string AzureKeyVaultUri = "https://{0}.vault.azure.net";

        private static TokenCredential credential;
        private static VaultSetting vaultSetting;

        static void Main(string[] args)
        {
            try
            {
                vaultSetting = GetVaultSetting();
                if (vaultSetting.HasError)
                {
                    Console.WriteLine("One or more errors occurred. Check your environment variables.");
                    foreach (var error in vaultSetting.Errors)
                    {
                        Console.WriteLine($"> {error}");
                    }
                    Console.ReadKey();
                    return;
                }

                credential = new ClientSecretCredential(vaultSetting.TenantId, vaultSetting.ClientId, vaultSetting.ClientSecret);

                var continueExecution = true;
                do
                {
                    //Console.Clear();
                    WriteMenu();
                    PickMenuOption();

                    continueExecution = ContinueExecution();
                } while (continueExecution);
            }
            catch (RequestFailedException ex)
            {
                Console.WriteLine($"RequestFailedException: {ex}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Generic exception: {ex}");
            }
        }

        private static VaultSetting GetVaultSetting()
        {
            var clientId = Environment.GetEnvironmentVariable(EnvironmentVariableAzureClientId);
            var clientSecret = Environment.GetEnvironmentVariable(EnvironmentVariableAzureClientSecret);
            var tenantId = Environment.GetEnvironmentVariable(EnvironmentVariableAzureTenantId);
            var keyVaultName = Environment.GetEnvironmentVariable(EnvironmentVariableAzureKeyVaultName);

            var vaultSetting = new VaultSetting(clientId, clientSecret, tenantId, keyVaultName);

            return vaultSetting;
        }

        private static void WriteMenu()
        {
            Console.WriteLine("[0] Exit");
            Console.WriteLine("[1] Store secret");
            Console.WriteLine("[2] Get secret");
            Console.WriteLine("[3] Get secret specific version");
            Console.WriteLine("[4] Store key");
            Console.WriteLine("[5] Get key");
            Console.WriteLine("[6] Get key specific version");
        }

        private static void PickMenuOption()
        {
            Console.Write("What do you want to do? ");
            var rawMenuOption = Console.ReadLine();
            if (int.TryParse(rawMenuOption, out int menuOption))
            {
                if (menuOption == 0)
                {
                    Environment.Exit(0);
                }
                if (menuOption == 1)
                {
                    StoreSecret().GetAwaiter().GetResult();
                    return;
                }
                else if (menuOption == 2)
                {
                    GetSecret().GetAwaiter().GetResult();
                    return;
                }
                else if (menuOption == 3)
                {
                    GetSecret(true).GetAwaiter().GetResult();
                    return;
                }
                else if (menuOption == 4)
                {
                    StoreKey().GetAwaiter().GetResult();
                    return;
                }
                else if (menuOption == 5)
                {
                    GetKey().GetAwaiter().GetResult();
                    return;
                }
                else if (menuOption == 6)
                {
                    GetKey(true).GetAwaiter().GetResult();
                    return;
                }
            }

            Console.WriteLine("Invalid menu option!");
        }

        private static bool ContinueExecution()
        {
            Console.Write("Continue? [Y]es/[N]o: ");
            bool continueExecution = (Console.ReadLine().ToUpper() ?? "Y")[0] == 'Y';

            return continueExecution;
        }

        #region Secret

        private static async Task StoreSecret()
        {
            var client = new SecretClient(new Uri(string.Format(AzureKeyVaultUri, vaultSetting.KeyVaultName)), credential);
            Console.WriteLine("Storing secret...");
            Console.Write("> Name: ");
            var name = Console.ReadLine();
            Console.Write("> Value: ");
            var value = Console.ReadLine();
            var result = await client.SetSecretAsync(name, value);
            PrintResult(result);
        }

        private static async Task GetSecret(bool askVersion = false)
        {
            var client = new SecretClient(new Uri(string.Format(AzureKeyVaultUri, vaultSetting.KeyVaultName)), credential);
            Console.WriteLine("Which secret do you want to get?");
            Console.Write("> Name: ");
            var name = Console.ReadLine();
            string? version = null;
            if (askVersion)
            {
                Console.Write("> Version: ");
                version = Console.ReadLine();
            }
            var result = await client.GetSecretAsync(name, version);
            PrintResult(result);
        }

        private static void PrintResult(Response<KeyVaultSecret> response)
        {
            var rawResponse = response.GetRawResponse();
            if (rawResponse.Status < (int)HttpStatusCode.OK || rawResponse.Status >= (int)HttpStatusCode.Ambiguous)
            {
                Console.WriteLine($"An error occurred. Reason: {rawResponse.ReasonPhrase}");
                return;
            }

            var keyVaultSecret = response.Value;
            Console.WriteLine("Secret details:");
            Console.WriteLine($"> ID: {keyVaultSecret.Id}");
            Console.WriteLine($"> Name: {keyVaultSecret.Name}");
            Console.WriteLine($"> Value: {keyVaultSecret.Value}");
            Console.WriteLine($"> Version: {keyVaultSecret.Properties.Version}");
        }

        #endregion

        #region Key

        private static async Task StoreKey()
        {
            var client = new KeyClient(new Uri(string.Format(AzureKeyVaultUri, vaultSetting.KeyVaultName)), credential);
            Console.WriteLine("Storing key...");
            Console.Write("> Name: ");
            var name = Console.ReadLine();
            var keyTypesValues = new List<KeyType>()
            {
                KeyType.Ec,
                KeyType.EcHsm,
                KeyType.Rsa,
                KeyType.RsaHsm,
            };
            var keyTypes = string.Join(", ", keyTypesValues);
            Console.Write($"> Type ({keyTypes}): ");
            var rawKeyType = Console.ReadLine().ToUpper();
            while (!keyTypesValues.Contains(rawKeyType))
            {
                Console.Write("Invalid key type");
                Console.Write($"> Type ({keyTypes}): ");
                rawKeyType = Console.ReadLine();
            }
            var keyType = keyTypesValues.Single(kt => kt == rawKeyType);
            var result = await client.CreateKeyAsync(name, keyType);
            PrintResult(result);
        }

        private static async Task GetKey(bool askVersion = false)
        {
            var client = new KeyClient(new Uri(string.Format(AzureKeyVaultUri, vaultSetting.KeyVaultName)), credential);
            Console.WriteLine("Which key do you want to get?");
            Console.Write("> Name: ");
            var name = Console.ReadLine();
            string? version = null;
            if (askVersion)
            {
                Console.Write("> Version: ");
                version = Console.ReadLine();
            }
            var result = await client.GetKeyAsync(name, version);
            PrintResult(result);
        }

        private static void PrintResult(Response<KeyVaultKey> response)
        {
            var rawResponse = response.GetRawResponse();
            if (rawResponse.Status < (int)HttpStatusCode.OK || rawResponse.Status >= (int)HttpStatusCode.Ambiguous)
            {
                Console.WriteLine($"An error occurred. Reason: {rawResponse.ReasonPhrase}");
                return;
            }

            var keyVaultKey = response.Value;
            Console.WriteLine("Key details:");
            Console.WriteLine($"> ID: {keyVaultKey.Id}");
            Console.WriteLine($"> Name: {keyVaultKey.Name}");
            Console.WriteLine($"> Type: {keyVaultKey.KeyType}");
            Console.WriteLine($"> Version: {keyVaultKey.Properties.Version}");
        }

        #endregion
    }
}
