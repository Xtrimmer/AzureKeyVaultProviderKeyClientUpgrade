using Azure.Identity;
using Microsoft.Data.AzureKeyVaultProviderKeyClientUpgrade;
using Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Threading.Tasks;
using Xunit;

namespace AzureKeyVaultProviderKeyClientUpgradeTests
{
    public class UnitTests
    {
        const string EncryptionAlgorithm = "RSA_OAEP";
        const string MasterKeyPath = "<KeyVaultIdentifierURI>";
        const string ClientId = "<AzureClientId>";
        const string ClientSecret = "<AzureClientSecret>";
        const string TenantId = "<TenantId>";
        public static readonly byte[] ColumnEncryptionKey = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };


        [Fact]
        public void BackwardCompatibilityWithAuthenticationCallbackWorks()
        {
            ColumnEncryptionAzureKeyVaultProvider akvProvider = new ColumnEncryptionAzureKeyVaultProvider(AzureActiveDirectoryAuthenticationCallback);
            byte[] encryptedCek = akvProvider.EncryptColumnEncryptionKey(MasterKeyPath, EncryptionAlgorithm, ColumnEncryptionKey);
            byte[] decryptedCek = akvProvider.DecryptColumnEncryptionKey(MasterKeyPath, EncryptionAlgorithm, encryptedCek);

            Assert.Equal(ColumnEncryptionKey, decryptedCek);
        }

        [Fact]
        public void TokenCredentialWorks()
        {
            ColumnEncryptionAzureKeyVaultProvider akvProvider = new ColumnEncryptionAzureKeyVaultProvider(new ClientSecretCredential(TenantId, ClientId, ClientSecret));
            byte[] encryptedCek = akvProvider.EncryptColumnEncryptionKey(MasterKeyPath, EncryptionAlgorithm, ColumnEncryptionKey);
            byte[] decryptedCek = akvProvider.DecryptColumnEncryptionKey(MasterKeyPath, EncryptionAlgorithm, encryptedCek);

            Assert.Equal(ColumnEncryptionKey, decryptedCek);
        }

        [Fact]
        public void IsCompatibleWithProviderUsingLegacyClient()
        {
            ColumnEncryptionAzureKeyVaultProvider newAkvProvider = new ColumnEncryptionAzureKeyVaultProvider(new ClientSecretCredential(TenantId, ClientId, ClientSecret));
            SqlColumnEncryptionAzureKeyVaultProvider oldAkvProvider = new SqlColumnEncryptionAzureKeyVaultProvider(AzureActiveDirectoryAuthenticationCallback);

            byte[] encryptedCekWithNewProvider = newAkvProvider.EncryptColumnEncryptionKey(MasterKeyPath, EncryptionAlgorithm, ColumnEncryptionKey);
            byte[] decryptedCekWithOldProvider = oldAkvProvider.DecryptColumnEncryptionKey(MasterKeyPath, EncryptionAlgorithm, encryptedCekWithNewProvider);
            Assert.Equal(ColumnEncryptionKey, decryptedCekWithOldProvider);

            byte[] encryptedCekWithOldProvider = oldAkvProvider.EncryptColumnEncryptionKey(MasterKeyPath, EncryptionAlgorithm, ColumnEncryptionKey);
            byte[] decryptedCekWithNewProvider = newAkvProvider.DecryptColumnEncryptionKey(MasterKeyPath, EncryptionAlgorithm, encryptedCekWithOldProvider);
            Assert.Equal(ColumnEncryptionKey, decryptedCekWithNewProvider);
        }

        public static async Task<string> AzureActiveDirectoryAuthenticationCallback(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(ClientId, ClientSecret);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);
            if (result == null)
            {
                throw new InvalidOperationException($"Failed to retrieve an access token for {resource}");
            }

            return result.AccessToken;
        }

    }
}
