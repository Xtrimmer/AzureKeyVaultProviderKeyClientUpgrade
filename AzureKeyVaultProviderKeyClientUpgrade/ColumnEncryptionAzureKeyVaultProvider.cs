using Azure.Core;
using Azure.Security.KeyVault.Keys.Cryptography;
using System;
using System.Linq;
using System.Text;

using static Microsoft.Data.AzureKeyVaultProviderKeyClientUpgrade.ArgumantValidator;
using static Microsoft.Data.AzureKeyVaultProviderKeyClientUpgrade.AzureKeyVaultProviderTokenCredential;

namespace Microsoft.Data.AzureKeyVaultProviderKeyClientUpgrade
{
    public class ColumnEncryptionAzureKeyVaultProvider
    {
        #region Properties

        /// <summary>
        /// Always Protected Param names for exec handling
        /// </summary>
        internal const string columnEncryptionKey = "columnEncryptionKey";
        internal const string encryptionAlgorithm = "encryptionAlgorithm";
        internal const string encryptedColumnEncryptionKey = "encryptedColumnEncryptionKey";

        /// <summary>
        /// Algorithm version
        /// </summary>
        private readonly byte version = 1;

        /// <summary>
        /// Column Encryption Key Store Provider string
        /// </summary>
        public const string ProviderName = "AZURE_KEY_VAULT";

        /// <summary>
        /// Key storage and cryptography client
        /// </summary>
        private KeyCryptographer KeyCryptographer { get; set; }

        /// <summary>
        /// List of Trusted Endpoints
        /// </summary>
        private readonly string[] TrustedEndPoints;

        /// <summary>
        /// Azure Key Vault Domain Name
        /// </summary>
        internal static readonly string[] AzureKeyVaultPublicDomainNames = new[] {
            @"vault.azure.net", // Public Cloud
            @"vault.azure.cn", // Azure China
            @"vault.usgovcloudapi.net", // US Government
            @"vault.microsoftazure.de" // Azure Germany
        };

        #endregion

        #region Constructors

        public ColumnEncryptionAzureKeyVaultProvider(TokenCredential tokenCredential) :
            this(tokenCredential, AzureKeyVaultPublicDomainNames)
        { }

        public ColumnEncryptionAzureKeyVaultProvider(AuthenticationCallback authenticationCallback) :
            this(authenticationCallback, AzureKeyVaultPublicDomainNames)
        { }

        public ColumnEncryptionAzureKeyVaultProvider(TokenCredential tokenCredential, string trustedEndPoint) :
            this(tokenCredential, new[] { trustedEndPoint })
        { }

        public ColumnEncryptionAzureKeyVaultProvider(AuthenticationCallback authenticationCallback, string trustedEndPoint) :
            this(authenticationCallback, new[] { trustedEndPoint })
        { }

        public ColumnEncryptionAzureKeyVaultProvider(TokenCredential tokenCredential, string[] trustedEndPoints)
        {
            ValidateNotNull(tokenCredential, nameof(tokenCredential));
            ValidateNotNull(trustedEndPoints, nameof(trustedEndPoints));
            ValidateNotEmpty(trustedEndPoints, nameof(trustedEndPoints));
            ValidateNotNullOrWhitespaceForEach(trustedEndPoints, nameof(trustedEndPoints));

            KeyCryptographer = new KeyCryptographer(tokenCredential);
            TrustedEndPoints = trustedEndPoints;
        }

        public ColumnEncryptionAzureKeyVaultProvider(AuthenticationCallback authenticationCallback, string[] trustedEndPoints)
        {
            ValidateNotNull(authenticationCallback, nameof(authenticationCallback));
            ValidateNotNull(trustedEndPoints, nameof(trustedEndPoints));
            ValidateNotEmpty(trustedEndPoints, nameof(trustedEndPoints));
            ValidateNotNullOrWhitespaceForEach(trustedEndPoints, nameof(trustedEndPoints));

            KeyCryptographer = new KeyCryptographer(authenticationCallback);
            TrustedEndPoints = trustedEndPoints;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Uses an asymmetric key identified by the key path to sign the masterkey metadata consisting of (masterKeyPath, allowEnclaveComputations bit, providerName).
        /// </summary>
        /// <param name="masterKeyPath">Complete path of an asymmetric key. Path format is specific to a key store provider.</param>
        /// <param name="allowEnclaveComputations">Boolean indicating whether this key can be sent to trusted enclave</param>
        /// <returns>Encrypted column encryption key</returns>
        public byte[] SignColumnMasterKeyMetadata(string masterKeyPath, bool allowEnclaveComputations)
        {
            ValidateNotNullOrWhitespace(masterKeyPath, nameof(masterKeyPath));
            ValidateMasterKeyPathFormat(masterKeyPath);
            ValidateMasterKeyIsTrusted(masterKeyPath, TrustedEndPoints);

            KeyCryptographer.AddKey(masterKeyPath);
            byte[] message = CompileMasterKeyMetadata(masterKeyPath, allowEnclaveComputations);
            return KeyCryptographer.SignData(message, masterKeyPath);
        }

        /// <summary>
        /// Uses an asymmetric key identified by the key path to verify the masterkey metadata consisting of (masterKeyPath, allowEnclaveComputations bit, providerName).
        /// </summary>
        /// <param name="masterKeyPath">Complete path of an asymmetric key. Path format is specific to a key store provider.</param>
        /// <param name="allowEnclaveComputations">Boolean indicating whether this key can be sent to trusted enclave</param>
        /// <param name="signature">Signature for the master key metadata</param>
        /// <returns>Boolean indicating whether the master key metadata can be verified based on the provided signature</returns>
        public bool VerifyColumnMasterKeyMetadata(string masterKeyPath, bool allowEnclaveComputations, byte[] signature)
        {
            ValidateNotNullOrWhitespace(masterKeyPath, nameof(masterKeyPath));
            ValidateMasterKeyPathFormat(masterKeyPath);
            ValidateMasterKeyIsTrusted(masterKeyPath, TrustedEndPoints);

            KeyCryptographer.AddKey(masterKeyPath);
            byte[] message = CompileMasterKeyMetadata(masterKeyPath, allowEnclaveComputations);
            return KeyCryptographer.VerifyData(message, signature, masterKeyPath);
        }

        /// <summary>
        /// This function uses the asymmetric key specified by the key path
        /// and decrypts an encrypted CEK with RSA encryption algorithm.
        /// Key format is (version + keyPathLength + ciphertextLength + keyPath + ciphertext +  signature)
        /// </summary>
        /// <param name="masterKeyPath">Complete path of an asymmetric key in AKV</param>
        /// <param name="encryptionAlgorithm">Asymmetric Key Encryption Algorithm</param>
        /// <param name="encryptedColumnEncryptionKey">Encrypted Column Encryption Key</param>
        /// <returns>Plain text column encryption key</returns>
        public byte[] DecryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] encryptedColumnEncryptionKey)
        {
            ValidateNotNullOrWhitespace(masterKeyPath, nameof(masterKeyPath));
            ValidateMasterKeyPathFormat(masterKeyPath);
            ValidateMasterKeyIsTrusted(masterKeyPath, TrustedEndPoints);
            ValidateNotNullOrWhitespace(encryptionAlgorithm, nameof(encryptionAlgorithm));
            ValidateEncryptionAlgorithmIsRsaOaep(encryptionAlgorithm);
            ValidateNotNull(encryptedColumnEncryptionKey, nameof(encryptedColumnEncryptionKey));
            ValidateNotEmpty(encryptedColumnEncryptionKey, nameof(encryptedColumnEncryptionKey));

            KeyCryptographer.AddKey(masterKeyPath);
            KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.RsaOaep;
            EncryptedColumnEncryptionKey encryptionKey = new EncryptedColumnEncryptionKey(encryptedColumnEncryptionKey);
            ValidateSignature(masterKeyPath, encryptionKey);

            return KeyCryptographer.UnwrapKey(keyWrapAlgorithm, encryptionKey.Ciphertext, masterKeyPath);
        }

        /// <summary>
        /// This function uses the asymmetric key specified by the key path
        /// and encrypts CEK with RSA encryption algorithm.
        /// Key format is (version + keyPathLength + ciphertextLength + ciphertext + keyPath + signature)
        /// </summary>
        /// <param name="masterKeyPath">Complete path of an asymmetric key in AKV</param>
        /// <param name="encryptionAlgorithm">Asymmetric Key Encryption Algorithm</param>
        /// <param name="columnEncryptionKey">Plain text column encryption key</param>
        /// <returns>Encrypted column encryption key</returns>
        public byte[] EncryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] columnEncryptionKey)
        {
            ValidateNotNullOrWhitespace(masterKeyPath, nameof(masterKeyPath));
            ValidateMasterKeyPathFormat(masterKeyPath);
            ValidateMasterKeyIsTrusted(masterKeyPath, TrustedEndPoints);
            ValidateNotNullOrWhitespace(encryptionAlgorithm, nameof(encryptionAlgorithm));
            ValidateEncryptionAlgorithmIsRsaOaep(encryptionAlgorithm);
            ValidateNotNull(columnEncryptionKey, nameof(columnEncryptionKey));
            ValidateNotEmpty(columnEncryptionKey, nameof(columnEncryptionKey));

            KeyCryptographer.AddKey(masterKeyPath);
            KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.RsaOaep;

            byte[] versionByte = new byte[] { version };
            byte[] masterKeyPathBytes = Encoding.Unicode.GetBytes(masterKeyPath.ToLowerInvariant());
            byte[] keyPathLength = BitConverter.GetBytes((short)masterKeyPathBytes.Length);
            byte[] cipherText = KeyCryptographer.WrapKey(keyWrapAlgorithm, columnEncryptionKey, masterKeyPath);
            byte[] cipherTextLength = BitConverter.GetBytes((short)cipherText.Length);
            byte[] message = versionByte.Concat(keyPathLength).Concat(cipherTextLength).Concat(masterKeyPathBytes).Concat(cipherText).ToArray();
            byte[] signature = KeyCryptographer.SignData(message, masterKeyPath);

            return message.Concat(signature).ToArray();
        }

        #endregion

        #region Private methods

        private void ValidateSignature(string masterKeyPath, EncryptedColumnEncryptionKey key)
        {
            if (!KeyCryptographer.VerifyData(key.Message, key.Signature, masterKeyPath))
            {
                throw new ArgumentException("Invalid signature");
            }
        }

        private byte[] CompileMasterKeyMetadata(string masterKeyPath, bool allowEnclaveComputations)
        {
            string masterkeyMetadata = ProviderName + masterKeyPath + allowEnclaveComputations;
            return Encoding.Unicode.GetBytes(masterkeyMetadata.ToLowerInvariant());
        }

        #endregion
    }
}
