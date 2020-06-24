using System;
using System.Collections;
using System.Linq;

namespace Microsoft.Data.AzureKeyVaultProviderKeyClientUpgrade
{
    internal static class ArgumantValidator
    {
        internal static void ValidateNotNull(Object parameter, string name)
        {
            if (null == parameter)
            {
                throw new ArgumentNullException(name);
            }
        }

        internal static void ValidateNotNullOrWhitespace(string parameter, string name)
        {
            if (string.IsNullOrWhiteSpace(parameter))
            {
                throw new ArgumentException($"{name} cannot be null or empty or consist of only whitespace.");
            }
        }

        internal static void ValidateNotEmpty(IList parameter, string name)
        {
            if (parameter.Count == 0)
            {
                throw new ArgumentException($"{name} cannot be empty.");
            }
        }

        internal static void ValidateNotNullForEach(Array parameters, string name)
        {
            for (int i = 0; i < parameters.Length; i++)
            {
                if (null == parameters.GetValue(i))
                {
                    throw new ArgumentException($"One of more of the elements in {name} is null or empty.");
                }
            }
        }

        internal static void ValidateNotNullOrWhitespaceForEach(string[] parameters, string name)
        {
            for (int i = 0; i < parameters.Length; i++)
            {
                if (null == parameters.GetValue(i))
                {
                    throw new ArgumentException($"One of more of the elements in {name} is null or empty or consist of only whitespace.");
                }
            }
        }

        internal static void ValidateMasterKeyPathFormat(string masterKeyPath)
        {
            bool isParsedSuccessfully = Uri.TryCreate(masterKeyPath, UriKind.Absolute, out Uri parsedUri);
            bool isValidFormat = isParsedSuccessfully && parsedUri.Segments.Length > 2;

            if (!isValidFormat)
            {
                throw new FormatException($"The {nameof(masterKeyPath)} is of an invalid format.");
            }
        }

        internal static void ValidateMasterKeyIsTrusted(string masterKeyPath, string[] trustedEndpoints)
        {
            bool isParsedSuccessfully = Uri.TryCreate(masterKeyPath, UriKind.Absolute, out Uri parsedUri);
            bool isTrustedEndpoint = isParsedSuccessfully && trustedEndpoints.Any(e => parsedUri.Host.EndsWith(e, StringComparison.OrdinalIgnoreCase));

            if (!isTrustedEndpoint)
            {
                throw new ArgumentException($"The {nameof(masterKeyPath)} was not found in the accepted trusted endpoints. {trustedEndpoints}");
            }
        }

        internal static void ValidateEncryptionAlgorithmIsRsaOaep(string encryptionAlgorithm)
        {
            if (!encryptionAlgorithm.Equals("RSA_OAEP", StringComparison.OrdinalIgnoreCase)
                && !encryptionAlgorithm.Equals("RSA-OAEP", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Encryption algorithm must be one of [RSA_OAEP, RSA-OAEP]");
            }
        }
    }
}

