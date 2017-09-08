using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

// ReSharper disable InconsistentNaming

namespace Defectively.Standard.Cryptography
{
    /// <summary>
    ///     Provides encrypt and decrypt functionality for <see cref="Aes"/> and <see cref="RSA"/> and <see cref="HMACSHA256"/> signing.
    /// </summary>
    public sealed class CryptographyProvider
    {
        private static volatile CryptographyProvider instance;
        private static readonly object syncRoot = new object();

        /// <summary>
        ///     A thread-safe singleton instance of the <see cref="CryptographyProvider"/>.
        /// </summary>
        public static CryptographyProvider Instance {
            get {
                if (instance == null) {
                    lock (syncRoot) {
                        if (instance == null) {
                            instance = new CryptographyProvider();
                        }
                    }
                }
                return instance;
            }
        }

        private readonly Aes aes = Aes.Create();
        private readonly RSACng rsa = new RSACng();
        private HMACSHA256 hmac = new HMACSHA256();

        private CryptographyProvider() { }

        /// <summary />
        ~CryptographyProvider() {
            aes.Dispose();
            rsa.Dispose();
            hmac.Dispose();
        }

        /// <summary>
        ///     Decrypts a string using the <see cref="Aes"/> algorithm.
        /// </summary>
        /// <param name="s">The encrypted string.</param>
        /// <param name="data">The <see cref="CryptographicData"/> used to encrypt the string.</param>
        /// <returns>Returns the decrypted string.</returns>
        public async Task<string> AesDecryptAsync(string s, CryptographicData data) {
            var transform = aes.CreateDecryptor(data.AesKey, data.AesIV);
            var memoryStream = new MemoryStream(Convert.FromBase64String(s));
            var cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read);
            var reader = new StreamReader(cryptoStream);
            var decrypted = await reader.ReadToEndAsync();
            reader.Dispose();
            cryptoStream.Dispose();
            memoryStream.Dispose();
            transform.Dispose();

            return decrypted;
        }

        /// <summary>
        ///     Encrypts a string using the <see cref="Aes"/> algorithm.
        /// </summary>
        /// <param name="s">The cipher string.</param>
        /// <param name="data">The <see cref="CryptographicData"/> that should be used.</param>
        /// <returns>Returns the encrypted string.</returns>
        public async Task<string> AesEncryptAsync(string s, CryptographicData data) {
            var transform = aes.CreateEncryptor(data.AesKey, data.AesIV);
            var memoryStream = new MemoryStream();

            using (var cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write)) {
                using (var writer = new StreamWriter(cryptoStream)) {
                    await writer.WriteAsync(s);
                }
            }

            var encrypted = Convert.ToBase64String(memoryStream.ToArray());
            memoryStream.Dispose();
            transform.Dispose();

            return encrypted;
        }

        /// <summary>
        ///     Generates random <see cref="CryptographicData"/>.
        /// </summary>
        /// <returns>Returns random <see cref="CryptographicData"/>.</returns>
        public CryptographicData GetRandomData() {
            aes.GenerateKey();
            aes.GenerateIV();
            hmac = new HMACSHA256();

            return new CryptographicData(aes.Key, aes.IV, hmac.Key);
        }

        /// <summary>
        ///     Creates a signature for a string using the <see cref="HMACSHA256"/> algorithm.
        /// </summary>
        /// <param name="s">The string to sign.</param>
        /// <param name="data">The <see cref="CryptographicData"/> that should be used.</param>
        /// <returns>Returns the signature for the string.</returns>
        public string HmacCreateSignature(string s, CryptographicData data) {
            hmac = new HMACSHA256(data.HmacKey);
            return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(s)));
        }

        /// <summary>
        ///     Validates a signature for a string using the <see cref="HMACSHA256"/> algorithm.
        /// </summary>
        /// <param name="s">The string to check.</param>
        /// <param name="signature">The signature to validate.</param>
        /// <param name="data">The <see cref="CryptographicData"/> used to create the signature.</param>
        /// <returns>Returns "true" if the signature is valid, otherwise "false".</returns>
        public bool HmacValidateSignature(string s, string signature, CryptographicData data) {
            hmac = new HMACSHA256(data.HmacKey);
            return string.Equals(signature, HmacCreateSignature(s, data));
        }

        /// <summary>
        ///     Decrypts a string using the <see cref="RSA"/> algorithm.
        /// </summary>
        /// <param name="s">The encrypted string.</param>
        /// <param name="params">The <see cref="RSAParameters"/> that should be used.</param>
        /// <returns>Returns the decrypted string.</returns>
        public string RSADecrypt(string s, RSAParameters @params) {
            rsa.ImportParameters(@params);
            return Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(s), RSAEncryptionPadding.Pkcs1));
        }

        /// <summary>
        ///     Encrypts a string using the <see cref="RSA"/> algorithm.
        /// </summary>
        /// <param name="s">The cipher string.</param>
        /// <param name="params">The <see cref="RSAParameters"/> that should be used.</param>
        /// <returns>Returns the encrypted string.</returns>
        public string RSAEncrypt(string s, RSAParameters @params) {
            rsa.ImportParameters(@params);
            return Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(s), RSAEncryptionPadding.Pkcs1));
        }
    }
}
