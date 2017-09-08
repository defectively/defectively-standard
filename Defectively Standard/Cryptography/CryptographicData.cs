// ReSharper disable InconsistentNaming

using System.Security.Cryptography;

namespace Defectively.Standard.Cryptography
{
    /// <summary>
    ///     Contains cryptographic values used for encryption and decryption with the <see cref="CryptographyProvider"/>.
    /// </summary>
    public class CryptographicData
    {
        /// <summary>
        ///     The key used in the <see cref="Aes"/> algorithm.
        /// </summary>
        public byte[] AesKey { get; }

        /// <summary>
        ///     The initialization vector used in the <see cref="Aes"/> algorithm.
        /// </summary>
        public byte[] AesIV { get; }

        /// <summary>
        ///     The key used to create and validate <see cref="HMACSHA256"/> signatures.
        /// </summary>
        public byte[] HmacKey { get; }

        /// <summary>
        ///     Initializes a new instance of the <see cref="CryptographicData"/> class.
        /// </summary>
        /// <param name="aesKey">The key to use in the <see cref="Aes"/> algorithm.</param>
        /// <param name="aesIV">The initialization vector to use in the <see cref="Aes"/> algorithm.</param>
        /// <param name="hmacKey">The key to create and validate <see cref="HMACSHA256"/> signatures.</param>
        public CryptographicData(byte[] aesKey, byte[] aesIV, byte[] hmacKey) {
            AesKey = aesKey;
            AesIV = aesIV;
            HmacKey = hmacKey;
        }

        /// <summary>
        ///     Validates if all values of the <see cref="CryptographicData"/> are set.
        /// </summary>
        /// <returns>Returns "true" if the <see cref="CryptographicData"/> has all values set, otherwise "false".</returns>
        public bool IsValid() => AesKey != null && AesKey.Length != 0 && AesIV != null && AesIV.Length != 0 && HmacKey != null && HmacKey.Length != 0;
    }
}
