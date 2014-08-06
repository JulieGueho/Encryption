using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using Microsoft.WindowsAzure;

namespace Encryption.Security
{
    /// <summary>
    /// Manages symmetric keys stored in table storage and referenced by encryption certificate thumbprint
    /// </summary>
    public class SymmetricKeyService : IDisposable
    {
        private int _maxKeyNumber = 10000;
        private X509Certificate2 _certificate = null;
        private SymmetricKeyContext _context = null;
        private RSACryptoServiceProvider _RSA = null;

        public SymmetricKeyService(string baseAddress, StorageCredentials credentials, X509Certificate2 certificate)
        {
            _certificate = certificate;

            try
            {
                if (credentials != null)
                {
                    _context = new SymmetricKeyContext(baseAddress, credentials);
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public SymmetricKey LoadSymmetricKey(int? version)
        {
            if (version.HasValue)
            {
                var symmetricKey = (from n in _context.SymmetricKeys
                                       where n.PartitionKey == "P" + _certificate.Thumbprint && n.Version == version.Value
                                       select n).FirstOrDefault();

                symmetricKey.Key = DecryptSymmetricKey_RSA(symmetricKey, _certificate);
                return symmetricKey;
            }
            else
            {
                return CreateNewAESSymmetricKeyset();
            }           
        }

        public void Dispose()
        {
            _RSA.Dispose();
        }

        private SymmetricKey CreateNewAESSymmetricKeyset()
        {
            return CreateNewAESSymmetricKeyset(32, 16);
        }

        private SymmetricKey CreateNewAESSymmetricKeyset(int KeyLength, int ivLength)
        {
            if (_certificate == null)
            {
                throw new InvalidOperationException("Unable to create new AES keyset; Certificate not loaded.");
            }

            // 32 bytes (32 bytes * 8 bits in a byte == 256 bits)
            byte[] symmKey = CreateCryptograhicKey(KeyLength);

            // IV: 16 bytes (16 bytes * 8 bits in a byte == 128 bits) == 128 bit block size.
            byte[] iv = CreateCryptograhicKey(ivLength);

            SymmetricKey symmKeySet = new SymmetricKey() { Iv = iv, Key = symmKey };
            symmKeySet.CertificateHash = _certificate.Thumbprint;
            symmKeySet.Version = 0;

            // Encrypt the Symmetric Key for storage
            symmKeySet.Key = EncryptSymmetricKey_RSA(symmKeySet, _certificate);

            // Determine the value of the most recent row
            var query = (from n in _context.SymmetricKeys
                         where n.PartitionKey == "P" + _certificate.Thumbprint
                         select n
                         ).FirstOrDefault();

            // Save to AzureTable
            symmKeySet.Version = query == null ? 0 : query.Version + 1;
            symmKeySet.PartitionKey = "P" + _certificate.Thumbprint;
            symmKeySet.RowKey = string.Format("{0:D19}", DateTime.MaxValue.Ticks - DateTime.UtcNow.Ticks);
            _context.SaveSymmetricKey(symmKeySet);

            // Cleanup
            // Return unencrypted value for key
            symmKeySet.Key = DecryptSymmetricKey_RSA(symmKeySet, _certificate);

            return symmKeySet;
        }

        private byte[] CreateCryptograhicKey(int length)
        {
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[length];

                crypto.GetBytes(key);

                return key;
            }
        }

        private byte[] DecryptSymmetricKey_RSA(SymmetricKey encryptedValue, X509Certificate2 cert)
        {
            _RSA = (RSACryptoServiceProvider)cert.PrivateKey;
            byte[] decrypt = _RSA.Decrypt(encryptedValue.Key, false);
            return decrypt;
        }

        private byte[] EncryptSymmetricKey_RSA(SymmetricKey symmKey, X509Certificate2 cert)
        {
            using (RSACryptoServiceProvider RSA = (RSACryptoServiceProvider)cert.PublicKey.Key)
            {
                var encrypt = RSA.Encrypt(symmKey.Key, false);
                return encrypt;
            }
        }
    }
}