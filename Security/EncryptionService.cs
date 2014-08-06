using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IO;
using System.Web.Configuration;
using Microsoft.WindowsAzure;

namespace Encryption.Security
{
    /// <summary>
    /// Manages encryption/decryption of strings with AES
    /// </summary>
    public class EncryptionService
    {
        private X509Certificate2 _certificate = null;
        private StorageCredentials _credentials = null;
        private string _baseAddress = null;
        private SymmetricKey _symmetricKey = null;

        public EncryptionService()
        {
            var storageAccount = Microsoft.WindowsAzure.CloudStorageAccount.Parse(ConfigurationManager.ConnectionStrings["StorageConnectionString"].ConnectionString);
            _baseAddress = storageAccount.TableEndpoint.AbsoluteUri;
            _credentials = storageAccount.Credentials;
            var section = (NameValueCollection)WebConfigurationManager.GetSection("encryption");
            LoadCertificateByThumbprint(section["certificateThumbprint"]);
        }

        public string EncryptString(string dataToEncrypt, int? version)
        {
            LoadSymmetricKey(version);
            return AesCrypto.Encrypt(dataToEncrypt, _symmetricKey.Key, _symmetricKey.Iv);
        }

        public string DecryptString(string secureData, int version)
        {
            LoadSymmetricKey(version);
            return AesCrypto.Decrypt(secureData, _symmetricKey.Key, _symmetricKey.Iv);
        }  

        public int GetKeyVersion()
        {
            return _symmetricKey.Version;
        }        

        private bool LoadCertificateByThumbprint(string thumbprint)
        {
            thumbprint = thumbprint.Replace(" ", "").ToUpperInvariant();
            StoreName storeName = StoreName.My;
            StoreLocation storeLocation = StoreLocation.LocalMachine;
            X509Store store = new X509Store(storeName, storeLocation);            

            try
            {
                store.Open(OpenFlags.ReadOnly);

                foreach (var cert in store.Certificates)
                {
                    if (cert.HasPrivateKey == false)
                        continue;

                    if (String.Compare(cert.Thumbprint, thumbprint) == 0)
                    {
                        _certificate = cert;
                        break;
                    }
                }
            }
            finally
            {
                store.Close();
            }

            if (_certificate == null)
            {
                throw new InvalidOperationException("The certificate with the thumbprint " + thumbprint + " could not be found.");
            }

            return true;
        }

        private void LoadSymmetricKey(int? version)
        {
            if (_symmetricKey == null || (version.HasValue && version.Value != _symmetricKey.Version))
            {
                SymmetricKeyService helper = new SymmetricKeyService(_baseAddress, _credentials, _certificate);
                _symmetricKey = helper.LoadSymmetricKey(version);
            }
        }
    }
}