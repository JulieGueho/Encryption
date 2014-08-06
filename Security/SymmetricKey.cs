using System;
using Microsoft.WindowsAzure.StorageClient;

namespace Encryption.Security
{
    public class SymmetricKey : TableServiceEntity
    {
        public SymmetricKey()
        {
            this.CreationDate = DateTime.UtcNow;
        }

        public byte[] Key { get; set; }
        public byte[] Iv { get; set; }
        public int Version { get; set; }
        public string CertificateHash { get; set; }
        public DateTime CreationDate { get; set; }
    }
}
