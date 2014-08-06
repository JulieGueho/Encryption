using System.Configuration;
using System.Linq;
using Microsoft.WindowsAzure;
using Microsoft.WindowsAzure.StorageClient;

namespace Encryption.Security
{
    /// <summary>
    /// Manages symmetric key context
    /// </summary>
    public class SymmetricKeyContext : TableServiceContext
    {
        public SymmetricKeyContext(string baseAddress, StorageCredentials credentials)
            : base(baseAddress, credentials)
        {
            var storageAccount = Microsoft.WindowsAzure.CloudStorageAccount.Parse(ConfigurationManager.ConnectionStrings["StorageConnectionString"].ConnectionString);
            var client = storageAccount.CreateCloudTableClient().CreateTableIfNotExist("SymmetricKeys");
        }

        public IQueryable<SymmetricKey> SymmetricKeys
        {
            get
            {
                return CreateQuery<SymmetricKey>("SymmetricKeys");
            }
        }

        public SymmetricKey SaveSymmetricKey(SymmetricKey sKey)
        {
            AddObject("SymmetricKeys", sKey);
            SaveChanges();
            return sKey;
        }
    }
}
