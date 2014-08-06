using System.Data.Entity.Core.Objects;
using System.Data.Entity.Infrastructure;
using System.Linq;
using Encryption.Security;

namespace Encryption.Data
{
    public class Context : EncryptionDbEntities
    {
        private EncryptionService _encryptionService;

        public Context()
            : base()
        {
            ((IObjectContextAdapter) this).ObjectContext.ObjectMaterialized += ObjectContextOnObjectMaterialized;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        public override int SaveChanges()
        {
            var changeSet = ChangeTracker.Entries<User>().Where(entity => entity.State.HasFlag(System.Data.Entity.EntityState.Modified) || entity.State.HasFlag(System.Data.Entity.EntityState.Added));
            if (changeSet.Any())
            {
                foreach (DbEntityEntry<User> entry in changeSet)
                {
                    Encrypt(entry.Entity);
                }
            }

            return base.SaveChanges();
        }     

        private void ObjectContextOnObjectMaterialized(object sender, ObjectMaterializedEventArgs objectMaterializedEventArgs)
        {
            if (objectMaterializedEventArgs.Entity.GetType().Name == "User")
            {
                var user = (User)objectMaterializedEventArgs.Entity;
                Decrypt(user);
            }
        }

        private void Encrypt(User user)
        {
            InitializeEncryptionService();
            user.Firstname = _encryptionService.EncryptString(user.Firstname, user.KeyVersion);
            user.Lastname = _encryptionService.EncryptString(user.Lastname, user.KeyVersion);
            user.KeyVersion = user.KeyVersion ?? _encryptionService.GetKeyVersion();
        }

        private void Decrypt(User user)
        {            
            if (user.KeyVersion.HasValue)
            {
                InitializeEncryptionService();
                user.Firstname = _encryptionService.DecryptString(user.Firstname, user.KeyVersion.Value);
                user.Lastname = _encryptionService.DecryptString(user.Lastname, user.KeyVersion.Value);
            }
        }

        private void InitializeEncryptionService()
        {
            if (_encryptionService == null)
            {
                _encryptionService = new EncryptionService();
            }
        }
    }
}
