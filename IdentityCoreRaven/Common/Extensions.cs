using Infrastructure;
using Raven.Client.Documents;

namespace IdentityCoreRaven.Common
{
    public static class Extensions
    {
        public static IDocumentStore EnsureExists(this IDocumentStore store)
        {
            try
            {
                using var dbSession = store.OpenSession();
                dbSession.Query<CustomUser>().Take(0).ToList();
            }
            catch (Raven.Client.Exceptions.Database.DatabaseDoesNotExistException)
            {
                store.Maintenance.Server.Send(new Raven.Client.ServerWide.Operations.CreateDatabaseOperation(new Raven.Client.ServerWide.DatabaseRecord
                {
                    DatabaseName = store.Database
                }));
            }

            return store;
        }

        public static IDocumentStore EnsureRolesExist(this IDocumentStore docStore, List<string> roleNames)
        {
            using (var dbSession = docStore.OpenSession())
            {
                var roleIds = roleNames.Select(r => "IdentityRoles/" + r);
                var roles = dbSession.Load<Raven.Identity.IdentityRole>(roleIds);
                foreach (var idRolePair in roles)
                {
                    if (idRolePair.Value == null)
                    {
                        var id = idRolePair.Key;
                        var roleName = id.Replace("IdentityRoles/", string.Empty);
                        dbSession.Store(new Raven.Identity.IdentityRole(roleName), id);
                    }
                }

                if (roles.Any(i => i.Value == null))
                {
                    dbSession.SaveChanges();
                }
            }

            return docStore;
        }
    }
}
