using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Raven.DependencyInjection;
using Raven.Identity;

namespace Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services)
        {
            services
                .AddRavenDbDocStore() // Create our IDocumentStore singleton using the database settings in appsettings.json
                .AddRavenDbAsyncSession() // Create a Raven IAsyncDocumentSession for every request.
                .AddIdentityCore<CustomUser>(
                    options =>
                    {
                        options.Lockout.MaxFailedAccessAttempts = 3;
                        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
                    }) // Add the Identity services for Intello User to the DI container. 
                .AddSignInManager<SignInManager<CustomUser>>() // Add the SignInManager to the DI container.
                .AddRoles<IdentityRole>() // Add the Add roles to the DI container.
                .AddRoleManager<RoleManager<IdentityRole>>()
                .AddRavenDbIdentityStores<CustomUser, IdentityRole>(); // Use Raven as the Identity store for user users and roles.

            return services;
        }
    }
}
