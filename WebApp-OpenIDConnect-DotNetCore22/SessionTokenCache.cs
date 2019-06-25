using System.Threading;
using Microsoft.AspNetCore.Http;
using Microsoft.Identity.Client;

namespace WebApp_OpenIDConnect_DotNetCore22
{
    public class SessionTokenCache
    {
        private static ReaderWriterLockSlim TokenCacheLock;

        private readonly HttpContext _context;
        private readonly string _sessionKey;

        static SessionTokenCache()
        {
            TokenCacheLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
        }

        public SessionTokenCache(HttpContext context, string userId)
        {
            _context = context;
            _sessionKey = userId + "_TokenCache";
        }

        public void Initialize(ITokenCache tokenCache)
        {
            tokenCache.SetBeforeAccess(OnBeforeAccess);
            tokenCache.SetAfterAccess(OnAfterAccess);
        }

        public void Load(ITokenCacheSerializer tokenCacheSerializer)
        {
            TokenCacheLock.EnterReadLock();
            var sessionValue = _context.Session.Get(_sessionKey);

            if (sessionValue != null)
            {
                tokenCacheSerializer.DeserializeMsalV3(sessionValue);
            }

            TokenCacheLock.ExitReadLock();
        }

        public void Save(ITokenCacheSerializer tokenCacheSerializer)
        {
            TokenCacheLock.EnterWriteLock();
            _context.Session.Set(_sessionKey, tokenCacheSerializer.SerializeMsalV3());
            TokenCacheLock.ExitWriteLock();
        }

        private void OnAfterAccess(TokenCacheNotificationArgs args)
        {
            if (args.HasStateChanged)
            {
                Save(args.TokenCache);
            }
        }

        private void OnBeforeAccess(TokenCacheNotificationArgs args)
        {
            Load(args.TokenCache);
        }
    }
}
