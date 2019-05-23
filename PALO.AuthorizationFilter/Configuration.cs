namespace PALO.AuthorizationFilter
{
    public static class Configuration
    {
        public static string PublicKey { get; private set; }

        public static void SetPublicKey(string publicKey)
        {
            PublicKey = publicKey;
        }
    }
}