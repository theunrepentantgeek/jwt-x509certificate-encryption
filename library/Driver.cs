using System;
using System.Net;

namespace library
{
    public class Driver
    {
        private static readonly NodeEntitlements _entitlements = new NodeEntitlements();

        public void TokenTest()
        {
            //var signing = KeyFactory.CreateSymmetricSigningCredentials();
            var signing = KeyFactory.CreateCertificateSigningCredentials();

            //var encrypting = KeyFactory.CreateSymmetricEncryptionCredentials();
            var encrypting = KeyFactory.CreateCertificateEncryptionCredentials();

            var generator = new TokenGenerator(signing, encrypting);
            var verifier = new TokenVerifier(signing.Key, encrypting.Key);

            var token = generator.Generate(_entitlements);
            var result = verifier.Verify(token, "app", IPAddress.Parse("127.0.0.1"));

            Console.WriteLine(result.ToString());
        }
    }
}
