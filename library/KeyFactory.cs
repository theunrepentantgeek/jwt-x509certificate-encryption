using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace library
{
    public static class KeyFactory
    {
        private const string SigningText = "This is my very long security key that is used to sign tokens for testing";
        private const string EncryptionText = "This is another very long security key that is used to encrypt tokens for testing";

        public static SigningCredentials CreateSymmetricSigningCredentials()
        {
            var bytes = Encoding.UTF8.GetBytes(SigningText);
            var key = new SymmetricSecurityKey(bytes);
            return new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
        }

        public static EncryptingCredentials CreateSymmetricEncryptionCredentials()
        {
            var bytes = Encoding.UTF8.GetBytes(EncryptionText);
            var key = new SymmetricSecurityKey(bytes);
            return new EncryptingCredentials(key, "dir", SecurityAlgorithms.Aes256CbcHmacSha512);
        }

        public static SigningCredentials CreateCertificateSigningCredentials()
        {
            var certificate = FindCertificate();
            var key = new X509SecurityKey(certificate);
            return new SigningCredentials(key, SecurityAlgorithms.RsaSha512Signature);
        }

        public static EncryptingCredentials CreateCertificateEncryptionCredentials()
        {
            var certificate = FindCertificate();
            var key = new X509SecurityKey(certificate);
            var result = new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512);
            return result;
        }

        private static X509Certificate2 FindCertificate()
        {
            const string thumbprint = "6D4C8E23E9C70D78F402BE9422BF44CE5465CD1A";

            var storeNames = new List<StoreName>
            {
                StoreName.My
            };

            // Prefer user cert to machine cert
            var storeLocations = new List<StoreLocation>
            {
                StoreLocation.CurrentUser,
                StoreLocation.LocalMachine
            };

            var query =
                from name in storeNames
                from location in storeLocations
                select FindByThumbprint(thumbprint, name, location);

            return query.First(cert => cert != null);
        }

        private static X509Certificate2 FindByThumbprint(string thumbprint, StoreName storeName, StoreLocation storeLocation)
        {
            using (var store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);

                //!! Passing TRUE here breaks things on .NET Core
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                var result = found.Cast<X509Certificate2>().SingleOrDefault();

                return result;
            }
        }
    }
}
