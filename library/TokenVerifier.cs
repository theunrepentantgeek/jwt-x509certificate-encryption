using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace library
{
    public class TokenVerifier
    {
        public SecurityKey SigningKey { get; }

        public SecurityKey EncryptionKey { get; }

        public TokenVerifier(SecurityKey signingKey = null, SecurityKey encryptingKey = null)
        {
            SigningKey = signingKey;
            EncryptionKey = encryptingKey;
        }

    public VerificationResult Verify(string tokenString)
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudience = "https://example.com",
            ValidateIssuer = true,
            ValidIssuer = "https://example.com",
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = SigningKey != null,
            ClockSkew = TimeSpan.FromSeconds(60),
            IssuerSigningKey = SigningKey,
            ValidateIssuerSigningKey = SigningKey != null,
            TokenDecryptionKey = EncryptionKey
        };

        try
        {
            var handler = new JwtSecurityTokenHandler();
            var principal = handler.ValidateToken(tokenString, validationParameters, out var token);

            var entitlementIdClaim = principal.FindFirst("id");
            if (entitlementIdClaim == null)
            {
                return VerificationResult.IdentifierNotPresent;
            }

            return VerificationResult.Valid;
        }
        catch (SecurityTokenException ex)
        {
            Console.WriteLine(ex);
            return VerificationResult.InvalidToken;
        }
    }
    }

    public enum VerificationResult
    {
        None,
        Valid,
        IdentifierNotPresent,
        InvalidToken
    }
}
