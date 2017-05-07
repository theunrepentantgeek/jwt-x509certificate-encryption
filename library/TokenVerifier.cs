using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace library
{
    public class TokenVerifier
    {
        public string VirtualMachineId { get; }

        public DateTimeOffset CurrentInstant { get; } = DateTimeOffset.Now;

        public SecurityKey SigningKey { get; }

        public SecurityKey EncryptionKey { get; }

        public TokenVerifier(SecurityKey signingKey = null, SecurityKey encryptingKey = null)
        {
            SigningKey = signingKey;
            EncryptionKey = encryptingKey;

            CurrentInstant = DateTimeOffset.Now;
        }

        public VerificationResult Verify(string tokenString, string application, IPAddress ipAddress)
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

                if (!VerifyApplication(principal, application))
                {
                    return VerificationResult.ApplicationNotEntitled;
                }

                if (!VerifyIpAddress(principal, ipAddress))
                {
                    return VerificationResult.MachineNotEntitled;
                }

                var entitlementIdClaim = principal.FindFirst("id");
                if (entitlementIdClaim == null)
                {
                    return VerificationResult.IdentifierNotPresent;
                }

                var virtualMachineIdClaim = principal.FindFirst("vmid");
                if (virtualMachineIdClaim == null)
                {
                    return VerificationResult.VirtualMachineNotSpecified;
                }

                return VerificationResult.Valid;
            }
            catch (SecurityTokenNotYetValidException)
            {
                return VerificationResult.TokenNotYetValid;
            }
            catch (SecurityTokenExpiredException)
            {
                return VerificationResult.TokenExpired;
            }
            catch (SecurityTokenException ex)
            {
                Console.WriteLine(ex);
                return VerificationResult.InvalidToken;
            }
        }

        private bool VerifyApplication(ClaimsPrincipal principal, string application)
        {
            var applicationsClaim = principal.FindAll("app");
            if (!applicationsClaim.Any(c => string.Equals(c.Value, application, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            return true;
        }

        private bool VerifyIpAddress(ClaimsPrincipal principal, IPAddress address)
        {
            var ipAddressClaims = principal.FindAll("ip").ToList();
            foreach (var ipClaim in ipAddressClaims)
            {
                if (!IPAddress.TryParse(ipClaim.Value, out var parsedAddress))
                {
                    // Skip any IP addresses in the token that are invalid
                    continue;
                }

                if (address.Equals(parsedAddress))
                {
                    // We have a match!
                    return true;
                }
            }

            return false;
        }
    }

    public enum VerificationResult
    {
        None,
        Valid,
        ApplicationNotEntitled,
        MachineNotEntitled,
        IdentifierNotPresent,
        VirtualMachineNotSpecified,
        TokenNotYetValid,
        TokenExpired,
        InvalidToken
    }
}
