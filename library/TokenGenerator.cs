using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace library
{
    public class TokenGenerator
    {
        public SigningCredentials SigningCredentials { get; }

        public EncryptingCredentials EncryptingCredentials { get; }

        public TokenGenerator(
            SigningCredentials signingCredentials,
            EncryptingCredentials encryptingCredentials)
        {
            SigningCredentials = signingCredentials;
            EncryptingCredentials = encryptingCredentials;
        }

public string Generate(NodeEntitlements entitlements)
{
    if (entitlements == null)
    {
        throw new ArgumentNullException(nameof(entitlements));
    }

    var claims = CreateClaims(entitlements);
    var claimsIdentity = new ClaimsIdentity(claims);

    var securityTokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = claimsIdentity,
        NotBefore = entitlements.NotBefore.UtcDateTime,
        Expires = entitlements.NotAfter.UtcDateTime,
        IssuedAt = DateTimeOffset.Now.UtcDateTime,
        Issuer = "https://example.com",
        Audience = "https://example.com",
        SigningCredentials = SigningCredentials,
        EncryptingCredentials = EncryptingCredentials
    };

    var handler = new JwtSecurityTokenHandler();

    var token = handler.CreateToken(securityTokenDescriptor);

    return handler.WriteToken(token);
}

        private List<Claim> CreateClaims(NodeEntitlements entitlements)
        {
            var claims = new List<Claim>
            {
                new Claim("vmid", entitlements.VirtualMachineId),
                new Claim("id", entitlements.Identifier)
            };

            foreach (var ip in entitlements.IpAddresses)
            {
                claims.Add(new Claim("ip", ip.ToString()));
            }

            foreach (var app in entitlements.Applications)
            {
                var claim = new Claim("app", app);
                claims.Add(claim);
            }

            return claims;
        }
    }
}
