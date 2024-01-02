// See https://aka.ms/new-console-template for more information
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

Console.WriteLine("Hello, World!");



//using System;
//using System.IdentityModel.Tokens.Jwt;
//using System.Security.Claims;
//using System.Security.Cryptography;
//using Microsoft.IdentityModel.Tokens;


        // Replace with your RSA private key
        string privateKey = "YOUR_RSA_PRIVATE_KEY";

        // Replace with your RSA public key
        string publicKey = "YOUR_RSA_PUBLIC_KEY";

        // Create RSA parameters from private and public keys
        RSAParameters rsaParamsPrivate = GetRSAParameters(privateKey);
        RSAParameters rsaParamsPublic = GetRSAParameters(publicKey);

        // Create RSA security keys
        var keyPrivate = new RsaSecurityKey(rsaParamsPrivate);
        var keyPublic = new RsaSecurityKey(rsaParamsPublic);

        // Create signing and verifying credentials
        var signingCredentials = new SigningCredentials(keyPrivate, SecurityAlgorithms.RsaSha256);
        var verifyingCredentials = new SigningCredentials(keyPublic, SecurityAlgorithms.RsaSha256);

        // Create claims
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, "subject"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            // Add more claims as needed
        };

        // Create JWT
        var token = new JwtSecurityToken(
            issuer: "yourIssuer",
            audience: "yourAudience",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: signingCredentials
        );

        // Serialize JWT to a string
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.WriteToken(token);

        Console.WriteLine($"Generated JWT: {jwt}");

        // Verify JWT (optional)
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "yourIssuer",
            ValidateAudience = true,
            ValidAudience = "yourAudience",
            IssuerSigningKey = keyPublic,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        SecurityToken validatedToken;
        var principal = handler.ValidateToken(jwt, validationParameters, out validatedToken);

        Console.WriteLine($"JWT Validation Successful. Subject: {principal.Identity.Name}");
    

    static RSAParameters GetRSAParameters(string key)
    {
        var rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(key);

        return rsa.ExportParameters(true);
    }
