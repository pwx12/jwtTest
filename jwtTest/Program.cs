//// See https://aka.ms/new-console-template for more information
//using Microsoft.IdentityModel.Tokens;
//using System.IdentityModel.Tokens.Jwt;
//using System.Security.Claims;
//using System.Security.Cryptography;

//Console.WriteLine("Hello, World!");



////using System;
////using System.IdentityModel.Tokens.Jwt;
////using System.Security.Claims;
////using System.Security.Cryptography;
////using Microsoft.IdentityModel.Tokens;


//        // Replace with your RSA private key
//        string privateKey = "YOUR_RSA_PRIVATE_KEY";

//        // Replace with your RSA public key
//        string publicKey = "YOUR_RSA_PUBLIC_KEY";

//        // Create RSA parameters from private and public keys
//        RSAParameters rsaParamsPrivate = GetRSAParameters(privateKey);
//        RSAParameters rsaParamsPublic = GetRSAParameters(publicKey);

//        // Create RSA security keys
//        var keyPrivate = new RsaSecurityKey(rsaParamsPrivate);
//        var keyPublic = new RsaSecurityKey(rsaParamsPublic);

//        // Create signing and verifying credentials
//        var signingCredentials = new SigningCredentials(keyPrivate, SecurityAlgorithms.RsaSha256);
//        var verifyingCredentials = new SigningCredentials(keyPublic, SecurityAlgorithms.RsaSha256);

//        // Create claims
//        var claims = new[]
//        {
//            new Claim(JwtRegisteredClaimNames.Sub, "subject"),
//            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
//            // Add more claims as needed
//        };

//        // Create JWT
//        var token = new JwtSecurityToken(
//            issuer: "yourIssuer",
//            audience: "yourAudience",
//            claims: claims,
//            expires: DateTime.UtcNow.AddHours(1),
//            signingCredentials: signingCredentials
//        );

//        // Serialize JWT to a string
//        var handler = new JwtSecurityTokenHandler();
//        var jwt = handler.WriteToken(token);

//        Console.WriteLine($"Generated JWT: {jwt}");

//        // Verify JWT (optional)
//        var validationParameters = new TokenValidationParameters
//        {
//            ValidateIssuer = true,
//            ValidIssuer = "yourIssuer",
//            ValidateAudience = true,
//            ValidAudience = "yourAudience",
//            IssuerSigningKey = keyPublic,
//            ValidateLifetime = true,
//            ClockSkew = TimeSpan.Zero
//        };

//        SecurityToken validatedToken;
//        var principal = handler.ValidateToken(jwt, validationParameters, out validatedToken);

//        Console.WriteLine($"JWT Validation Successful. Subject: {principal.Identity.Name}");


//    static RSAParameters GetRSAParameters(string key)
//    {
//        var rsa = new RSACryptoServiceProvider();
//        rsa.FromXmlString(key);

//        return rsa.ExportParameters(true);
//    }

//---------------------------------------------------

//using System;
//using System.IdentityModel.Tokens.Jwt;
//using System.Security.Claims;
//using System.Security.Cryptography;
//using Microsoft.IdentityModel.Tokens;


//        // Replace with your RSA private key
//        string privateKey = "YOUR_RSA_PRIVATE_KEY";

//        // Replace with your RSA public key
//        string publicKey = "YOUR_RSA_PUBLIC_KEY";

//        // Create RSA parameters from private and public keys
//        RSAParameters rsaParamsPrivate = GetRSAParameters(privateKey);
//        RSAParameters rsaParamsPublic = GetRSAParameters(publicKey);

//        // Create RSA security keys
//        var keyPrivate = new RsaSecurityKey(rsaParamsPrivate);
//        var keyPublic = new RsaSecurityKey(rsaParamsPublic);

//        // Create signing and verifying credentials
//        var signingCredentials = new SigningCredentials(keyPrivate, SecurityAlgorithms.RsaSha256);
//        var verifyingCredentials = new SigningCredentials(keyPublic, SecurityAlgorithms.RsaSha256);

//        // Create claims
//        var claims = new[]
//        {
//            new Claim(JwtRegisteredClaimNames.Sub, "subject"),
//            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
//            // Add more claims as needed
//        };

//        // Create JWT
//        var token = new JwtSecurityToken(
//            issuer: "yourIssuer",
//            audience: "yourAudience",
//            claims: claims,
//            expires: DateTime.UtcNow.AddHours(1),
//            signingCredentials: signingCredentials
//        );

//        // Serialize JWT to a string
//        var handler = new JwtSecurityTokenHandler();
//        var jwt = handler.WriteToken(token);

//        Console.WriteLine($"Generated JWT: {jwt}");

//        // Verify JWT (optional)
//        var validationParameters = new TokenValidationParameters
//        {
//            ValidateIssuer = true,
//            ValidIssuer = "yourIssuer",
//            ValidateAudience = true,
//            ValidAudience = "yourAudience",
//            IssuerSigningKey = keyPublic,
//            ValidateLifetime = true,
//            ClockSkew = TimeSpan.Zero
//        };

//        SecurityToken validatedToken;
//        var principal = handler.ValidateToken(jwt, validationParameters, out validatedToken);

//        Console.WriteLine($"JWT Validation Successful. Subject: {principal.Identity.Name}");


//    static RSAParameters GetRSAParameters(string key)
//    {
//        var rsa = new RSACryptoServiceProvider();
//        rsa.FromXmlString(key);

//        return rsa.ExportParameters(true);
//}


using System;
using System.IO;
using System.Security.Cryptography;
//using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
//using BouncyCastle.Crypto;
//using BouncyCastle.Crypto.Parameters;
//using BouncyCastle.Security;
using Microsoft.IdentityModel.Tokens;

class RS256TokenGenerator
{
    static void Main()
    {
        // Replace with the paths to your PEM files
        string privateKeyPath = @"C:\Users\misie\OneDrive\Desktop\key\prv8.pem";
        string publicKeyPath = @"C:\Users\misie\OneDrive\Desktop\key\pub8.pem";

        // Load private key from PEM file
        RSA privateKey = LoadPrivateKey(privateKeyPath);

        // Load public key from PEM file
        RSA publicKey = LoadPublicKey(publicKeyPath);

        // Create JWT token
        string jwt = GenerateJwt(privateKey, publicKey);

        Console.WriteLine("Generated JWT: " + jwt);
    }

    static RSA LoadPrivateKey(string privateKeyPath)
    {
        using (StreamReader reader = new StreamReader(privateKeyPath))
        {
            string privateKeyPem = reader.ReadToEnd();
            var privateKeyBytes = Convert.FromBase64String(
                privateKeyPem
                    .Replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .Replace("-----END RSA PRIVATE KEY-----", "")
                    .Replace("\n", "")
            );

            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
            return rsa;
        }
    }

    static RSA LoadPublicKey(string publicKeyPath)
    {
        using (StreamReader reader = new StreamReader(publicKeyPath))
        {
            string publicKeyPem = reader.ReadToEnd();
            var publicKeyBytes = Convert.FromBase64String(
                publicKeyPem
                    .Replace("-----BEGIN PUBLIC KEY-----", "")
                    .Replace("-----END PUBLIC KEY-----", "")
                    .Replace("\n", "")
            );

            var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            return rsa;
        }
    }

    static string GenerateJwt(RSA privateKey, RSA publicKey)
    {
        var securityKey = new RsaSecurityKey(privateKey);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.CreateJwtSecurityToken(
            issuer: "your-issuer",
            audience: "your-audience",
            subject: new System.Security.Claims.ClaimsIdentity(new[] { new System.Security.Claims.Claim("sub", "subject") }),
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials
        );

        return tokenHandler.WriteToken(jwtToken);
    }
}






//-------------------------------- Read pem file
//using System;
//using System.IO;
//using Org.BouncyCastle.Crypto;
//using Org.BouncyCastle.OpenSsl;

//class Program
//{
//    static void Main()
//    {
//        string privateKeyPath = "path/to/private_key.pem";

//        try
//        {
//            AsymmetricCipherKeyPair keyPair = ReadPrivateKey(privateKeyPath);

//            // Now you have the private key in the keyPair variable
//            // You can use it for cryptographic operations as needed
//            Console.WriteLine("Private key read successfully.");
//        }
//        catch (Exception ex)
//        {
//            Console.WriteLine($"Error reading private key: {ex.Message}");
//        }
//    }

//    static AsymmetricCipherKeyPair ReadPrivateKey(string privateKeyPath)
//    {
//        using (StreamReader reader = new StreamReader(privateKeyPath))
//        {
//            PemReader pemReader = new PemReader(reader);
//            object obj = pemReader.ReadObject();

//            if (obj is AsymmetricCipherKeyPair)
//            {
//                return (AsymmetricCipherKeyPair)obj;
//            }
//            else
//            {
//                throw new InvalidOperationException("The PEM file does not contain a private key.");
//            }
//        }
//    }
//}



