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


//using System;
//using System.IO;
//using System.Security.Cryptography;
////using System.Security.Cryptography.X509Certificates;
//using System.Text;
//using System.IdentityModel.Tokens.Jwt;
////using BouncyCastle.Crypto;
////using BouncyCastle.Crypto.Parameters;
////using BouncyCastle.Security;
//using Microsoft.IdentityModel.Tokens;

//class RS256TokenGenerator
//{
//    static void Main()
//    {
//        // Replace with the paths to your PEM files
//        string privateKeyPath = @"C:\Users\misie\OneDrive\Desktop\key\prv8.pem";
//        string publicKeyPath = @"C:\Users\misie\OneDrive\Desktop\key\pub8.pem";

//        // Load private key from PEM file
//        RSA privateKey = LoadPrivateKey(privateKeyPath);

//        // Load public key from PEM file
//        RSA publicKey = LoadPublicKey(publicKeyPath);

//        // Create JWT token
//        string jwt = GenerateJwt(privateKey, publicKey);

//        Console.WriteLine("Generated JWT: " + jwt);
//    }

//    static RSA LoadPrivateKey(string privateKeyPath)
//    {
//        using (StreamReader reader = new StreamReader(privateKeyPath))
//        {
//            string privateKeyPem = reader.ReadToEnd();
//            var privateKeyBytes = Convert.FromBase64String(
//                privateKeyPem
//                    .Replace("-----BEGIN RSA PRIVATE KEY-----", "")
//                    .Replace("-----END RSA PRIVATE KEY-----", "")
//                    .Replace("\n", "")
//            );

//            var rsa = RSA.Create();
//            rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
//            return rsa;
//        }
//    }

//    static RSA LoadPublicKey(string publicKeyPath)
//    {
//        using (StreamReader reader = new StreamReader(publicKeyPath))
//        {
//            string publicKeyPem = reader.ReadToEnd();
//            var publicKeyBytes = Convert.FromBase64String(
//                publicKeyPem
//                    .Replace("-----BEGIN PUBLIC KEY-----", "")
//                    .Replace("-----END PUBLIC KEY-----", "")
//                    .Replace("\n", "")
//            );

//            var rsa = RSA.Create();
//            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
//            return rsa;
//        }
//    }

//    static string GenerateJwt(RSA privateKey, RSA publicKey)
//    {
//        var securityKey = new RsaSecurityKey(privateKey);
//        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

//        var tokenHandler = new JwtSecurityTokenHandler();
//        var jwtToken = tokenHandler.CreateJwtSecurityToken(
//            issuer: "your-issuer",
//            audience: "your-audience",
//            subject: new System.Security.Claims.ClaimsIdentity(new[] { new System.Security.Claims.Claim("sub", "subject") }),
//            expires: DateTime.UtcNow.AddHours(1),
//            signingCredentials: credentials
//        );

//        return tokenHandler.WriteToken(jwtToken);
//    }
//}






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


//--------------------

//using System;
//using System.IO;
//using System.Security.Cryptography;
//using System.Text;
//using System.IdentityModel.Tokens.Jwt;
//using Microsoft.IdentityModel.Tokens;

//class Program
//{
//    static void Main()
//    {
//        // Replace these paths with the paths to your PEM files
//        string privateKeyPath = "path/to/private-key.pem";
//        string publicKeyPath = "path/to/public-key.pem";

//        try
//        {
//            string privateKeyPEM = ReadKeyFromFile(privateKeyPath);
//            string publicKeyPEM = ReadKeyFromFile(publicKeyPath);

//            RSACryptoServiceProvider rsaPrivate = LoadRSAPrivateKey(privateKeyPEM);
//            RSACryptoServiceProvider rsaPublic = LoadRSAPublicKey(publicKeyPEM);

//            // Create a JWT token
//            string jwtToken = GenerateJwt(rsaPrivate, rsaPublic);

//            Console.WriteLine($"Generated JWT token:\n{jwtToken}");
//        }
//        catch (Exception ex)
//        {
//            Console.WriteLine($"An error occurred: {ex.Message}");
//        }
//    }

//    static RSACryptoServiceProvider LoadRSAPrivateKey(string privateKeyPEM)
//    {
//        byte[] privateKeyBytes = Convert.FromBase64String(privateKeyPEM);

//        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
//        {
//            RSAParameters rsaParams = new RSAParameters();

//            using (BinaryReader reader = new BinaryReader(new MemoryStream(privateKeyBytes)))
//            {
//                // Implementation of loading RSA private key similar to the previous example
//                // ...

//                // Use the LoadRSAPSSPrivateKey method from the previous example
//                return LoadRSAPSSPrivateKey(privateKeyPEM);
//            }
//        }
//    }

//    static RSACryptoServiceProvider LoadRSAPublicKey(string publicKeyPEM)
//    {
//        byte[] publicKeyBytes = Convert.FromBase64String(publicKeyPEM);

//        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
//        {
//            RSAParameters rsaParams = new RSAParameters();

//            using (BinaryReader reader = new BinaryReader(new MemoryStream(publicKeyBytes)))
//            {
//                // Implementation of loading RSA public key similar to the previous example
//                // ...

//                // Use the LoadRSAPublicKey method from the previous example
//                return LoadRSAPublicKey(publicKeyPEM);
//            }
//        }
//    }

//    static string GenerateJwt(RSACryptoServiceProvider rsaPrivate, RSACryptoServiceProvider rsaPublic)
//    {
//        var securityKey = new RsaSecurityKey(rsaPrivate);

//        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

//        var header = new JwtHeader(credentials);
//        var payload = new JwtPayload
//        {
//            { "sub", "subject" },
//            { "exp", DateTime.UtcNow.AddHours(1) }
//            // Add additional claims as needed
//        };

//        var jwtToken = new JwtSecurityToken(header, payload);
//        var jwtHandler = new JwtSecurityTokenHandler();

//        return jwtHandler.WriteToken(jwtToken);
//    }

//    // Other helper methods similar to the previous example
//    // ...
//}


//using System;
//using System.IO;
//using System.Security.Cryptography;
//using System.Text;

//class Program
//{
//    static void Main()
//    {
//        // Replace this path with the path to your PEM file containing the RSASSA-PSS private key
//        string privateKeyPath = "path/to/private-key.pem";

//        try
//        {
//            string privateKeyPEM = ReadKeyFromFile(privateKeyPath);

//            RSA rsa = LoadRSASSAPSSPrivateKey(privateKeyPEM);

//            // Now you can use the 'rsa' object for cryptographic operations

//            Console.WriteLine("RSASSA-PSS private key loaded successfully.");
//        }
//        catch (Exception ex)
//        {
//            Console.WriteLine($"An error occurred: {ex.Message}");
//        }
//    }

//    static RSA LoadRSASSAPSSPrivateKey(string privateKeyPEM)
//    {
//        byte[] privateKeyBytes = Convert.FromBase64String(privateKeyPEM);

//        using (RSA rsa = RSA.Create())
//        {
//            RSAParameters rsaParams = new RSAParameters();

//            // Assuming the private key is in PKCS#8 format
//            if (PrivateKeyParser.TryReadPkcs8(privateKeyBytes, out var keyInfo))
//            {
//                rsaParams.Modulus = keyInfo.Modulus;
//                rsaParams.Exponent = keyInfo.Exponent;
//                rsaParams.D = keyInfo.D;
//                rsaParams.P = keyInfo.P;
//                rsaParams.Q = keyInfo.Q;
//                rsaParams.DP = keyInfo.DP;
//                rsaParams.DQ = keyInfo.DQ;
//                rsaParams.InverseQ = keyInfo.InverseQ;

//                rsa.ImportParameters(rsaParams);

//                return rsa;
//            }

//            throw new InvalidOperationException("Failed to read RSASSA-PSS private key.");
//        }
//    }

//    static string ReadKeyFromFile(string filePath)
//    {
//        using (StreamReader reader = new StreamReader(filePath))
//        {
//            StringBuilder keyBuilder = new StringBuilder();
//            string line;

//            // Skip the first line if it contains "-----BEGIN..."
//            if ((line = reader.ReadLine()?.Trim())?.StartsWith("-----BEGIN") == true)
//            {
//                while ((line = reader.ReadLine()?.Trim()) != null && !line.StartsWith("-----END"))
//                {
//                    keyBuilder.AppendLine(line);
//                }
//            }

//            return keyBuilder.ToString();
//        }
//    }
//}

//public static class PrivateKeyParser
//{
//    public static bool TryReadPkcs8(byte[] keyBytes, out RSAParameters keyInfo)
//    {
//        // Implementation to parse PKCS#8 private key
//        // ...

//        keyInfo = default;
//        return false;
//    }
//}




//------------------------httpClient example--------
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

class Program
{
    static async Task Main()
    {
        // Replace the URL with the actual endpoint you want to post data to
        string apiUrl = "https://example.com/api";

        // Prepare the data you want to send as key-value pairs
        var formData = new Dictionary<string, string>
        {
            { "key1", "value1" },
            { "key2", "value2" }
        };

        // Create an instance of HttpClient
        using (HttpClient httpClient = new HttpClient())
        {
            // Create FormUrlEncodedContent from the data
            var content = new FormUrlEncodedContent(formData);

            try
            {
                // Send the POST request
                HttpResponseMessage response = await httpClient.PostAsync(apiUrl, content);

                // Check if the request was successful
                if (response.IsSuccessStatusCode)
                {
                    // Read and handle the response content
                    string responseContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine("Response: " + responseContent);
                }
                else
                {
                    Console.WriteLine("Error: " + response.StatusCode);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
            }
        }
    }
}






