using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json;
using Jose;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace ConsoleApp4
{
	internal class Program
	{
		private static void Main(string[] args)
		{
			//public enum JweAlgorithm
			//{
			//	RSA1_5 = 0,
			//	RSA_OAEP = 1,
			//	RSA_OAEP_256 = 2,
			//	DIR = 3,
			//	A128KW = 4,
			//	A192KW = 5,
			//	A256KW = 6,
			//	ECDH_ES = 7,
			//	ECDH_ES_A128KW = 8,
			//	ECDH_ES_A192KW = 9,
			//	ECDH_ES_A256KW = 10,
			//	PBES2_HS256_A128KW = 11,
			//	PBES2_HS384_A192KW = 12,
			//	PBES2_HS512_A256KW = 13,
			//	A128GCMKW = 14,
			//	A192GCMKW = 15,
			//	A256GCMKW = 16
			//}

			//public enum JweEncryption
			//{
			//	A128CBC_HS256 = 0,
			//	A192CBC_HS384 = 1,
			//	A256CBC_HS512 = 2,
			//	A128GCM = 3,
			//	A192GCM = 4,
			//	A256GCM = 5
			//}

			IdentityModelEventSource.HeaderWritten = true;
			IdentityModelEventSource.ShowPII = true;

			var D = Convert.FromBase64String("kpkdD3N0dyFRfw4CSXcoK6GanQ1IV/UwqUgU+K0ov4A=");
			var X = Convert.FromBase64String("UikR3BSfvdDxyECb3GYdy4ozLIygXePGJWM7dd98P+8=");
			var Y = Convert.FromBase64String("PpdBNnEz/VUJTrzzz1+uWWNg5Uo4nDSEPDNIB0OtMGU=");

			var sharedEcParameters = new ECParameters()
			{
				Curve = ECCurve.NamedCurves.nistP256,
				Q = new ECPoint() { X = X, Y = Y },
				D = D,
			};

			Console.WriteLine("SharedEcParameters: x: {0}, y:{1}", Base64Url.Encode(sharedEcParameters.Q.X), Base64Url.Encode(sharedEcParameters.Q.Y));
			Console.WriteLine();

			string token = GenerateToken(sharedEcParameters);
			ValidateToken(token, sharedEcParameters);

		}

		private static string GenerateToken(ECParameters sharedKey)
		{
			var rsaSecurityKey = new RsaSecurityKey(RSA.Create());
			var eCDsaSecurityKey = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256));

			var signingCredential = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);

			var eCDHSecurityKey = new EcdhSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256), sharedKey);

			var encryptingCredential = new EncryptingCredentials(eCDHSecurityKey, Consts.ECDH_ES_A128KW, SecurityAlgorithms.Aes128CbcHmacSha256);

			var additionalHeader = new Dictionary<string, object> { };
			eCDHSecurityKey.OnNewKey = (ecParameter) =>
			{
				additionalHeader["epk"] = new
				{
					kty = "EC",
					crv = "P-256",
					x = Base64Url.Encode(ecParameter.Q.X),
					y = Base64Url.Encode(ecParameter.Q.Y),
				};

				Console.WriteLine(JsonSerializer.Serialize(additionalHeader["epk"]));
			};

			CryptoProviderFactory.Default.CustomCryptoProvider = new CustomCryptoProvider();

			var handler = new JsonWebTokenHandler();
			var payload = JsonSerializer.Serialize(new { sub = "123456" });

			var token = handler.CreateToken(
				payload,
				signingCredential,
				encryptingCredential,
				additionalHeaderClaims: additionalHeader);

			Console.WriteLine(" New Token : ");
			Console.WriteLine(token);
			Console.WriteLine();

			return token;
		}

		private static void ValidateToken(string token, ECParameters sharedKey)
		{
			var key = EccKey.New(sharedKey.Q.X, sharedKey.Q.Y, sharedKey.D, CngKeyUsages.KeyAgreement);

			string result = JWT.Decode(token, key);

			Console.WriteLine(" Decode result : ");
			Console.WriteLine(result);
			Console.WriteLine();

		}
	}
}
