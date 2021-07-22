using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ConsoleApp4
{
	public class EcdhSecurityKey : SymmetricSecurityKey
	{
		private static readonly byte[] _secretPreprend = { 0x0, 0x0, 0x0, 0x1 };

		public EcdhSecurityKey(ECDsa privateKey, ECParameters externalPubKey) : base(privateKey.ExportParameters(false).Q.X)
		{
			PrivateKey = privateKey;
			ExternalPubKey = externalPubKey;
		}

		public EcdhSecurityKey(byte[] key) : base(key)
		{
		}

		public ECDsa PrivateKey { get; }

		public ECParameters ExternalPubKey { get; }

		public Action<ECParameters> OnNewKey { get; set; }

		public byte[] NewKey(string algorithm)
		{
			var staticParameters = PrivateKey.ExportParameters(true);

			// external  
			var keyParameters = ExternalPubKey;


			//var staticKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
			//var partKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);

			var otherPartyKey = ECDiffieHellman.Create(keyParameters);
			var ephemeralKey = ECDiffieHellman.Create(staticParameters);

			// EccKey ephemeral = EccKey.Generate(staticKey);

			// CngKey bobKey = CngKey.Import(otherPartyKey.PublicKey.ToByteArray(), CngKeyBlobFormat.EccPublicBlob);

			// byte[] exchangeHash = ((ECDiffieHellmanCng)ephemeralKey).DeriveKeyMaterial(bobKey);
			// byte[] exchangeHash = ephemeralKey.DeriveKeyMaterial(otherPartyKey.PublicKey);

			// header => EPK 
			//using var epk = ECJwk.FromParameters(ephemeralKey.ExportParameters(false));
			//header.Add(new JwtProperty(HeaderParameters.EpkUtf8, epk.AsJwtObject()));

			OnNewKey?.Invoke(ephemeralKey.ExportParameters(false));

			int keyLength = 128;

			var secretAppend = BuildSecret(algorithm, keyLength, Array.Empty<byte>(), Array.Empty<byte>());

			byte[] exchangeHash = ephemeralKey.DeriveKeyFromHash(otherPartyKey.PublicKey, HashAlgorithmName.SHA256, _secretPreprend, secretAppend);

			int byteCount = keyLength / 8;

			var result = new byte[byteCount];

			Buffer.BlockCopy(exchangeHash, 0, result, 0, byteCount);

			return result;
		}

		private static byte[] BuildSecret(string algorithm, int keyLength, byte[] partyUIInfo, byte[] partyVInfo)
		{
			int algorithmLength = Encoding.UTF8.GetBytes(algorithm).Length;
			var length = algorithmLength + partyUIInfo.Length + partyVInfo.Length + keyLength;

			var result = new byte[length];

			using (var ms = new MemoryStream(result))
			{
				using (BinaryWriter write = new BinaryWriter(ms))
				{
					// algorithm
					var temp = BitConverter.GetBytes(algorithmLength);
					if (BitConverter.IsLittleEndian)
						Array.Reverse(temp);
					write.Write(temp);

					write.Write(Encoding.UTF8.GetBytes(algorithm));

					// partyUIInfo 
					temp = BitConverter.GetBytes(partyUIInfo.Length);
					if (BitConverter.IsLittleEndian)
						Array.Reverse(temp);
					write.Write(temp);

					write.Write(partyUIInfo);

					// partyVInfo 
					temp = BitConverter.GetBytes(partyVInfo.Length);
					if (BitConverter.IsLittleEndian)
						Array.Reverse(temp);
					write.Write(temp);

					write.Write(partyVInfo);

					// suppPubInfo 
					temp = BitConverter.GetBytes(keyLength);
					if (BitConverter.IsLittleEndian)
						Array.Reverse(temp);
					write.Write(temp);
				}

				return ms.ToArray();
			}
		}

	}
}
