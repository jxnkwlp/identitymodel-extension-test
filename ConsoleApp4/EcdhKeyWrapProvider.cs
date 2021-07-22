using Microsoft.IdentityModel.Tokens;

namespace ConsoleApp4
{
	public class EcdhKeyWrapProvider : KeyWrapProvider
	{
		public override string Algorithm { get; }

		public override string Context { get; set; }

		public override SecurityKey Key { get; }

		private readonly EcdhSecurityKey _ecdhSecurityKey;

		public EcdhKeyWrapProvider(SecurityKey key, string algorithm)
		{
			Key = key;
			Algorithm = algorithm;

			_ecdhSecurityKey = key as EcdhSecurityKey;
		}

		private AesKeyWrapProvider CreateAesKeyWrapProvider(byte[] key)
		{
			var skey = new SymmetricSecurityKey(key);
			return new AesKeyWrapProvider(skey, "A128KW");
		}

		public override byte[] UnwrapKey(byte[] keyBytes)
		{
			var result = _ecdhSecurityKey.NewKey(Algorithm);

			return CreateAesKeyWrapProvider(result).UnwrapKey(keyBytes);
		}

		public override byte[] WrapKey(byte[] keyBytes)
		{
			var result = _ecdhSecurityKey.NewKey(Algorithm);

			var wrapResult = CreateAesKeyWrapProvider(result).WrapKey(keyBytes);
			return wrapResult;
		}

		protected override void Dispose(bool disposing)
		{
		}

	}
}
