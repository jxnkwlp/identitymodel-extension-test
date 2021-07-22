using Microsoft.IdentityModel.Tokens;

namespace ConsoleApp4
{
	public class AesKeyWrapProvider : SymmetricKeyWrapProvider
	{
		public AesKeyWrapProvider(SecurityKey key, string algorithm) : base(key, algorithm)
		{
		}

		protected override bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
		{
			if (algorithm == Consts.ECDH_ES_A128KW)
				return true;

			return base.IsSupportedAlgorithm(key, algorithm);
		}

		public override byte[] WrapKey(byte[] keyBytes)
		{
			return base.WrapKey(keyBytes);
		}

		public override byte[] UnwrapKey(byte[] keyBytes)
		{
			return base.UnwrapKey(keyBytes);
		}
	}
}
