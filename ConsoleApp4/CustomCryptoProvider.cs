using Microsoft.IdentityModel.Tokens;

namespace ConsoleApp4
{
	public class CustomCryptoProvider : ICryptoProvider
	{
		public object Create(string algorithm, params object[] args)
		{
			if (algorithm == Consts.ECDH_ES_A128KW)
			{
				return new EcdhKeyWrapProvider((SecurityKey)args[0], algorithm);
			}

			return null;
		}

		public bool IsSupportedAlgorithm(string algorithm, params object[] args)
		{
			return algorithm == Consts.ECDH_ES_A128KW;
		}

		public void Release(object cryptoInstance)
		{
		}
	}
}
