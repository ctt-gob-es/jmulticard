package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class HSSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    HSSKeyGenerationParameters param;

    @Override
	public void init(KeyGenerationParameters param)
    {
        this.param = (HSSKeyGenerationParameters)param;
    }

    @Override
	public AsymmetricCipherKeyPair generateKeyPair()
    {
        HSSPrivateKeyParameters privKey = HSS.generateHSSKeyPair(param);

        return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
    }
}
