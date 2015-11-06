package es.gob.jmulticard.apdu.connection.cwa14890;

import java.io.IOException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.apdu.ResponseApdu;

final class ApduEncrypterAes extends ApduEncrypter {

	@Override
	protected byte[] encryptData(final byte[] data, final byte[] key, final byte[] ssc, final CryptoHelper cryptoHelper) {
		return null;
	}

	@Override
	protected byte[] generateMac(final byte[] dataPadded,
			                     final byte[] ssc,
			                     final byte[] kMac,
			                     final CryptoHelper cryptoHelper) throws IOException {
		return null;
	}

	@Override
	ResponseApdu decryptResponseApdu(final ResponseApdu responseApdu,
			                         final byte[] keyCipher,
			                         final byte[] ssc,
			                         final byte[] kMac,
			                         final CryptoHelper cryptoHelper) throws IOException {
		return null;
	}

}
