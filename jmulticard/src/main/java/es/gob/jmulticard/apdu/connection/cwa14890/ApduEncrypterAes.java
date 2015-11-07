package es.gob.jmulticard.apdu.connection.cwa14890;

import java.io.IOException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.ResponseApdu;

final class ApduEncrypterAes extends ApduEncrypter {

	ApduEncrypterAes() {
		this.paddingLength = 16;
	}

	@Override
	protected byte[] encryptData(final byte[] data,
			                     final byte[] key,
			                     final byte[] ssc,
			                     final CryptoHelper cryptoHelper) throws IOException {
		if (ssc == null) {
			throw new IllegalArgumentException(
				"El contador de secuencia no puede ser nulo en esta version de CWA-14890" //$NON-NLS-1$
			);
		}
		// El vector de inicializacion del cifrado AES se calcula cifrando el SSC igualmente en AES con la misma clave y un vector
		// de inicializacion todo a 0x00
		final byte[] iv = cryptoHelper.aesEncrypt(
			ssc,
			new byte[0],
			key
		);
		return cryptoHelper.aesEncrypt(
			data,
			iv,
			key
		);
	}

	@Override
	protected byte[] generateMac(final byte[] dataPadded,
			                     final byte[] ssc,
			                     final byte[] kMac,
			                     final CryptoHelper cryptoHelper) throws IOException {
		final byte[] mac;
		try {
			mac = cryptoHelper.doAesCmac(HexUtils.concatenateByteArrays(ssc, dataPadded), kMac);
		}
		catch (final Exception e) {
			throw new IOException(
				"Error creando la CMAC de la APDU cifrada: " + e //$NON-NLS-1$
			);
		}
		final byte[] ret = new byte[8];
		System.arraycopy(mac, 0, ret, 0, 8);
		return ret;
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
