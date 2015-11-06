package es.gob.jmulticard.apdu.connection.cwa14890;

import java.io.IOException;

import junit.framework.Assert;

import org.junit.Test;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.dnie.VerifyApduCommand;

/** Pruebas del cifrado de APDU seg&uacute;n CWA-14890.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestApduEncrypter extends ApduEncrypter {

	private static final byte[] KENC = new byte[] {
		(byte)0x59, (byte)0x8f, (byte)0x26, (byte)0xe3, (byte)0x6e, (byte)0x11, (byte)0xa8, (byte)0xec,
		(byte)0x14, (byte)0xb8, (byte)0x1e, (byte)0x19, (byte)0xbd, (byte)0xa2, (byte)0x23, (byte)0xca
	};
	private static final byte[] KMAC = new byte[] {
		(byte)0x5d, (byte)0xe2, (byte)0x93, (byte)0x9a, (byte)0x1e, (byte)0xa0, (byte)0x3a, (byte)0x93,
		(byte)0x0b, (byte)0x88, (byte)0x20, (byte)0x6d, (byte)0x8f, (byte)0x73, (byte)0xe8, (byte)0xa7
	};
	private static final byte[] SSC_SIMPLE = new byte[] {
		(byte)0xd3, (byte)0x1a, (byte)0xc8, (byte)0xec, (byte)0x7b, (byte)0xa0, (byte)0xfe, (byte)0x75
	};

	private static final byte[] SSC_PIN = new byte[] {
		(byte)0xd3, (byte)0x1a, (byte)0xc8, (byte)0xec, (byte)0x7b, (byte)0xa0, (byte)0xfe, (byte)0x6f
	};


	private static final byte[] KENC2 = new byte[] {
		(byte)0xf1, (byte)0xb0, (byte)0xd6, (byte)0x44, (byte)0x9c, (byte)0xec, (byte)0x48, (byte)0x86,
		(byte)0x4c, (byte)0x1e, (byte)0xfa, (byte)0xbb, (byte)0x49, (byte)0x57, (byte)0xd6, (byte)0x4b
	};
	private static final byte[] KMAC2 = new byte[] {
		(byte)0x16, (byte)0x65, (byte)0xa3, (byte)0xad, (byte)0xcb, (byte)0x57, (byte)0x90, (byte)0x53,
		(byte)0xcc, (byte)0x5d, (byte)0x90, (byte)0x87, (byte)0x20, (byte)0xce, (byte)0x4d, (byte)0xc1
	};
	private static final byte[] SSC2 = new byte[] {
		(byte)0x3d, (byte)0xe0, (byte)0xc9, (byte)0x65, (byte)0x8f, (byte)0x83, (byte)0x68, (byte)0x88,
		(byte)0xbd, (byte)0x35, (byte)0x2d, (byte)0xbf, (byte)0x46, (byte)0x46, (byte)0x2f, (byte)0x60
	};

	/** Prueba de cifrado 3DES de APDU.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testEncryptionAes() throws Exception {
		final CommandApdu apdu = new CommandApdu(
			(byte)0x00,
			(byte)0xa4,
			(byte)0x04,
			(byte)0x00,
			new byte[] {
				(byte)0x4d, (byte)0x61, (byte)0x73, (byte)0x74, (byte)0x65, (byte)0x72, (byte)0x2e,
				(byte)0x46, (byte)0x69, (byte)0x6c, (byte)0x65
			},
			null
		);
		Assert.assertEquals(
			"00a404000b4d61737465722e46696c65", //$NON-NLS-1$
			HexUtils.hexify(apdu.getBytes(), false).toLowerCase()
		);
		final byte[] paddedData = addPadding7816(apdu.getData());
		Assert.assertEquals(
			"4d61737465722e46696c658000000000", //$NON-NLS-1$
			HexUtils.hexify(paddedData, false).toLowerCase()
		);
		final CryptoHelper cryptoHelper = new JseCryptoHelper();

		final byte[] iv = cryptoHelper.aesEncrypt(
			SSC2,
			new byte[0],
			KENC2
		);

		System.out.println(HexUtils.hexify(iv, false).toLowerCase());
		System.out.println();

		final byte[] encryptedApdu = cryptoHelper.aesEncrypt(
			paddedData,
			iv,
			KENC2
		);

		System.out.println("f5124ee2f53962e86e66a6d234827f0f"); //$NON-NLS-1$
		System.out.println(HexUtils.hexify(encryptedApdu, false).toLowerCase());
	}



	/** Prueba de cifrado 3DES de APDU de verificaci&oacute;n de PIN.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testPinEncryptionDes() throws Exception {
		final CommandApdu verifyCommandApdu = new VerifyApduCommand(
			(byte) 0x00,
			new CachePasswordCallback("CRYPTOKI".toCharArray()) //$NON-NLS-1$
		);
		final ApduEncrypter apduEncrypterDes = new ApduEncrypterDes();
		final byte[] res = apduEncrypterDes.protectAPDU(
			verifyCommandApdu,
			KENC,
			KMAC,
			SSC_PIN,
			new JseCryptoHelper()
		).getBytes();
		Assert.assertEquals(
			"0c20000019871101ce1ab937c332f3faee43336d4311ef338e046908df4e", //$NON-NLS-1$
			HexUtils.hexify(res, false).toLowerCase()
		);
	}

	/** Prueba de cifrado 3DES de APDU.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testEncryptionDes() throws Exception {
		final ApduEncrypter apduEncrypterDes = new ApduEncrypterDes();
		final CipheredApdu a = apduEncrypterDes.protectAPDU(
			new CommandApdu(
				(byte)0x00,
				(byte)0xA4,
				(byte)0x04,
				(byte)0x00,
				new byte[] {
					(byte)0x4d, (byte)0x61, (byte)0x73, (byte)0x74, (byte)0x65, (byte)0x72, (byte)0x2e,
					(byte)0x46, (byte)0x69, (byte)0x6c, (byte)0x65
				},
				null
			),
			KENC,
			KMAC,
			SSC_SIMPLE,
			new JseCryptoHelper()
		);
		Assert.assertEquals(
			"0ca40400198711013e9ac315a8e855dd3722f291078ac2bd8e04b6f56963", //$NON-NLS-1$
			HexUtils.hexify(a.getBytes(), false).toLowerCase()
		);
	}


	@Override
	protected byte[] encryptData(final byte[] data, final byte[] key, final byte[] ssc, final CryptoHelper cryptoHelper) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	protected byte[] generateMac(final byte[] dataPadded, final byte[] ssc, final byte[] kMac, final CryptoHelper cryptoHelper) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	ResponseApdu decryptResponseApdu(final ResponseApdu responseApdu, final byte[] keyCipher, final byte[] ssc, final byte[] kMac, final CryptoHelper cryptoHelper) throws IOException {
		throw new UnsupportedOperationException();
	}

}
