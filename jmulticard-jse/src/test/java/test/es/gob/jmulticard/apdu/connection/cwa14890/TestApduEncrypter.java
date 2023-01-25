package test.es.gob.jmulticard.apdu.connection.cwa14890;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import es.gob.jmulticard.BcCryptoHelper;
import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.CryptoHelper.BlockMode;
import es.gob.jmulticard.CryptoHelper.Padding;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.dnie.VerifyApduCommand;
import es.gob.jmulticard.connection.AbstractApduEncrypter;
import es.gob.jmulticard.connection.ApduEncrypterAes;
import es.gob.jmulticard.connection.ApduEncrypterDes;
import es.gob.jmulticard.connection.CipheredApdu;

/** Pruebas del cifrado de APDU seg&uacute;n CWA-14890.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestApduEncrypter extends AbstractApduEncrypter {

	private static final CryptoHelper CRYPTO_HELPER = new BcCryptoHelper();

	private static final byte[] KENC = {
		(byte)0x59, (byte)0x8f, (byte)0x26, (byte)0xe3, (byte)0x6e, (byte)0x11, (byte)0xa8, (byte)0xec,
		(byte)0x14, (byte)0xb8, (byte)0x1e, (byte)0x19, (byte)0xbd, (byte)0xa2, (byte)0x23, (byte)0xca
	};
	private static final byte[] KMAC = {
		(byte)0x5d, (byte)0xe2, (byte)0x93, (byte)0x9a, (byte)0x1e, (byte)0xa0, (byte)0x3a, (byte)0x93,
		(byte)0x0b, (byte)0x88, (byte)0x20, (byte)0x6d, (byte)0x8f, (byte)0x73, (byte)0xe8, (byte)0xa7
	};
	private static final byte[] SSC_SIMPLE = {
		(byte)0xd3, (byte)0x1a, (byte)0xc8, (byte)0xec, (byte)0x7b, (byte)0xa0, (byte)0xfe, (byte)0x75
	};

	private static final byte[] SSC_PIN = {
		(byte)0xd3, (byte)0x1a, (byte)0xc8, (byte)0xec, (byte)0x7b, (byte)0xa0, (byte)0xfe, (byte)0x6f
	};


	private static final byte[] KENC2 = {
		(byte)0xf1, (byte)0xb0, (byte)0xd6, (byte)0x44, (byte)0x9c, (byte)0xec, (byte)0x48, (byte)0x86,
		(byte)0x4c, (byte)0x1e, (byte)0xfa, (byte)0xbb, (byte)0x49, (byte)0x57, (byte)0xd6, (byte)0x4b
	};
	private static final byte[] KMAC2 = {
		(byte)0x16, (byte)0x65, (byte)0xa3, (byte)0xad, (byte)0xcb, (byte)0x57, (byte)0x90, (byte)0x53,
		(byte)0xcc, (byte)0x5d, (byte)0x90, (byte)0x87, (byte)0x20, (byte)0xce, (byte)0x4d, (byte)0xc1
	};
	private static final byte[] SSC2 = {
		(byte)0x3d, (byte)0xe0, (byte)0xc9, (byte)0x65, (byte)0x8f, (byte)0x83, (byte)0x68, (byte)0x88,
		(byte)0xbd, (byte)0x35, (byte)0x2d, (byte)0xbf, (byte)0x46, (byte)0x46, (byte)0x2f, (byte)0x60
	};

	/** Prueba la generaci&oacute;n de CMAC con datos dependientes del SSC.
	 * @throws IOException En cualquier error. */
	@Test
	@Ignore // Necesita el proveedor BC/SC firmado
	public void testCMacGeneration() throws IOException {
		final byte[] data = {
			(byte)0x0c, (byte)0xa4, (byte)0x04, (byte)0x00, (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00,
			(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
			(byte)0x87, (byte)0x11, (byte)0x01, (byte)0xf5, (byte)0x12, (byte)0x4e, (byte)0xe2, (byte)0xf5,
			(byte)0x39, (byte)0x62, (byte)0xe8, (byte)0x6e, (byte)0x66, (byte)0xa6, (byte)0xd2, (byte)0x34,
			(byte)0x82, (byte)0x7f, (byte)0x0f, (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
			(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
		};
		Assert.assertEquals(
			"70e6de5f679aee64", //$NON-NLS-1$
			HexUtils.hexify(
				generateMac(data, SSC2, KMAC2, CRYPTO_HELPER),
				false
			).toLowerCase()
		);
	}

	/** Prueba de cifrado AES de una APDU.
	 * @throws Exception En cualquier error. */
	@Test
	@Ignore // Necesita el proveedor BC/SC firmado
	public void testEncryptionAes() throws Exception {

		paddingLength = 16;

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
		System.out.println(
			HexUtils.hexify(
				protectAPDU(
					apdu,
					KENC2,
					KMAC2,
					SSC2,
					CRYPTO_HELPER
				).getBytes(),
				false
			).toLowerCase()
		)
			;

		System.out.println(
				HexUtils.hexify(
					new ApduEncrypterAes().protectAPDU(
						apdu,
						KENC2,
						KMAC2,
						SSC2,
						CRYPTO_HELPER
					).getBytes(),
					false
				).toLowerCase()
			)
				;


		System.out.println("0ca404001d871101f5124ee2f53962e86e66a6d234827f0f8e0870e6de5f679aee64"); //$NON-NLS-1$
	}

	/** Prueba de cifrado AES del cuerpo de una APDU.
	 * @throws Exception En cualquier error. */
	@Test
	public void testPartialEncryptionAes() throws Exception {

		paddingLength = 16;

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
		final byte[] paddedData = addPadding7816(apdu.getData(), paddingLength);
		Assert.assertEquals(
			"4d61737465722e46696c658000000000", //$NON-NLS-1$
			HexUtils.hexify(paddedData, false).toLowerCase()
		);

		final byte[] encryptedApdu = encryptData(
			paddedData,
			KENC2,
			SSC2,
			CRYPTO_HELPER
		);
		Assert.assertEquals(
			"f5124ee2f53962e86e66a6d234827f0f", //$NON-NLS-1$
			HexUtils.hexify(encryptedApdu, false).toLowerCase()
		);

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
		final AbstractApduEncrypter apduEncrypterDes = new ApduEncrypterDes();
		final byte[] res = apduEncrypterDes.protectAPDU(
			verifyCommandApdu,
			KENC,
			KMAC,
			SSC_PIN,
			CRYPTO_HELPER
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
		final AbstractApduEncrypter apduEncrypterDes = new ApduEncrypterDes();
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
			CRYPTO_HELPER
		);
		Assert.assertEquals(
			"0ca40400198711013e9ac315a8e855dd3722f291078ac2bd8e04b6f56963", //$NON-NLS-1$
			HexUtils.hexify(a.getBytes(), false).toLowerCase()
		);
	}


	@Override
	protected byte[] encryptData(final byte[] data, final byte[] key, final byte[] ssc, final CryptoHelper cryptoHelper) throws IOException {
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
			key,
			BlockMode.CBC,
			Padding.NOPADDING // Sin relleno
		);
		return cryptoHelper.aesEncrypt(
			data,
			iv,
			key,
			BlockMode.CBC,
			Padding.NOPADDING // Sin relleno
		);
	}

	@Override
	protected byte[] generateMac(final byte[] dataPadded, final byte[] ssc, final byte[] kMac, final CryptoHelper cryptoHelper) throws IOException {
		final Mac eng;
		try {
			eng = Mac.getInstance("AESCMAC", new BouncyCastleProvider()); //$NON-NLS-1$
			eng.init(new SecretKeySpec(kMac, "AES")); //$NON-NLS-1$
		}
		catch(final InvalidKeyException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		final byte[] mac = eng.doFinal(HexUtils.concatenateByteArrays(ssc, dataPadded));
		final byte[] ret = new byte[8];
		System.arraycopy(mac, 0, ret, 0, 8);
		return ret;
	}

	@Override
	public ResponseApdu decryptResponseApdu(final ResponseApdu responseApdu, final byte[] keyCipher, final byte[] ssc, final byte[] kMac, final CryptoHelper cryptoHelper) {
		throw new UnsupportedOperationException();
	}

}
