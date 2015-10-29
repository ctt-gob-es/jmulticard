package es.gob.jmulticard.apdu.connection.cwa14890;

import junit.framework.Assert;

import org.junit.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;

/** Pruebas del cifrado de APDU seg&uacute;n CWA-14890.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestApduEncrypter {

	private static final byte[] KENC = new byte[] {
		(byte)0x59, (byte)0x8f, (byte)0x26, (byte)0xe3, (byte)0x6e, (byte)0x11, (byte)0xa8, (byte)0xec,
		(byte)0x14, (byte)0xb8, (byte)0x1e, (byte)0x19, (byte)0xbd, (byte)0xa2, (byte)0x23, (byte)0xca
	};

	private static final byte[] KMAC = new byte[] {
		(byte)0x5d, (byte)0xe2, (byte)0x93, (byte)0x9a, (byte)0x1e, (byte)0xa0, (byte)0x3a, (byte)0x93,
		(byte)0x0b, (byte)0x88, (byte)0x20, (byte)0x6d, (byte)0x8f, (byte)0x73, (byte)0xe8, (byte)0xa7
	};

	private static final byte[] SSC = new byte[] {
		(byte)0xd3, (byte)0x1a, (byte)0xc8, (byte)0xec, (byte)0x7b, (byte)0xa0, (byte)0xfe, (byte)0x75
	};

	/** Prueba de cifrado de APDU.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testEncryption() throws Exception {
		final CipheredApdu a = ApduEncrypter.protectAPDU(
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
			SSC,
			new JseCryptoHelper()
		);
		Assert.assertEquals(
			"0ca40400198711013e9ac315a8e855dd3722f291078ac2bd8e04b6f56963", //$NON-NLS-1$
			HexUtils.hexify(a.getBytes(), false).toLowerCase()
		);
	}

}
