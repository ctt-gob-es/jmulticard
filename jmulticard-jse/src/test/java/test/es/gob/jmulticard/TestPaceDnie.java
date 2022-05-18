package test.es.gob.jmulticard;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.CryptoHelper.BlockMode;
import es.gob.jmulticard.CryptoHelper.Padding;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.jse.provider.CachePasswordCallback;
import es.gob.jmulticard.jse.provider.ProviderUtil;

/** pruebas de PACE con DNIe 3&#46;0.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestPaceDnie {

	/** Main.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final ApduConnection conn = ProviderUtil.getDefaultConnection();
		final CachePasswordCallback cpc = new CachePasswordCallback("password".toCharArray()); //$NON-NLS-1$
		final Dnie dni = DnieFactory.getDnie(
			conn,
			cpc,
			new JseCryptoHelper(),
			null
		);
		System.out.println("Canal PACE abierto"); //$NON-NLS-1$
		dni.changePIN("password", "1234512345"); //$NON-NLS-1$ //$NON-NLS-2$
		System.out.println("Se ha realizado el cambio de PIN correctamente"); //$NON-NLS-1$
	}

	/** Prueba de cifrado AES seg&uacute;n valores del manual.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testAesDec() throws Exception {
		final byte[] nonce = {
			(byte)0x39, (byte)0xe9, (byte)0x79, (byte)0xea, (byte)0x2c, (byte)0x87, (byte)0x25, (byte)0x4d,
			(byte)0x98, (byte)0x86, (byte)0x1b, (byte)0x09, (byte)0x34, (byte)0x52, (byte)0x23, (byte)0xb4
		};
		final byte[] sk = {
			(byte)0x59, (byte)0x14, (byte)0x68, (byte)0xcd, (byte)0xa8, (byte)0x3d, (byte)0x65, (byte)0x21,
			(byte)0x9c, (byte)0xcc, (byte)0xb8, (byte)0x56, (byte)0x02, (byte)0x33, (byte)0x60, (byte)0x0f
		};
		Assert.assertEquals(
			"10EA7515CF362555AB77B7DCE0384E89", //$NON-NLS-1$
			HexUtils.hexify(
				new JseCryptoHelper().aesDecrypt(
					nonce,
					new byte[0],
					sk,
					BlockMode.CBC,
					Padding.NOPADDING // Sin relleno
				),
				false
			)
		);
	}

}
