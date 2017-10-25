package es.gob.jmulticard;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

import javax.security.auth.callback.PasswordCallback;

import org.junit.Assert;
import org.junit.Test;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECPrivateKeySpec;

import es.gob.jmulticard.CryptoHelper.EcCurve;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.jse.provider.JseCryptoHelper;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** pruebas de PACE con DNIe 3.0.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestPaceDnie {

	final static class CachePasswordCallback extends PasswordCallback {

	    private static final long serialVersionUID = 816457144215238935L;

	    /** Contruye una Callback con una contrase&ntilde; preestablecida.
	     * @param password Contrase&ntilde;a por defecto. */
	    public CachePasswordCallback(final char[] password) {
	        super(">", false); //$NON-NLS-1$
	        setPassword(password);
	    }
	}

	/** Main.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final ApduConnection conn = new SmartcardIoConnection();
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
	public void testAesDec() throws Exception {
		final byte[] nonce = new byte[] {
			(byte)0x39, (byte)0xe9, (byte)0x79, (byte)0xea, (byte)0x2c, (byte)0x87, (byte)0x25, (byte)0x4d,
			(byte)0x98, (byte)0x86, (byte)0x1b, (byte)0x09, (byte)0x34, (byte)0x52, (byte)0x23, (byte)0xb4
		};
		final byte[] sk = new byte[] {
			(byte)0x59, (byte)0x14, (byte)0x68, (byte)0xcd, (byte)0xa8, (byte)0x3d, (byte)0x65, (byte)0x21,
			(byte)0x9c, (byte)0xcc, (byte)0xb8, (byte)0x56, (byte)0x02, (byte)0x33, (byte)0x60, (byte)0x0f
		};
		Assert.assertEquals(
			"10EA7515CF362555AB77B7DCE0384E89", //$NON-NLS-1$
			HexUtils.hexify(
				new JseCryptoHelper().aesDecrypt(nonce, new byte[0], sk),
				false
			)
		);
	}

	/** Prueba de DH-EC seg&uacute;n valores del manual.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testDhEc() throws Exception {
		final byte[] prkIfcDh1 = new byte[] {
			(byte)0x04,
			(byte)0x93, (byte)0x6a, (byte)0x1f, (byte)0x95, (byte)0xb4, (byte)0x0e, (byte)0x4a, (byte)0xf3,
			(byte)0xa2, (byte)0xb2, (byte)0xef, (byte)0x44, (byte)0xf2, (byte)0x31, (byte)0x09, (byte)0x50,
			(byte)0x8c, (byte)0x7f, (byte)0x77, (byte)0x81, (byte)0xef, (byte)0x05, (byte)0xc8, (byte)0xf2,
			(byte)0xf8, (byte)0x80, (byte)0xde, (byte)0x42, (byte)0xfa, (byte)0xb9, (byte)0xfb, (byte)0xa0,
			(byte)0x1d, (byte)0x17, (byte)0xd9, (byte)0xef, (byte)0x41, (byte)0x73, (byte)0xb6, (byte)0xc1,
			(byte)0xe6, (byte)0x23, (byte)0x01, (byte)0x9f, (byte)0x6f, (byte)0xd8, (byte)0x08, (byte)0x0b,
			(byte)0xc9, (byte)0xdf, (byte)0x0f, (byte)0x71, (byte)0xbc, (byte)0xe1, (byte)0x8d, (byte)0x46,
			(byte)0xb7, (byte)0x00, (byte)0xd0, (byte)0x5e, (byte)0x64, (byte)0x89, (byte)0x10, (byte)0xec
		};
		final byte[] pukIccDh1 = new byte[] {
			(byte)0x04,
			(byte)0x64, (byte)0x44, (byte)0x87, (byte)0x06, (byte)0x4b, (byte)0x4b, (byte)0x21, (byte)0x21,
			(byte)0xd8, (byte)0xc7, (byte)0xe2, (byte)0x2b, (byte)0x27, (byte)0x8b, (byte)0x19, (byte)0x14,
			(byte)0x33, (byte)0x51, (byte)0xe0, (byte)0xa7, (byte)0x4a, (byte)0x99, (byte)0xe9, (byte)0x8f,
			(byte)0xc7, (byte)0x60, (byte)0xad, (byte)0x0a, (byte)0xc9, (byte)0x00, (byte)0xbc, (byte)0x27,
			(byte)0x88, (byte)0x3e, (byte)0x8e, (byte)0xa2, (byte)0xef, (byte)0xcb, (byte)0xf3, (byte)0x02,
			(byte)0xdc, (byte)0x7d, (byte)0x6a, (byte)0xcf, (byte)0x5d, (byte)0x6a, (byte)0xdc, (byte)0xd4,
			(byte)0x64, (byte)0xbd, (byte)0x18, (byte)0x85, (byte)0xe6, (byte)0xe6, (byte)0x4f, (byte)0xf9,
			(byte)0x45, (byte)0xe1, (byte)0xe8, (byte)0xb8, (byte)0x84, (byte)0x61, (byte)0x99, (byte)0xf7
		};
		final byte[] res = new JseCryptoHelper().doEcDh(
			loadEcPrivateKey(prkIfcDh1, EcCurve.BRAINPOOL_P256_R1),
			pukIccDh1,
			EcCurve.BRAINPOOL_P256_R1
		);
		System.out.println(
			HexUtils.hexify(
				res,
				false
			)
		);
		System.out.println("Len: " + res.length); //$NON-NLS-1$

	}

	private static Key loadEcPrivateKey(final byte [] data, final EcCurve curveName) throws NoSuchAlgorithmException,
                                                                                            InvalidKeySpecException {
		Security.addProvider(new BouncyCastleProvider());
		final ECParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName.toString());
		final ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME); //$NON-NLS-1$
		}
		catch (final NoSuchProviderException e) {
			Logger.getLogger("es.gob.afirma").warning( //$NON-NLS-1$
				"No esta instalado el proveedor BouncyCastle / SpongyCastle: " + e //$NON-NLS-1$
			);
			kf = KeyFactory.getInstance("ECDH"); //$NON-NLS-1$
		}
		return kf.generatePrivate(prvkey);
	}

}
