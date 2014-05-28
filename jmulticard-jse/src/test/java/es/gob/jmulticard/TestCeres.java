package es.gob.jmulticard;

import java.util.Arrays;

import es.gob.jmulticard.card.fnmt.ceres.Ceres;
import es.gob.jmulticard.jse.provider.JseCryptoHelper;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de FNMT-CERES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestCeres {

	/** Main.
	 * @param args
	 * @throws Exception */
	public static void main(final String[] args) throws Exception {
		final Ceres ceres = new Ceres(
			new SmartcardIoConnection(),
			new JseCryptoHelper()
		);
		System.out.println(ceres.getCardName());
		System.out.println(Arrays.asList(ceres.getAliases()));
		System.out.println(ceres.getPrivateKey(ceres.getAliases()[0]));
		ceres.verifyPin(new CachePasswordCallback("PIN".toCharArray())); //$NON-NLS-1$
		System.out.println(HexUtils.hexify(
			ceres.sign("hola".getBytes(), "SHA512withRSA", null),  //$NON-NLS-1$//$NON-NLS-2$
			true
		));
	}

}
