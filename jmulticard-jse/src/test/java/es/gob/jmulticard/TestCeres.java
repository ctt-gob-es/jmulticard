package es.gob.jmulticard;

import java.util.Arrays;

import es.gob.jmulticard.TestTui.CachePasswordCallback;
import es.gob.jmulticard.card.PrivateKeyReference;
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
		System.out.println(ceres.getCertificate(ceres.getAliases()[0]));
		final PrivateKeyReference pkr = ceres.getPrivateKey(ceres.getAliases()[0]);
		ceres.verifyPin(new CachePasswordCallback("1234".toCharArray())); //$NON-NLS-1$
		System.out.println(
			HexUtils.hexify(
				ceres.sign("hola".getBytes(), "SHA1withRSA", pkr),  //$NON-NLS-1$//$NON-NLS-2$
				true
			)
		);

//		System.out.println(
//			HexUtils.hexify(
//				CryptoHelper.addPkcs1PaddingForPrivateKeyOperation(
//					DigestInfo.encode("SHA1withRSA", "HOLA".getBytes(), new JseCryptoHelper()), //$NON-NLS-1$ //$NON-NLS-2$
//					1024
//				),
//				true
//			)
//		);

	}

}