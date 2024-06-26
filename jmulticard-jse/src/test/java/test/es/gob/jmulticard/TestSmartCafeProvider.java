package test.es.gob.jmulticard;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.jse.provider.gide.SmartCafeProvider;

/** Pruebas del proveedor JSE para tarjeta G&amp;D SmartCafe con Applet PKCS#15.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestSmartCafeProvider {

	/** Main.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final Provider p = new SmartCafeProvider();
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("GDSCPKCS15"); //$NON-NLS-1$
		final char[] pin = new TestingUiPasswordCallback(
			"PIN de la tarjeta SmartCafe", //$NON-NLS-1$
			null,
			"Introduzca el PIN de la tarjeta SmartCafe", //$NON-NLS-1$
			"PIN G&D SmartCafe" //$NON-NLS-1$
		).getPassword();
		ks.load(null, pin);
		final Enumeration<String> aliases = ks.aliases();
		String alias = null;
		System.out.println("Encontrados los siguientes certificados:"); //$NON-NLS-1$
		while (aliases.hasMoreElements()) {
			alias = aliases.nextElement();
			System.out.println(
				((X509Certificate) ks.getCertificate(alias)).getSubjectX500Principal()
			);
		}
		System.out.println();
		System.out.println("Se hara una firma de prueba con '" + ((X509Certificate) ks.getCertificate(alias)).getSubjectX500Principal() + "'"); //$NON-NLS-1$ //$NON-NLS-2$
		final Signature signature = Signature.getInstance("SHA1withRSA"); //$NON-NLS-1$
		signature.initSign((PrivateKey) ks.getKey(alias, pin));
		signature.update("Hola Mundo!!".getBytes()); //$NON-NLS-1$
		final byte[] sign = signature.sign();

		System.out.println("Firma generada correctamente:"); //$NON-NLS-1$
		System.out.println(HexUtils.hexify(sign, true));
	}
}
