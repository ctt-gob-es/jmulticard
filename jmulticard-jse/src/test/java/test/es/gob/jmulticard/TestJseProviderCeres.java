package test.es.gob.jmulticard;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.jse.provider.ProviderUtil;
import es.gob.jmulticard.jse.provider.ceres.CeresProvider;

/** Pruebas del proveedor JSE para tarjeta CERES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestJseProviderCeres {

	private static final char[] PASSWORD = "eJh3Rhbf".toCharArray(); //$NON-NLS-1$

	/** Main.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		//TestJseProviderCeres.testProviderWithCustomConnection();
		//TestJseProviderCeres.testProviderWithDefaultConnection();
		final Provider p = new CeresProvider();
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("CERES"); //$NON-NLS-1$
		final char[] pin = new UIPasswordCallback(
			"PIN de la tarjeta CERES", //$NON-NLS-1$
			null,
			"Introduzca el PIN de la tarjeta CERES", //$NON-NLS-1$
			"PIN FNMT-RCM-CERES" //$NON-NLS-1$
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

	static void testProviderWithCustomConnection() throws Exception {
		final Provider p = new CeresProvider(ProviderUtil.getDefaultConnection());
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("CERES"); //$NON-NLS-1$
		ks.load(null, PASSWORD);
		final Enumeration<String> aliases = ks.aliases();
		String alias = null;
		while (aliases.hasMoreElements()) {
			alias = aliases.nextElement();
			System.out.println(alias);
		}

		final Signature signature = Signature.getInstance("SHA1withRSA"); //$NON-NLS-1$
		signature.initSign((PrivateKey) ks.getKey(alias, PASSWORD));
		signature.update("Hola Mundo!!".getBytes()); //$NON-NLS-1$
		signature.sign();

		System.out.println("Firma generada correctamente"); //$NON-NLS-1$
	}

	static void testProviderWithDefaultConnection() throws Exception {
		final Provider p = new CeresProvider();
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("CERES"); //$NON-NLS-1$
		ks.load(null, PASSWORD);
		final Enumeration<String> aliases = ks.aliases();
		String alias = null;
		while (aliases.hasMoreElements()) {
			alias = aliases.nextElement();
			System.out.println(alias);
		}

		final Signature signature = Signature.getInstance("SHA1withRSA"); //$NON-NLS-1$
		signature.initSign((PrivateKey) ks.getKey(alias, PASSWORD));
		signature.update("Hola Mundo!!".getBytes()); //$NON-NLS-1$
		signature.sign();

		System.out.println("Firma generada correctamente"); //$NON-NLS-1$

		System.out.println(
			((X509Certificate)ks.getCertificate(alias)).getIssuerX500Principal().toString()
		);
	}

}
