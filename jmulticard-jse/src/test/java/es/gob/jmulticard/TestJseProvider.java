package es.gob.jmulticard;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Enumeration;

import es.gob.jmulticard.jse.provider.DnieProvider;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas del proveedor JSE para DNIe 100% Java.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestJseProvider {

	private static final char[] PASSWORD = null;
	
	/** Main.
	 * @param args
	 * @throws Exception */
	public static void main(final String[] args) throws Exception {
		TestJseProvider.testProviderWithCustomConnection();
		TestJseProvider.testProviderWithDefaultConnection();
	}

	static void testProviderWithCustomConnection() throws Exception {
		final Provider p = new DnieProvider(new SmartcardIoConnection());
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("DNI"); //$NON-NLS-1$
		ks.load(null, PASSWORD); //$NON-NLS-1$
		final Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			System.out.println(aliases.nextElement());
		}
		
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign((PrivateKey) ks.getKey("CertFirmaDigital", PASSWORD));
		signature.update("Hola Mundo!!".getBytes());
		signature.sign();
		
		System.out.println("Firma generada correctamente");
	}

	static void testProviderWithDefaultConnection() throws Exception {
		final Provider p = new DnieProvider();
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("DNI"); //$NON-NLS-1$
		ks.load(null, PASSWORD); //$NON-NLS-1$
		final Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			System.out.println(aliases.nextElement());
		}
		
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign((PrivateKey) ks.getKey("CertFirmaDigital", PASSWORD));
		signature.update("Hola Mundo!!".getBytes());
		signature.sign();
		
		System.out.println("Firma generada correctamente");
	}
}
