package es.gob.jmulticard;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;

import es.gob.jmulticard.jse.provider.DnieProvider;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas del proveedor JSE para DNIe 100% Java.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestJseProvider {

	/** Main.
	 * @param args
	 * @throws Exception */
	public static void main(final String[] args) throws Exception {
		TestJseProvider.testProviderWithCustomConnection();
	}

	static void testProviderWithCustomConnection() throws Exception {
		final Provider p = new DnieProvider(new SmartcardIoConnection());
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("DNI"); //$NON-NLS-1$
		ks.load(null, "rock2048".toCharArray()); //$NON-NLS-1$
		final Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			System.out.println(aliases.nextElement());
		}
	}

}
