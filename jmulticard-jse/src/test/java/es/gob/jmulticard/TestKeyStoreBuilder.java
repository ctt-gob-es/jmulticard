package es.gob.jmulticard;

import java.security.KeyStore;

import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.jse.provider.DnieProvider;

/** Pruebas de construcci&oacute;n de KeyStore mediante <code>KeyStore.Builder</code>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestKeyStoreBuilder {

	/** Prueba de construcci&oacute;n de KeyStore mediante <code>KeyStore.Builder</code>.
	 * @throws Exception En cualquier error.*/
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testKeyStoreBuilderCreation() throws Exception {
		final KeyStore.Builder builder = KeyStore.Builder.newInstance(
			"DNI", //$NON-NLS-1$
			new DnieProvider(),
			new KeyStore.CallbackHandlerProtection(
				new TestingDnieCallbackHandler("can", "pin") //$NON-NLS-1$ //$NON-NLS-2$
			)
		);
		final KeyStore ks = builder.getKeyStore();
		System.out.println("Numero de certificados: " + ks.size()); //$NON-NLS-1$
		System.out.println(ks.getCertificate(ks.aliases().nextElement()));
	}

}
