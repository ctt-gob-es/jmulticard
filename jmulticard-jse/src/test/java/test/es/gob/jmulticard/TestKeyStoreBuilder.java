package test.es.gob.jmulticard;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.jse.provider.DnieProvider;

/** Pruebas de construcci&oacute;n de KeyStore mediante <code>KeyStore.Builder</code>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestKeyStoreBuilder {

	/** Alias del certificado de autenticaci&oacute;n del DNIe (siempre el mismo en el DNIe y tarjetas derivadas). */
	private static final String CERT_ALIAS_AUTH = "CertAutenticacion"; //$NON-NLS-1$

	/** Prueba de construcci&oacute;n de KeyStore mediante <code>KeyStore.Builder</code>.
	 * @throws Exception En cualquier error.*/
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testKeyStoreBuilderCreation() throws Exception {

		final Provider p = new DnieProvider();
		Security.addProvider(p);

		try {
			final KeyStore.Builder builder = KeyStore.Builder.newInstance(
				"DNI", //$NON-NLS-1$
				p,
				new KeyStore.CallbackHandlerProtection(
					new TestingDnieCallbackHandler("630208", "WJ8d6EzzxDkz") //$NON-NLS-1$ //$NON-NLS-2$
				)
			);
			final KeyStore ks = builder.getKeyStore();
			System.out.println("Numero de certificados: " + ks.size()); //$NON-NLS-1$
			System.out.println(ks.getCertificate(ks.aliases().nextElement()));

			final Signature sig = Signature.getInstance("SHA512withRSA", p); //$NON-NLS-1$
			sig.initSign((PrivateKey) ks.getKey(CERT_ALIAS_AUTH, null));
			sig.update("kaka".getBytes()); //$NON-NLS-1$
			final byte[] res = sig.sign();
			System.out.println(HexUtils.hexify(res, false));
		}
		catch (final Exception e) {
			e.printStackTrace();
			Assertions.fail();
			return;
		}
	}
}
