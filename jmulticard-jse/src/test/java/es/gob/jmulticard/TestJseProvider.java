package es.gob.jmulticard;

import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.security.auth.callback.CallbackHandler;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.jse.provider.DnieProvider;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas del proveedor JSE para DNIe 100% Java.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestJseProvider {

	private static final char[] PASSWORD = "12341234".toCharArray(); //$NON-NLS-1$

	/** Main.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		//TestJseProvider.testProviderWithCustomConnection();
		TestJseProvider.testProviderWithDefaultConnection();
	}

	static void testProviderWithCustomConnection() throws Exception {
		final Provider p = new DnieProvider(new SmartcardIoConnection());
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("DNI"); //$NON-NLS-1$
    	final CallbackHandler callbackHandler;
    	callbackHandler = (CallbackHandler) Class.forName("es.gob.jmulticard.ui.passwordcallback.gui.DnieCallbackHandler").getConstructor().newInstance(); //$NON-NLS-1$
		final LoadStoreParameter lsp = new LoadStoreParameter() {
			@Override
			public ProtectionParameter getProtectionParameter() {
				return new KeyStore.CallbackHandlerProtection(callbackHandler);
			}
		};
		ks.load(lsp);
		final Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			System.out.println(aliases.nextElement());
		}

		final Signature signature = Signature.getInstance("SHA1withRSA"); //$NON-NLS-1$
		signature.initSign((PrivateKey) ks.getKey("CertFirmaDigital", PASSWORD)); //$NON-NLS-1$
		signature.update("Hola Mundo!!".getBytes()); //$NON-NLS-1$
		signature.sign();

		System.out.println("Firma generada correctamente"); //$NON-NLS-1$
	}

	static void testProviderWithDefaultConnection() throws Exception {
		final Provider p = new DnieProvider();
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("DNI"); //$NON-NLS-1$
		ks.load(null, PASSWORD);
		final Enumeration<String> aliases = ks.aliases();
		String alias = null;
		while (aliases.hasMoreElements()) {
			alias = aliases.nextElement();
			System.out.println(alias);
		}

		Assert.assertNotNull("La tarjeta debe tener al menos un certificado", alias); //$NON-NLS-1$

		final Signature signature = Signature.getInstance("SHA1withRSA"); //$NON-NLS-1$
		signature.initSign((PrivateKey) ks.getKey(alias, PASSWORD));
		signature.update("Hola Mundo!!".getBytes()); //$NON-NLS-1$
		signature.sign();

		System.out.println("Firma generada correctamente"); //$NON-NLS-1$

		System.out.println(
			((X509Certificate)ks.getCertificate(alias)).getIssuerX500Principal().toString()
		);
	}

	/** prueba de obtenci&oacute;n de la cadena de certificados.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testGetCertificateChain() throws Exception {
		final Provider p = new DnieProvider();
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("DNI"); //$NON-NLS-1$
		ks.load(null, PASSWORD);
		final Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			final String alias = aliases.nextElement();
			for (final Certificate cert : ks.getCertificateChain(alias)) {
				System.out.println(
					"XXX: " + ((X509Certificate)cert).getSubjectX500Principal() //$NON-NLS-1$
				);
			}
		}
	}
}
