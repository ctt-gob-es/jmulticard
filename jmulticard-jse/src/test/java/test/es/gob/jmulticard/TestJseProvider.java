package test.es.gob.jmulticard;

import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import javax.security.auth.callback.CallbackHandler;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.jse.provider.DnieProvider;
import es.gob.jmulticard.jse.provider.ProviderUtil;

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

	/** Prueba el proveedor indicando manualmente la conexi&oacute;n.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testProviderWithCustomConnection() throws Exception {
		final Provider p = new DnieProvider(ProviderUtil.getDefaultConnection());
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("DNI"); //$NON-NLS-1$
    	final CallbackHandler callbackHandler = (CallbackHandler) Class.forName(
			"test.es.gob.jmulticard.ui.passwordcallback.gui.DnieCacheCallbackHandler" //$NON-NLS-1$
		).getConstructor().newInstance();
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

	private static void testProviderWithDefaultConnection() throws Exception {
		final Provider p = new DnieProvider();
		Security.addProvider(p);
		final KeyStore ks = KeyStore.getInstance("DNI"); //$NON-NLS-1$
		final CallbackHandler callbackHandler;
    	callbackHandler = (CallbackHandler) Class.forName(
			"test.es.gob.jmulticard.ui.passwordcallback.gui.DnieCacheCallbackHandler" //$NON-NLS-1$
		).getConstructor().newInstance();
		final LoadStoreParameter lsp = new LoadStoreParameter() {
			@Override
			public ProtectionParameter getProtectionParameter() {
				return new KeyStore.CallbackHandlerProtection(callbackHandler);
			}
		};
		ks.load(lsp);
		final Enumeration<String> aliases = ks.aliases();
		String alias = null;
		while (aliases.hasMoreElements()) {
			alias = aliases.nextElement();
			System.out.println(alias);
		}

		Assert.assertNotNull("La tarjeta debe tener al menos un certificado", alias); //$NON-NLS-1$

		Signature signature = Signature.getInstance("SHA1withRSA"); //$NON-NLS-1$
		signature.initSign((PrivateKey) ks.getKey(alias, null));
		signature.update("Hola Mundo!!".getBytes()); //$NON-NLS-1$
		byte[] signBytes = signature.sign();

		System.out.println("Firma generada correctamente: " + HexUtils.hexify(signBytes, false)); //$NON-NLS-1$

		System.out.println(
			((X509Certificate)ks.getCertificate(alias)).getIssuerX500Principal().toString()
		);

		signature = Signature.getInstance("SHA1withRSA"); //$NON-NLS-1$
		signature.initSign((PrivateKey) ks.getKey(alias, null));
		signature.update("Hola Mundo!!".getBytes()); //$NON-NLS-1$
		signBytes = signature.sign();

		System.out.println("Firma generada correctamente: " + HexUtils.hexify(signBytes, false)); //$NON-NLS-1$
	}

	/** Prueba de obtenci&oacute;n de la cadena de certificados.
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

	private static final List<String> FORBIDDEN_PROVIDERS = Arrays.asList("Ceres430JCAProvider", "SunMSCAPI"); //$NON-NLS-1$ //$NON-NLS-2$

	/** Prueba la b&uacute;squeda de proveedor de firma alternativo. */
	@SuppressWarnings("static-method")
	@Test
	public void listP() {
		final String serviceName = "Signature"; //$NON-NLS-1$
		final String serviceAlgorithm = "SHA512withRSA"; //$NON-NLS-1$

		final Provider[] providerList = Security.getProviders();
		for (final Provider provider : providerList) {
			final Set<Service> serviceList = provider.getServices();
			for (final Service service : serviceList) {
				if (serviceName.equals(service.getType()) && serviceAlgorithm.equals(service.getAlgorithm())) {
					final String providerName = provider.getName();
					if (!FORBIDDEN_PROVIDERS.contains(providerName) && !providerName.contains("PKCS11")) { //$NON-NLS-1$
						System.out.println(
							providerName
						);
					}
				}
			}
		}
	}
}
