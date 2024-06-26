package test.es.gob.jmulticard;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.crypto.BcCryptoHelper;
import es.gob.jmulticard.jse.provider.DnieProvider;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de firma en tarjeta CERES v4.30. */
final class TestCeres430Signature {

	private static final String PROVIDER_NAME = "DNI"; //$NON-NLS-1$
	private static final String ALGORITHM = "SHA256withRSA"; //$NON-NLS-1$
	private static final byte[] DATA = "Datos a firmar".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
//	private static final char[] PIN = "eJh3Rhbf".toCharArray(); //$NON-NLS-1$
//	private static final char[] PIN = "CRYPTOKIFNMT".toCharArray(); //$NON-NLS-1$
	private static final char[] PIN = "12341234".toCharArray(); //$NON-NLS-1$

	/** Prueba de firmas consecutivas. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testSignRepeatedly() {
		try {
	    	Security.addProvider(new DnieProvider());

	    	final KeyStore ks = KeyStore.getInstance(PROVIDER_NAME);
	    	ks.load(null, PIN);

	    	final Enumeration<String> aliases = ks.aliases();
	    	String alias = null;
	    	while (aliases.hasMoreElements()) {
	    		alias = aliases.nextElement();
	    		System.out.println("ALIAS: " + alias); //$NON-NLS-1$
	    		System.out.println("CERTIFICADO: " + ((X509Certificate)ks.getCertificate(alias)).getSubjectX500Principal()); //$NON-NLS-1$
	    		System.out.println("CLAVE PRIVADA: " + ks.getEntry(alias, null).getClass().getName()); //$NON-NLS-1$
	    		System.out.println();
	    	}

	    	if (alias == null) {
	    		System.out.println("La tarjeta no tiene entradas"); //$NON-NLS-1$
	    		return;
	    	}

	    	System.out.println("Se firma en CERES 4.30 con el alias '" + alias + "'"); //$NON-NLS-1$ //$NON-NLS-2$
	    	System.out.println();
	    	System.out.println(ks.getCertificate(alias));
	    	final PrivateKey sKey = (PrivateKey) ks.getKey(alias, PIN);

	    	final Signature signature1 = Signature.getInstance(ALGORITHM);
	    	signature1.initSign(sKey);
	    	signature1.update(DATA);
	    	System.out.println( "Firma 1: " + Base64.toBase64String(signature1.sign())); //$NON-NLS-1$

	    	final Signature signature2 = Signature.getInstance(ALGORITHM);
	    	signature2.initSign(sKey);
	    	signature2.update(DATA);
	    	System.out.println( "Firma 2: " + Base64.toBase64String(signature2.sign())); //$NON-NLS-1$
		}
		catch(final Exception e) {
			e.printStackTrace();
			Assertions.fail();
		}
	}

	/** Pruebas generales de tarjeta FNMT CERES. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void TestCeresScLow() {
		try  {
			final Dnie ceres = DnieFactory.getDnie(
				new SmartcardIoConnection(),
				null, // PasswordCallback
				new BcCryptoHelper(),
				new TestingDnieCallbackHandler(null, PIN),
				false
			);
			System.out.println(ceres);
		}
		catch(final Exception e) {
			e.printStackTrace();
			Assertions.fail();
		}
	}
}
