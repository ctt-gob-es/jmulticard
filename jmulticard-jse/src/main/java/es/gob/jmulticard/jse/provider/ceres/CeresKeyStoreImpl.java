package es.gob.jmulticard.jse.provider.ceres;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.x500.X500Principal;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.fnmt.ceres.Ceres;
import es.gob.jmulticard.card.fnmt.ceres.CeresPrivateKeyReference;
import es.gob.jmulticard.jse.provider.BadPasswordProviderException;
import es.gob.jmulticard.jse.provider.JseCryptoHelper;

/** Implementaci&oacute;n del SPI KeyStore para tarjeta FNMT-RCM-CERES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class CeresKeyStoreImpl extends KeyStoreSpi {

    private static List<String> userCertAliases = null;

    private Ceres cryptoCard = null;

    private void loadAliases() throws CryptoCardException {
    	final String[] aliases = this.cryptoCard.getAliases();
    	userCertAliases = new ArrayList<String>(aliases.length);
    	for (final String alias : aliases) {
    		userCertAliases.add(alias);
    	}
    }

    /** {@inheritDoc} */
    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(userCertAliases);
    }

    /** {@inheritDoc} */
    @Override
    public boolean engineContainsAlias(final String alias) {
        return userCertAliases.contains(alias);
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineDeleteEntry(final String alias) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    /** {@inheritDoc} */
    @Override
    public Certificate engineGetCertificate(final String alias) {
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}
        try {
			return this.cryptoCard.getCertificate(alias);
		}
        catch (final CryptoCardException e) {
			throw new ProviderException(e);
		}
        catch (final BadPinException e) {
			throw new BadPasswordProviderException(e);
		}
    }

    /** {@inheritDoc} */
    @Override
    public String engineGetCertificateAlias(final Certificate cert) {
        if (!(cert instanceof X509Certificate)) {
            return null;
        }
        final BigInteger serial = ((X509Certificate) cert).getSerialNumber();
        final X500Principal principal = ((X509Certificate) cert).getIssuerX500Principal();
        for (final String alias : userCertAliases) {
        	final X509Certificate c = (X509Certificate) engineGetCertificate(alias);
            if (c.getSerialNumber() == serial && principal.equals(principal)) {
                return alias;
            }
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public Certificate[] engineGetCertificateChain(final String alias) {
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}
		return new X509Certificate[] {
			(X509Certificate) engineGetCertificate(alias)
		};
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public Date engineGetCreationDate(final String alias) {
        throw new UnsupportedOperationException();
    }

    /** {@inheritDoc} */
    @Override
    public Key engineGetKey(final String alias, final char[] password) throws NoSuchAlgorithmException,
                                                                              UnrecoverableKeyException {
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}

    	// No permitimos PIN nulo, si llega nulo pedimos por dialogo grafico
    	if (password == null) {
    		// En Android damos directamente un fallo
    		if ("Dalvik".equals(System.getProperty("java.vm.name"))) { //$NON-NLS-1$ //$NON-NLS-2$
    			throw new IllegalArgumentException("Es necesario proporcionar el PIN de la tarjeta"); //$NON-NLS-1$
    		}
    		try {
    			final Class<?> uiPasswordCallbackClass = Class.forName("es.gob.jmulticard.ui.passwordcallback.gui.UIPasswordCallback"); //$NON-NLS-1$
    			final Constructor<?> uiPasswordCallbackConstructor = uiPasswordCallbackClass.getConstructor(
					String.class,
					Object.class,
					String.class,
					String.class
				);

    			final PasswordCallback passwordCallback = (PasswordCallback) uiPasswordCallbackConstructor.newInstance(
					CeresMessages.getString("CeresKeyStoreImpl.0"), //$NON-NLS-1$
					null,
					null,
					CeresMessages.getString("CeresKeyStoreImpl.1") //$NON-NLS-1$
				);
    			this.cryptoCard.setPasswordCallback(passwordCallback);
    		}
    		catch (final Exception e) {
    			throw new IllegalArgumentException("Se ha proporcionado un PIN nulo y no se ha podido solicitar al usuario: " + e, e); //$NON-NLS-1$
    		}
    	}
    	else {
    		this.cryptoCard.setPasswordCallback(
				new CachePasswordCallback(password)
			);
    	}
        try {
        	final PrivateKeyReference pkRef = this.cryptoCard.getPrivateKey(alias);
        	if (!(pkRef instanceof CeresPrivateKeyReference)) {
        		throw new ProviderException("La clave obtenida de la tarjeta no es del tipo esperado, se ha obtenido: " + pkRef.getClass().getName()); //$NON-NLS-1$
        	}
        	return new CeresPrivateKey(
    			(CeresPrivateKeyReference) pkRef,
    			this.cryptoCard,
    			((RSAPublicKey)engineGetCertificate(alias).getPublicKey()).getModulus()
			);
		}
        catch (final CryptoCardException e) {
			throw new ProviderException(e);
		}
    }

    /** {@inheritDoc} */
    @Override
    public KeyStore.Entry engineGetEntry(final String alias,
    		                             final ProtectionParameter protParam) throws KeyStoreException,
    		                                                                         NoSuchAlgorithmException,
    		                                                                         UnrecoverableEntryException {
    	if (!(protParam instanceof KeyStore.PasswordProtection)) {
    		throw new KeyStoreException(
				"Se necesita un ProtectionParameter de tipo KeyStore.PasswordProtection" //$NON-NLS-1$
			);
    	}
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}
    	final PrivateKey key = (PrivateKey) engineGetKey(
			alias,
			((KeyStore.PasswordProtection)protParam).getPassword()
		);
    	return new PrivateKeyEntry(key, engineGetCertificateChain(alias));
    }

    /** {@inheritDoc} */
    @Override
    public boolean engineIsCertificateEntry(final String alias) {
        return userCertAliases.contains(alias);
    }

    /** {@inheritDoc} */
    @Override
    public boolean engineIsKeyEntry(final String alias) {
        return userCertAliases.contains(alias);
    }

    private static ApduConnection getApduConnection() {
    	return CeresProvider.getDefaultApduConnection();
    }

    /** {@inheritDoc} */
    @Override
    public void engineLoad(final KeyStore.LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {
    	throw new UnsupportedOperationException(
			"No soportado, se debe usar 'engineLoad(InputStream stream, char[] password)'" //$NON-NLS-1$
    	);
    }

    /** {@inheritDoc} */
    @Override
    public void engineLoad(final InputStream stream, final char[] password) throws IOException,
                                                                                   NoSuchAlgorithmException,
                                                                                   CertificateException {
        // Aqui se realiza el acceso e inicializacion de la tarjeta
        this.cryptoCard = new Ceres(
    		getApduConnection(),
    		new JseCryptoHelper()
		);

        // Precargamos los alias
        loadAliases();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] pass, final Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    /** {@inheritDoc} */
    @Override
    public int engineSize() {
        return userCertAliases.size();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineStore(final OutputStream os, final char[] pass) throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new UnsupportedOperationException();
    }

    /** {@inheritDoc} */
    @Override
    public boolean engineEntryInstanceOf(final String alias, final Class<? extends KeyStore.Entry> entryClass) {
        if (!engineContainsAlias(alias)) {
            return false;
        }
        return entryClass.equals(PrivateKeyEntry.class);
    }

    /** PasswordCallbak que almacena internamente y devuelve la contrase&ntilde;a con la que se
     * construy&oacute; o la que se le establece posteriormente. */
    private static final class CachePasswordCallback extends PasswordCallback {

        private static final long serialVersionUID = 816457144215238935L;

        /** Contruye una Callback con una contrase&ntilde;a pre-establecida.
         * @param password Contrase&ntilde;a por defecto. */
        CachePasswordCallback(final char[] password) {
            super(">", false); //$NON-NLS-1$
            this.setPassword(password);
        }
    }
}