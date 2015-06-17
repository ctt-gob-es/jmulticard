package es.gob.jmulticard.jse.provider.ceres;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

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

    private static List<String> USERS_CERTS_ALIASES = null;

    private Ceres cryptoCard = null;

    private void loadAliases() throws CryptoCardException {
    	final String[] aliases = this.cryptoCard.getAliases();
    	USERS_CERTS_ALIASES = new ArrayList<String>(aliases.length);
    	for (final String alias : aliases) {
    		USERS_CERTS_ALIASES.add(alias);
    	}
    }

    /** {@inheritDoc} */
    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(USERS_CERTS_ALIASES);
    }

    /** {@inheritDoc} */
    @Override
    public boolean engineContainsAlias(final String alias) {
        return USERS_CERTS_ALIASES.contains(alias);
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
        for (final String alias : USERS_CERTS_ALIASES) {
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
    public Key engineGetKey(final String alias, final char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}
        try {
        	final PrivateKeyReference pkRef = this.cryptoCard.getPrivateKey(alias);
        	if (!(pkRef instanceof CeresPrivateKeyReference)) {
        		throw new ProviderException("La clave obtenida de la tarjeta no es del tipo esperado, se ha obtenido: " + pkRef.getClass().getName()); //$NON-NLS-1$
        	}
        	return new CeresPrivateKey((CeresPrivateKeyReference) pkRef, this.cryptoCard);
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
    	if (protParam != null) {
    		Logger.getLogger("es.gob.jmulticard").warning( //$NON-NLS-1$
				"Se ha proporcionado un ProtectionParameter, pero este se ignorara, ya que el PIN se gestiona en la carga" //$NON-NLS-1$
			);
    	}
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}
    	final PrivateKey key = (PrivateKey) engineGetKey(alias, null);
    	return new PrivateKeyEntry(key, engineGetCertificateChain(alias));
    }

    /** {@inheritDoc} */
    @Override
    public boolean engineIsCertificateEntry(final String alias) {
        return USERS_CERTS_ALIASES.contains(alias);
    }

    /** {@inheritDoc} */
    @Override
    public boolean engineIsKeyEntry(final String alias) {
        return USERS_CERTS_ALIASES.contains(alias);
    }

    private static ApduConnection getApduConnection() {
    	try {
	    	 return CeresProvider.getDefaultApduConnection() == null ?
				(ApduConnection) Class.forName("es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection").newInstance() : //$NON-NLS-1$
					CeresProvider.getDefaultApduConnection();
	   	}
	   	catch(final Exception e) {
	   		throw new IllegalStateException("No hay una conexion de APDU por defecto: " + e); //$NON-NLS-1$
	   	}
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
    		password != null ?
				new CachePasswordCallback(password) :
					null,
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
        return USERS_CERTS_ALIASES.size();
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
        public CachePasswordCallback(final char[] password) {
            super(">", false); //$NON-NLS-1$
            this.setPassword(password);
        }
    }
}