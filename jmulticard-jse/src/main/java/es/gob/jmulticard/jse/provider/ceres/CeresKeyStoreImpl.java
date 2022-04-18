package es.gob.jmulticard.jse.provider.ceres;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.x500.X500Principal;

import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.fnmt.ceres.Ceres;
import es.gob.jmulticard.card.fnmt.ceres.CeresPrivateKeyReference;
import es.gob.jmulticard.jse.provider.CachePasswordCallback;
import es.gob.jmulticard.jse.provider.CardPasswordCallback;
import es.gob.jmulticard.jse.provider.JMultiCardProviderMessages;

/** Implementaci&oacute;n del SPI <code>KeyStore</code> para tarjeta FNMT-RCM-CERES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CeresKeyStoreImpl extends KeyStoreSpi {

    private static List<String> userCertAliases = null;

    private Ceres cryptoCard = null;

    private void loadAliases() {
    	final String[] aliases = this.cryptoCard.getAliases();
    	userCertAliases = new ArrayList<>(aliases.length);
    	Collections.addAll(userCertAliases, aliases);
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(userCertAliases);
    }

    @Override
    public boolean engineContainsAlias(final String alias) {
        return userCertAliases.contains(alias);
    }

    @Override
    public Certificate engineGetCertificate(final String alias) {
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}
        return this.cryptoCard.getCertificate(alias);
    }

    @Override
    public String engineGetCertificateAlias(final Certificate cert) {
        if (!(cert instanceof X509Certificate)) {
            return null;
        }

        final BigInteger serial = ((X509Certificate) cert).getSerialNumber();
        final X500Principal principal = ((X509Certificate) cert).getIssuerX500Principal();

        for (final String alias : userCertAliases) {
        	final X509Certificate c = (X509Certificate) engineGetCertificate(alias);
            if (c.getSerialNumber().equals(serial) && c.getIssuerX500Principal().equals(principal)) {
                return alias;
            }
        }
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(final String alias) {
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}
		return new X509Certificate[] {
			(X509Certificate) engineGetCertificate(alias)
		};
    }

    @Override
    public Key engineGetKey(final String alias, final char[] password) {
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}

    	// No permitimos PIN nulo, si llega nulo pedimos por callback
    	if (password != null) {
    		this.cryptoCard.setPasswordCallback(
				new CachePasswordCallback(password)
			);
    	}
        final PrivateKeyReference pkRef = this.cryptoCard.getPrivateKey(alias);
		if (!(pkRef instanceof CeresPrivateKeyReference)) {
			throw new ProviderException(
				"La clave obtenida de la tarjeta no es del tipo esperado, se ha obtenido: " + pkRef.getClass().getName() //$NON-NLS-1$
			);
		}
		return new CeresPrivateKey(
			(CeresPrivateKeyReference) pkRef,
			this.cryptoCard,
			((RSAPublicKey)engineGetCertificate(alias).getPublicKey()).getModulus()
		);
    }

    @Override
    public KeyStore.Entry engineGetEntry(final String alias,
    		                             final ProtectionParameter protParam) {
    	if (protParam instanceof KeyStore.PasswordProtection) {
	    	final PasswordCallback pwc = new CachePasswordCallback(((KeyStore.PasswordProtection)protParam).getPassword());
			this.cryptoCard.setPasswordCallback(pwc);
    	}
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}
    	final PrivateKey key = (PrivateKey) engineGetKey(
			alias,
			null // Le pasamos null porque ya hemos establecido el PasswordCallback o el CallbackHander antes
		);
    	return new PrivateKeyEntry(key, engineGetCertificateChain(alias));
    }

    @Override
    public boolean engineIsCertificateEntry(final String alias) {
    	// Solo se soportan certificados con clave privada
        return false;
    }

    @Override
    public boolean engineIsKeyEntry(final String alias) {
        return userCertAliases.contains(alias);
    }

    private static ApduConnection getApduConnection() {
    	return CeresProvider.getDefaultApduConnection();
    }

    @Override
    public void engineLoad(final KeyStore.LoadStoreParameter param) throws IOException {
    	if (param != null) {
    		final ProtectionParameter pp = param.getProtectionParameter();
    		if (pp instanceof KeyStore.CallbackHandlerProtection) {
    			if (((KeyStore.CallbackHandlerProtection) pp).getCallbackHandler() == null) {
    				throw new IllegalArgumentException("El CallbackHandler no puede ser nulo"); //$NON-NLS-1$
    			}
    			this.cryptoCard = new Ceres(
					CeresProvider.getDefaultApduConnection(),
					new JseCryptoHelper()
				);
    			this.cryptoCard.setCallbackHandler(((KeyStore.CallbackHandlerProtection) pp).getCallbackHandler());
    		}
    		else if (pp instanceof KeyStore.PasswordProtection) {
    			final PasswordCallback pwc = new CardPasswordCallback(
					(PasswordProtection) pp,
					JMultiCardProviderMessages.getString("Ceres430KeyStoreImpl.0") //$NON-NLS-1$
				);
    			this.cryptoCard = new Ceres(
					CeresProvider.getDefaultApduConnection(),
					new JseCryptoHelper()
				);
    			this.cryptoCard.setPasswordCallback(pwc);
    		}
    		else {
	       		Logger.getLogger("es.gob.jmulticard").warning( //$NON-NLS-1$
	   				"Se ha proporcionado un LoadStoreParameter de tipo no soportado, se ignorara: " + (pp != null ? pp.getClass().getName() : "NULO") //$NON-NLS-1$ //$NON-NLS-2$
				);
    		}
    	}
    	else {
	    	this.cryptoCard = new Ceres(
				CeresProvider.getDefaultApduConnection(),
				new JseCryptoHelper()
			);
    	}

    	userCertAliases = Arrays.asList(this.cryptoCard.getAliases());
    }

    @Override
    public void engineLoad(final InputStream stream, final char[] password) throws IOException {
        // Aqui se realiza el acceso e inicializacion de la tarjeta
        this.cryptoCard = new Ceres(
    		getApduConnection(),
    		new JseCryptoHelper()
		);

        // Precargamos los alias
        loadAliases();
    }

    @Override
    public int engineSize() {
        return userCertAliases.size();
    }

    @Override
    public boolean engineEntryInstanceOf(final String alias, final Class<? extends KeyStore.Entry> entryClass) {
        if (!engineContainsAlias(alias)) {
            return false;
        }
        return entryClass.equals(PrivateKeyEntry.class);
    }

    // ******************************************
    // ******* OPERACIONES NO SOPORTADAS ********
    // ******************************************

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineDeleteEntry(final String alias) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineStore(final OutputStream os, final char[] pass) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineSetCertificateEntry(final String alias, final Certificate cert) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] pass, final Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public Date engineGetCreationDate(final String alias) {
    	Logger.getLogger("es.gob.jmulticard").warning( //$NON-NLS-1$
			"No se soporta la obtencion de fecha de creacion, se devuelve la fecha actual" //$NON-NLS-1$
		);
        return new Date();
    }

}