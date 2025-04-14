package es.gob.jmulticard.jse.provider;

import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DniePrivateKeyReference;
import es.gob.jmulticard.crypto.BcCryptoHelper;

/** Funcionalidades comunes a todos los SPI <code>KeyStore</code> derivados de DNI.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class AbstractJMultiCardKeyStore extends KeyStoreSpi {

	protected static final Logger LOGGER = Logger.getLogger(AbstractJMultiCardKeyStore.class.getName());

	protected static final CryptoHelper CRYPTO_HELPER = new BcCryptoHelper();

	protected Dnie cryptoCard = null;
	protected List<String> aliases = null;

    @Override
    public final Enumeration<String> engineAliases() {
        return Collections.enumeration(this.aliases);
    }

    @Override
    public final boolean engineContainsAlias(final String alias) {
        return this.aliases.contains(alias);
    }

    @Override
    public final Certificate engineGetCertificate(final String alias) {
        return this.cryptoCard.getCertificate(alias);
    }

    @Override
    public final String engineGetCertificateAlias(final Certificate otherCert) {
        if (!(otherCert instanceof X509Certificate)) {
            return null;
        }
        for (final String alias : this.aliases) {
        	final Certificate myCert = engineGetCertificate(alias);
            try {
				if (myCert != null && HexUtils.arrayEquals(otherCert.getEncoded(), myCert.getEncoded())) {
				    return alias;
				}
			}
            catch (final CertificateEncodingException e) {
            	LOGGER.warning("No se han podido comparar certificados: " + e); //$NON-NLS-1$
				return null;
			}
        }
        return null;
    }

    @Override
    public final Key engineGetKey(final String alias, final char[] password) {
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}
    	if (password != null) {
    		// Establecemos el PasswordCallback
    		final PasswordCallback pwc = new CachePasswordCallback(password);
    		this.cryptoCard.setPasswordCallback(pwc);
    	}
        final PrivateKeyReference pkRef = this.cryptoCard.getPrivateKey(alias);
		if (!(pkRef instanceof DniePrivateKeyReference)) {
			throw new ProviderException(
				"La clave obtenida de la tarjeta no es del tipo esperado, se ha obtenido: " + (pkRef != null ? pkRef.getClass().getName() : "null") //$NON-NLS-1$ //$NON-NLS-2$
			);
		}
		return new DniePrivateKey(
			(DniePrivateKeyReference) pkRef,
			((RSAPublicKey)engineGetCertificate(alias).getPublicKey()).getModulus()
		);
    }

    @Override
    public final Entry engineGetEntry(final String alias,
    		                          final ProtectionParameter protParam) {

    	if(protParam instanceof KeyStore.CallbackHandlerProtection) {
    		// Establecemos el CallbackHandler
    		final CallbackHandler chp = ((KeyStore.CallbackHandlerProtection) protParam).getCallbackHandler();
    		if(chp != null) {
    			this.cryptoCard.setCallbackHandler(chp);
    		}
    	}
    	else if (protParam instanceof KeyStore.PasswordProtection) {
    		// Establecemos el PasswordCallback
    		final PasswordCallback pwc = new CachePasswordCallback(
				((KeyStore.PasswordProtection)protParam).getPassword()
			);
    		this.cryptoCard.setPasswordCallback(pwc);
    	}
    	else {
    		LOGGER.warning(
   				"Se ha proporcionado un ProtectionParameter de tipo no soportado, se ignorara: " + //$NON-NLS-1$
					(protParam != null ? protParam.getClass().getName() : "NULO") //$NON-NLS-1$
			);
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
    public final int engineSize() {
        return this.aliases.size();
    }

    @Override
    public final boolean engineEntryInstanceOf(final String alias, final Class<? extends KeyStore.Entry> entryClass) {
        if (!engineContainsAlias(alias)) {
            return false;
        }
        return entryClass.equals(PrivateKeyEntry.class);
    }

    @Override
    public final boolean engineIsCertificateEntry(final String alias) {
    	// Solo se soportan certificados con clave privada
        return false;
    }

    @Override
    public final boolean engineIsKeyEntry(final String alias) {
        return this.aliases.contains(alias);
    }

    //***************************************************************************************
    //*************** OPERACIONES NO SOPORTADAS *********************************************

    /** Operaci&oacute;n no soportada. */
    @Override
    public final void engineStore(final OutputStream os, final char[] pass) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public final void engineSetCertificateEntry(final String alias, final Certificate cert) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public final void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public final void engineSetKeyEntry(final String alias, final Key key, final char[] pass, final Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public final void engineDeleteEntry(final String alias) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public final Date engineGetCreationDate(final String alias) {
    	LOGGER.warning("No se soporta la obtencion de fecha de creacion, se devuelve la fecha actual"); //$NON-NLS-1$
        return new Date();
    }
}
