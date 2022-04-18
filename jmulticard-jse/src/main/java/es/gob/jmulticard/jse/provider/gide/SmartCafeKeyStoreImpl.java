/*
 * Controlador Java de la Secretaria de Estado de Administraciones Publicas
 * para el DNI electronico.
 *
 * El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
 * que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
 * para la realizacion de procesos de autenticacion, firma electronica y validacion
 * de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
 * el acceso a los certificados y claves del DNI electronico, asi como la realizacion
 * de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
 * sido disenado para su funcionamiento independiente del sistema operativo final.
 *
 * Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
 * e Impulso de la Administracion Electronica
 *
 * Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
 * o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
 * licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
 * en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
 * su compatibilidad con otros componentes.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * Lesser GNU General Public License publicada por la Free Software Foundation,
 * tanto en la version 2.1 de la Licencia, o en una version posterior.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * European Union Public License publicada por la Comision Europea,
 * tanto en la version 1.1 de la Licencia, o en una version posterior.
 *
 * Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
 *
 * Deberia recibir una copia de la European Union Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
 *
 * Este programa es distribuido con la esperanza de que sea util, pero
 * SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
 * o idoneidad para un proposito particular.
 */
package es.gob.jmulticard.jse.provider.gide;

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
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.gide.smartcafe.SmartCafePkcs15Applet;
import es.gob.jmulticard.card.gide.smartcafe.SmartCafePrivateKeyReference;
import es.gob.jmulticard.jse.provider.CachePasswordCallback;
import es.gob.jmulticard.jse.provider.ProviderUtil;

/** Implementaci&oacute;n del SPI <code>KeyStore</code> para tarjeta G&amp;D SmartCafe con Applet PKCS#15.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SmartCafeKeyStoreImpl extends KeyStoreSpi {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    private SmartCafePkcs15Applet cryptoCard = null;
    private List<String> aliases = null;

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(this.aliases);
    }

    @Override
    public boolean engineContainsAlias(final String alias) {
        return this.aliases.contains(alias);
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
        for (final String alias : this.aliases) {
            if (((X509Certificate) engineGetCertificate(alias)).getSerialNumber() == serial) {
                return alias;
            }
        }
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(final String alias) {
    	LOGGER.warning(
			"El proveedor no soporta la formacion de cadenas de certificados, se devolvera solo el certificado final" //$NON-NLS-1$
		);
    	return new Certificate[] { engineGetCertificate(alias) };
    }

    @Override
    public Key engineGetKey(final String alias, final char[] password) {
    	if (!engineContainsAlias(alias)) {
    		return null;
    	}
    	if (password != null) {
    		// Establecemos el PasswordCallback
    		final PasswordCallback pwc = new CachePasswordCallback(password);
    		this.cryptoCard.setPasswordCallback(pwc);
    	}
        final PrivateKeyReference pkRef = this.cryptoCard.getPrivateKey(alias);
		if (!(pkRef instanceof SmartCafePrivateKeyReference)) {
			throw new ProviderException(
				"La clave obtenida de la tarjeta no es del tipo '" + //$NON-NLS-1$
					SmartCafePrivateKeyReference.class.getName() + "', se ha obtenido: " + //$NON-NLS-1$
						(pkRef != null ? pkRef.getClass().getName() : "null") //$NON-NLS-1$
			);
		}
		return new SmartCafePrivateKey((SmartCafePrivateKeyReference) pkRef, this.cryptoCard);
    }

    @Override
    public KeyStore.Entry engineGetEntry(final String alias,
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
    		final PasswordCallback pwc = new CachePasswordCallback(((KeyStore.PasswordProtection)protParam).getPassword());
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
    public boolean engineIsCertificateEntry(final String alias) {
        return false;
    }

    @Override
    public boolean engineIsKeyEntry(final String alias) {
        return this.aliases.contains(alias);
    }

    @Override
    public int engineSize() {
        return this.aliases.size();
    }

    @Override
    public boolean engineEntryInstanceOf(final String alias, final Class<? extends KeyStore.Entry> entryClass) {
        if (!engineContainsAlias(alias)) {
            return false;
        }
        return entryClass.equals(PrivateKeyEntry.class);
    }

    @Override
    public void engineLoad(final InputStream stream, final char[] password) throws IOException {
    	// Ponemos la conexion por defecto
    	final ApduConnection conn = ProviderUtil.getDefaultConnection();

        // Aqui se realiza el acceso e inicializacion de la tarjeta
    	this.cryptoCard = new SmartCafePkcs15Applet(conn, new JseCryptoHelper());
    	if (password != null) {
    		this.cryptoCard.setPasswordCallback(new CachePasswordCallback(password));
    	}
    	this.aliases = Arrays.asList(this.cryptoCard.getAliases());
    }

    @Override
    public void engineLoad(final KeyStore.LoadStoreParameter param) throws IOException {
		final ApduConnection conn = ProviderUtil.getDefaultConnection();
		this.cryptoCard = new SmartCafePkcs15Applet(conn, new JseCryptoHelper());
    	if (param != null) {
    		final ProtectionParameter pp = param.getProtectionParameter();
    		if (pp instanceof KeyStore.CallbackHandlerProtection) {
    			if (((KeyStore.CallbackHandlerProtection) pp).getCallbackHandler() == null) {
    				throw new IllegalArgumentException("El CallbackHandler no puede ser nulo"); //$NON-NLS-1$
    			}
    			this.cryptoCard.setCallbackHandler(((KeyStore.CallbackHandlerProtection) pp).getCallbackHandler());
    		}
    		else if (pp instanceof KeyStore.PasswordProtection) {
    			final PasswordCallback pwc = new CachePasswordCallback(((PasswordProtection) pp).getPassword());
    			this.cryptoCard.setPasswordCallback(pwc);
    		}
    		else {
    			LOGGER.warning(
	   				"Se ha proporcionado un LoadStoreParameter de tipo no soportado, se ignorara: " + (pp != null ? pp.getClass().getName() : "NULO") //$NON-NLS-1$ //$NON-NLS-2$
				);
    		}
    	}
    	this.aliases = Arrays.asList(this.cryptoCard.getAliases());
    }

    //***********************************************************************
    //********* OPERACIONES NO SOPORTADAS ***********************************

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
    public void engineStore(final OutputStream os, final char[] pass) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public void engineDeleteEntry(final String alias) {
        throw new UnsupportedOperationException();
    }

    /** Operaci&oacute;n no soportada. */
    @Override
    public Date engineGetCreationDate(final String alias) {
    	LOGGER.warning(
			"No se soporta la obtencion de fecha de creacion, se devuelve la fecha actual" //$NON-NLS-1$
		);
        return new Date();
    }

}