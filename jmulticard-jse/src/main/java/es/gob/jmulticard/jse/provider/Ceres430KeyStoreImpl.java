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
package es.gob.jmulticard.jse.provider;

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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.CeresSc;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DniePrivateKeyReference;
import es.gob.jmulticard.ui.passwordcallback.gui.CommonPasswordCallback;

/** Implementaci&oacute;n del SPI <code>KeyStore</code> para tarjetas CERES 4.30 o superiores.
 * Esta implementaci&oacute;n es una copia del de DNIe, ya que estas tarjetas son
 * iguales internamente que el DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Ceres430KeyStoreImpl extends KeyStoreSpi {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

	private static final String INTERMEDIATE_CA_CERT_ALIAS = "CertCAIntermediaDGP"; //$NON-NLS-1$

    private Dnie cryptoCard = null;
    private List<String> aliases = null;

    /** {@inheritDoc} */
    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(this.aliases);
    }

    /** {@inheritDoc} */
    @Override
    public boolean engineContainsAlias(final String alias) {
        return this.aliases.contains(alias);
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
        catch (final PinException e) {
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
        for (final String alias : this.aliases) {
            if (((X509Certificate) engineGetCertificate(alias)).getSerialNumber() == serial) {
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

    	final List<X509Certificate> certs = new ArrayList<>();
    	certs.add((X509Certificate) engineGetCertificate(alias));

    	// La cadena disponible del certificado la componen el propio certificado y el
    	// certificado de la CA intermedia. Si no se puede recuperar esta ultima, se obvia
    	X509Certificate intermediateCaCert;
    	try {
    		intermediateCaCert = this.cryptoCard.getCertificate(INTERMEDIATE_CA_CERT_ALIAS);
    	}
    	catch (final AuthenticationModeLockedException e) {
    		throw e;
    	}
    	catch (final BadPinException e) {
    		throw new BadPasswordProviderException(e);
    	}
    	catch (final Exception e) {
    		LOGGER.warning(
				"No se ha podido cargar el certificado de la CA intermedia: " + e //$NON-NLS-1$
			);
    		intermediateCaCert = null;
		}

    	X509Certificate sha2DnieRoot = null;

    	if (intermediateCaCert != null) {

    		certs.add(intermediateCaCert);

    		// Si tenemos CA intermedia probamos con la raiz, incluida estaticamente
    		// en el proyecto
	    	try {
				sha2DnieRoot = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate( //$NON-NLS-1$
					Ceres430KeyStoreImpl.class.getResourceAsStream("/ACRAIZ-SHA2.crt") //$NON-NLS-1$
				);
			}
	    	catch (final Exception e) {
	    		sha2DnieRoot = null;
	    		LOGGER.warning(
					"No se ha podido cargar el certificado de la CA raiz: " + e //$NON-NLS-1$
				);
			}

	    	// Comprobamos que efectivamente sea su raiz
	    	if (sha2DnieRoot != null) {
		    	try {
					intermediateCaCert.verify(sha2DnieRoot.getPublicKey());
				}
		    	catch (final Exception e) {
		    		sha2DnieRoot = null;
		    		LOGGER.info(
						"La CA raiz precargada no es la emisora de esta tarjeta: " + e //$NON-NLS-1$
					);
				}
	    	}
    	}

    	if (sha2DnieRoot != null) {
    		certs.add(sha2DnieRoot);
    	}

    	return certs.toArray(new X509Certificate[0]);
    }

    /** {@inheritDoc} */
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
		if (!(pkRef instanceof DniePrivateKeyReference)) {
			throw new ProviderException(
				"La clave obtenida de la tarjeta no es del tipo esperado, se ha obtenido: " + (pkRef != null ? pkRef.getClass().getName() : "null") //$NON-NLS-1$ //$NON-NLS-2$
			);
		}
		return new DniePrivateKey((DniePrivateKeyReference) pkRef);
    }

    /** {@inheritDoc} */
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

    /** {@inheritDoc} */
    @Override
    public boolean engineIsCertificateEntry(final String alias) {
        return this.aliases.contains(alias);
    }

    /** {@inheritDoc} */
    @Override
    public boolean engineIsKeyEntry(final String alias) {
        return this.aliases.contains(alias);
    }

    /** {@inheritDoc} */
    @Override
    public void engineLoad(final KeyStore.LoadStoreParameter param) throws IOException {
    	if (param != null) {
    		final ProtectionParameter pp = param.getProtectionParameter();
    		if (pp instanceof KeyStore.CallbackHandlerProtection) {
    			if (((KeyStore.CallbackHandlerProtection) pp).getCallbackHandler() == null) {
    				throw new IllegalArgumentException("El CallbackHandler no puede ser nulo"); //$NON-NLS-1$
    			}
    			this.cryptoCard = new CeresSc(
					Ceres430Provider.getDefaultApduConnection(),
					null,
					new JseCryptoHelper(),
					((KeyStore.CallbackHandlerProtection) pp).getCallbackHandler()
				);
    		}
    		else if (pp instanceof KeyStore.PasswordProtection) {
    			final PasswordCallback pwc = new CommonPasswordCallback((PasswordProtection) pp);
    			this.cryptoCard = new CeresSc(
					Ceres430Provider.getDefaultApduConnection(),
					pwc,
					new JseCryptoHelper(),
					null
				);
    		}
    		else {
    			LOGGER.warning(
	   				"Se ha proporcionado un LoadStoreParameter de tipo no soportado, se ignorara: " + (pp != null ? pp.getClass().getName() : "NULO") //$NON-NLS-1$ //$NON-NLS-2$
				);
    		}
    	}
    	else {
	    	this.cryptoCard = new CeresSc(
				Ceres430Provider.getDefaultApduConnection(),
				null,
				new JseCryptoHelper(),
				null
			);
    	}

    	this.aliases = Arrays.asList(this.cryptoCard.getAliases());
    }

    /** {@inheritDoc} */
    @Override
    public void engineLoad(final InputStream stream, final char[] password) throws IOException {
    	// Ponemos la conexion por defecto
    	final ApduConnection conn;
    	try {
	    	 conn = Ceres430Provider.getDefaultApduConnection() == null ?
				(ApduConnection) Class.forName("es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection").getConstructor().newInstance() : //$NON-NLS-1$
					Ceres430Provider.getDefaultApduConnection();
    	}
    	catch(final Exception e) {
    		throw new IllegalStateException("No hay una conexion de APDU por defecto: " + e); //$NON-NLS-1$
    	}

        // Aqui se realiza el acceso e inicializacion del DNIe
    	this.cryptoCard = new CeresSc(
    		conn,
    		password != null ?
				new CachePasswordCallback(password) :
					null,
    		new JseCryptoHelper(),
    		null
		);

    	this.aliases = Arrays.asList(this.cryptoCard.getAliases());
    }

    /** {@inheritDoc} */
    @Override
    public int engineSize() {
        return this.aliases.size();
    }

    /** {@inheritDoc} */
    @Override
    public boolean engineEntryInstanceOf(final String alias, final Class<? extends KeyStore.Entry> entryClass) {
        if (!engineContainsAlias(alias)) {
            return false;
        }
        return entryClass.equals(PrivateKeyEntry.class);
    }

    /** <code>PasswordCallback</code> que almacena internamente y devuelve la contrase&ntilde;a con la que se
     * construy&oacute; o la que se le establece posteriormente. */
    private static final class CachePasswordCallback extends PasswordCallback {

        private static final long serialVersionUID = 816457144215238935L;

        /** Contruye una <code>Callback</code> con una contrase&ntilde;a preestablecida.
         * @param password Contrase&ntilde;a por defecto. */
        public CachePasswordCallback(final char[] password) {
            super(">", false); //$NON-NLS-1$
            setPassword(password);
        }
    }

    // ******************************************
    // ******* OPERACIONES NO SOPORTADAS ********
    // ******************************************

    /** Operaci&oacute;n no soportada. */
    @Override
    public Date engineGetCreationDate(final String alias) {
    	LOGGER.warning(
			"No se soporta la obtencion de fecha de creacion, se devuelve la fecha actual" //$NON-NLS-1$
		);
        return new Date();
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
    public void engineDeleteEntry(final String alias) {
        throw new UnsupportedOperationException();
    }

}