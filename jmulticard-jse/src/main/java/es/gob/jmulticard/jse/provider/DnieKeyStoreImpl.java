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
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.connection.ApduConnection;

/**
 * Implementaci&oacute;n del SPI <code>KeyStore</code> para DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s.
 */
public class DnieKeyStoreImpl extends AbstractJMultiCardKeyStore {

	/** Alias del certificado de CA intermedia (siempre el mismo en el DNIe). */
	private static final String INTERMEDIATE_CA_CERT_ALIAS = "CertCAIntermediaDGP"; //$NON-NLS-1$

    @Override
    public Certificate[] engineGetCertificateChain(final String alias) {

    	if (!engineContainsAlias(alias)) {
    		return null;
    	}

    	final List<X509Certificate> certs = new ArrayList<>();
    	certs.add((X509Certificate) engineGetCertificate(alias));

    	// La cadena disponible del certificado la componen el propio certificado y el
    	// certificado de la CA intermedia. Si no se puede recuperar esta ultima, se obvia
    	final X509Certificate intermediateCaCert = this.cryptoCard.getCertificate(INTERMEDIATE_CA_CERT_ALIAS);

    	X509Certificate sha2DnieRoot = null;

    	if (intermediateCaCert != null) {

    		certs.add(intermediateCaCert);

    		// Si tenemos CA intermedia probamos con la raiz v2, que esta incluida estaticamente en el proyecto
	    	try (InputStream is = DnieKeyStoreImpl.class.getResourceAsStream("/ACRAIZ-SHA2-2.crt")) { //$NON-NLS-1$
				sha2DnieRoot = CryptoHelper.generateCertificate(is);
			}
	    	catch (final Exception e) {
	    		sha2DnieRoot = null;
	    		LOGGER.warning("No se ha podido cargar el certificado de la CA raiz 2: " + e); //$NON-NLS-1$
			}

	    	// Comprobamos que efectivamente sea su raiz
	    	if (sha2DnieRoot != null) {
		    	try {
					intermediateCaCert.verify(sha2DnieRoot.getPublicKey());
				}
		    	catch (final Exception e) {
		    		// Si no es la raiz, puede que sea un DNI antiguo con la raiz anterior
		    		LOGGER.warning("La CA raiz no es la V2, se intentara con la version anterior: " + e); //$NON-NLS-1$

		    		try (InputStream is = DnieKeyStoreImpl.class.getResourceAsStream("/ACRAIZ-SHA2.crt")) { //$NON-NLS-1$
	    				sha2DnieRoot = CryptoHelper.generateCertificate(is);
	    			}
	    	    	catch (final Exception ex) {
	    	    		sha2DnieRoot = null;
	    	    		LOGGER.warning("No se ha podido cargar el certificado de la CA raiz: " + ex); //$NON-NLS-1$
	    			}
		    		if (sha2DnieRoot != null) {
				    	try {
							intermediateCaCert.verify(sha2DnieRoot.getPublicKey());
						}
				    	catch (final Exception ex2) {
				    		sha2DnieRoot = null;
				    		LOGGER.info("La CA raiz de DNIe precargada no es la emisora de este DNIe: " + ex2); //$NON-NLS-1$
						}
		    		}
		    	}
	    	}
    	}

    	if (sha2DnieRoot != null) {
    		certs.add(sha2DnieRoot);
    	}

    	return certs.toArray(new X509Certificate[0]);
    }

    @Override
    public void engineLoad(final KeyStore.LoadStoreParameter param) throws IOException {
    	if (param != null) {
    		final ProtectionParameter pp = param.getProtectionParameter();
    		if (pp instanceof KeyStore.CallbackHandlerProtection) {
    			if (((KeyStore.CallbackHandlerProtection) pp).getCallbackHandler() == null) {
    				throw new IllegalArgumentException("El CallbackHandler no puede ser nulo"); //$NON-NLS-1$
    			}
    			this.cryptoCard = DnieFactory.getDnie(
					DnieProvider.getDefaultApduConnection(),
					null,
					CRYPTO_HELPER,
					((KeyStore.CallbackHandlerProtection) pp).getCallbackHandler(),
					isAnotherCardsAllowed()
				);
    		}
    		else if (pp instanceof KeyStore.PasswordProtection) {
    			final PasswordCallback pwc = new CardPasswordCallback(
					(PasswordProtection) pp,
					JMultiCardProviderMessages.getString("DnieKeyStoreImpl.0") //$NON-NLS-1$
				);
    			this.cryptoCard = DnieFactory.getDnie(DnieProvider.getDefaultApduConnection(), pwc, CRYPTO_HELPER, null, isAnotherCardsAllowed());
    		}
    		else {
    			LOGGER.warning(
	   				"Se ha proporcionado un LoadStoreParameter de tipo no soportado, se ignorara: " + (pp != null ? pp.getClass().getName() : "NULO") //$NON-NLS-1$ //$NON-NLS-2$
				);
    		}
    	}
    	else {
	    	this.cryptoCard = DnieFactory.getDnie(DnieProvider.getDefaultApduConnection(), null, CRYPTO_HELPER, null, isAnotherCardsAllowed());
    	}

    	this.aliases = Arrays.asList(this.cryptoCard.getAliases());
    }

    @Override
    public void engineLoad(final InputStream stream, final char[] password) throws IOException {

    	// Ponemos la conexion por defecto
    	final ApduConnection conn;
    	try {
	    	 conn = DnieProvider.getDefaultApduConnection() == null ?
				(ApduConnection) Class.forName(ProviderUtil.DEFAULT_PROVIDER_CLASSNAME).getConstructor().newInstance() :
					DnieProvider.getDefaultApduConnection();
    	}
    	catch(final Exception e) {
    		throw new IllegalStateException("No hay una conexion de APDU por defecto", e); //$NON-NLS-1$
    	}

        // Aqui se realiza el acceso e inicializacion del DNIe
    	this.cryptoCard = DnieFactory.getDnie(
    		conn,
    		password != null ? new CachePasswordCallback(password) : null,
			CRYPTO_HELPER,
			null,
			isAnotherCardsAllowed()
		);

    	this.aliases = Arrays.asList(this.cryptoCard.getAliases());
    }
    
    /**
     * Indica si se va a permitir la carga de otras tarjetas compatibles con JMulticard a traves de esta implementaci&oacute;n.
     * La implementaci&oacute;n por defecto siempre devuelve {@code false}.
     * @return {@code true} si se permite la carga de otras tarjetas, {@code false} en caso contrario.
     */
    @SuppressWarnings("static-method")
	protected boolean isAnotherCardsAllowed() {
    	return false;
    }
}