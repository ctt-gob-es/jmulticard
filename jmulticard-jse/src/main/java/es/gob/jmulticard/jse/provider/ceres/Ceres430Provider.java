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
package es.gob.jmulticard.jse.provider.ceres;

import java.security.Provider;
import java.security.ProviderException;

import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.jse.provider.ProviderUtil;

/** Proveedor criptogr&aacute;fico JCA para tarjetas CERES 4.30 o superiores. Esta tarjeta es
 * exactamente igual que un DNIe 3.0, por lo que usaremos sus mismas clases.
 * Crea dos servicios:
 * <dl>
 * <dt><code>KeyStore</code></dt>
 * <dd><i>CERES430</i></dd>
 * <dt><code>Signature</code></dt>
 * <dd><i>SHA1withRSA</i>, <i>SHA256withRSA</i>, <i>SHA384withRSA</i>, <i>SHA512withRSA</i></dd>
 * </dl>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Ceres430Provider extends Provider {

	/** Firma RSA con huellas SHA-512. */
    private static final String SHA512WITH_RSA = "SHA512withRSA"; //$NON-NLS-1$

    /** Firma RSA con huellas SHA-384. */
    private static final String SHA384WITH_RSA = "SHA384withRSA"; //$NON-NLS-1$

    /** Firma RSA con huellas SHA-256. */
    private static final String SHA256WITH_RSA = "SHA256withRSA"; //$NON-NLS-1$

    /** Firma RSA con huellas SHA-1. */
    private static final String SHA1WITH_RSA = "SHA1withRSA"; //$NON-NLS-1$

    private static final String CERES_PRIVATE_KEY = "es.gob.jmulticard.jse.provider.DniePrivateKey"; //$NON-NLS-1$

    private static final long serialVersionUID = 4544152908167923163L;

    private static final String INFO = "Proveedor para tarjetas FNMT CERES 4.30 o superior"; //$NON-NLS-1$
    private static final double VERSION = 0.2;
    private static final String NAME = "Ceres430JCAProvider"; //$NON-NLS-1$

    private static ApduConnection defaultConnection = null;

    /** Obtiene de forma est&aacute;tica el tipo de conexi&oacute;n de APDU que debe usar el <i>keyStore</i>.
     * Si es nula (se ha invocado al constructor por defecto), es el propio <code>KeyStore</code> el que decide que
     * conexi&oacute;n usar.
     * @return Conexi&oacute;n por defecto */
    static ApduConnection getDefaultApduConnection() {
    	return defaultConnection;
    }

    /** Crea un proveedor JCA para tarjetas FNMT CERES 4.30 o superiores con la conexi&oacute;n por defecto. */
    public Ceres430Provider() {
    	this(null);
    }

    /** Crea un proveedor JCA para tarjetas CERES 4.30 o superiores.
     * @param conn Conexi&oacute;n a usar para el env&iacute;o y recepci&oacute;n de APDU. */
    public Ceres430Provider(final ApduConnection conn) {
        super(NAME, VERSION, INFO);

        try {
			defaultConnection = conn == null ?
				(ApduConnection) Class.forName(ProviderUtil.DEFAULT_PROVIDER_CLASSNAME).getConstructor().newInstance() :
					conn;
		}
        catch (final Exception e) {
			throw new ProviderException(
				"No se ha proporcionado una conexion con un lector y no ha podido instanciarse la por defecto", e //$NON-NLS-1$
			);
		}

        try {
        	Dnie.connect(defaultConnection);
        	defaultConnection.close();
        }
        catch(final Exception e) {
        	throw new ProviderException(
    			"No se ha podido inicializar el proveedor de Ceres 4.30 y superior", e //$NON-NLS-1$
			);
        }

        // KeyStore
        put("KeyStore.CERES430", "es.gob.jmulticard.jse.provider.ceres.Ceres430KeyStoreImpl"); //$NON-NLS-1$ //$NON-NLS-2$

        // Motores de firma
        put("Signature.SHA1withRSA",   "es.gob.jmulticard.jse.provider.DnieSignatureImpl$Sha1"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA256withRSA", "es.gob.jmulticard.jse.provider.DnieSignatureImpl$Sha256"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA384withRSA", "es.gob.jmulticard.jse.provider.DnieSignatureImpl$Sha384"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA512withRSA", "es.gob.jmulticard.jse.provider.DnieSignatureImpl$Sha512"); //$NON-NLS-1$ //$NON-NLS-2$

        // Claves soportadas
        put("Signature.SHA1withRSA SupportedKeyClasses",   Ceres430Provider.CERES_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA256withRSA SupportedKeyClasses", Ceres430Provider.CERES_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA384withRSA SupportedKeyClasses", Ceres430Provider.CERES_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA512withRSA SupportedKeyClasses", Ceres430Provider.CERES_PRIVATE_KEY); //$NON-NLS-1$

        // Alias de los nombres de algoritmos de firma
        put("Alg.Alias.Signature.1.2.840.113549.1.1.5",     Ceres430Provider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", Ceres430Provider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.1.3.14.3.2.29",            Ceres430Provider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHAwithRSA",               Ceres430Provider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-1withRSA",             Ceres430Provider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA1withRSAEncryption",    Ceres430Provider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-1withRSAEncryption",   Ceres430Provider.SHA1WITH_RSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.113549.1.1.11",     Ceres430Provider.SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.11", Ceres430Provider.SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-256withRSA",            Ceres430Provider.SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-256withRSAEncryption",  Ceres430Provider.SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA256withRSAEncryption",   Ceres430Provider.SHA256WITH_RSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.113549.1.1.12",     Ceres430Provider.SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.12", Ceres430Provider.SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-384withRSA",            Ceres430Provider.SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-384withRSAEncryption",  Ceres430Provider.SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA384withRSAEncryption",   Ceres430Provider.SHA384WITH_RSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.113549.1.1.13",     Ceres430Provider.SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.13", Ceres430Provider.SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-512withRSA",            Ceres430Provider.SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-512withRSAEncryption",  Ceres430Provider.SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA512withRSAEncryption",   Ceres430Provider.SHA512WITH_RSA); //$NON-NLS-1$
    }
}