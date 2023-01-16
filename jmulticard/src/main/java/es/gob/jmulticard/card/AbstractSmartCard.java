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
package es.gob.jmulticard.card;

import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;

/** Tarjeta inteligente gen&eacute;rica.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class AbstractSmartCard implements Card {

	/** Establece el modo de depuraci&oacute;n para todo el proyecto. */
	public static final boolean DEBUG = true;

	/** Clase por defecto de APDU de la tarjeta. */
    private final byte cla;

    /** Conexi&oacute;n con el lector de tarjetas. */
    private ApduConnection connection;

    /** Obtiene la conexi&oacute;n de la tarjeta.
     * @return Conexi&oacute;n de la tarjeta. */
    protected ApduConnection getConnection() {
        return connection;
    }

    /** Env&iacute;a una APDU a la tarjeta.
     * @param apdu APDU a enviar.
     * @return APDU de respuesta.
     * @throws ApduConnectionException En cualquier error. */
    protected ResponseApdu sendArbitraryApdu(final CommandApdu apdu) throws ApduConnectionException {
    	return connection.transmit(apdu);
    }

    /** Establece una nueva conexi&oacute;n con la tarjeta.
     * No se cierra la conexi&oacute;n anterior.
     * @param conn Nueva conexi&oacute;n con la tarjeta.
     * @throws ApduConnectionException Cuando no se puede sustituir la conexi&oacute;n actual por la nueva. */
    protected void setConnection(final ApduConnection conn) throws ApduConnectionException {
        if (!conn.isOpen()) {
            conn.open();
        }
        connection = conn;
    }

    /** Obtiene la clase de APDU por defecto de la tarjeta.
     * @return Clase de APDU por defecto de la tarjeta. */
    protected byte getCla() {
        return cla;
    }

    /** Construye una tarjeta inteligente gen&eacute;rica.
     * @param c Octeto de clase (CLA) de las APDU
     * @param conn Connexi&oacute;n con la tarjeta. */
    public AbstractSmartCard(final byte c, final ApduConnection conn) {
        if (conn == null) {
            throw new IllegalArgumentException("La conexion con la tarjeta no puede ser nula"); //$NON-NLS-1$
        }
        cla = c;
        connection = conn;
    }

    /** Obtiene el nombre de la tarjeta.
     * @return Nombre de la tarjeta */
    public abstract String getCardName();
}
