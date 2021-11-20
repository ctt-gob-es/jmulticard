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
package es.gob.jmulticard.apdu.connection.cwa14890;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduEncrypter;
import es.gob.jmulticard.apdu.connection.ApduEncrypterDesMac8;
import es.gob.jmulticard.card.cwa14890.Cwa14890Card;
import es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants;
import es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants;

/** Clase para el establecimiento y control del canal seguro con tarjeta inteligente y MAC de 8 octetos. */
public class Cwa14890OneV2Connection extends Cwa14890OneV1Connection {

	@Override
	protected ApduEncrypter instantiateApduEncrypter() {
    	return new ApduEncrypterDesMac8();
    }

	@Override
	public String toString() {
    	return "Conexion de tipo CWA-14890-V2 " + //$NON-NLS-1$
			(isOpen()
				? "abierta sobre " + getSubConnection() //$NON-NLS-1$
					: "cerrada"); //$NON-NLS-1$
    }

    /** Crea el canal seguro CWA-14890 para la comunicaci&oacute;n de la tarjeta. Es necesario abrir el
     * canal asoci&aacute;ndolo a una conexi&oacute;n para poder trasmitir APDUs. Si no se indica una conexi&oacute;n
     * se utilizar&aacute;a la conexi&oacute;n impl&iacute;cita de la tarjeta indicada.
     * @param connection Conexi&oacute;n sobre la cual montar el canal seguro.
     * @param cryptoHelper Motor de operaciones criptogr&aacute;ficas. */
	public Cwa14890OneV2Connection(final ApduConnection connection,
			                       final CryptoHelper cryptoHelper) {
		super(connection, cryptoHelper);
	}

    /** Crea el canal seguro CWA-14890 para la comunicaci&oacute;n de la tarjeta. Es necesario abrir el
     * canal asoci&aacute;ndolo a una conexi&oacute;n para poder trasmitir APDUs. Si no se indica una conexi&oacute;n
     * se utilizar&aacute;a la conexi&oacute;n impl&iacute;cita de la tarjeta indicada.
     * @param card Tarjeta con la funcionalidad CWA-14890.
     * @param connection Conexi&oacute;n sobre la cual montar el canal seguro.
     * @param cryptoHelper Motor de operaciones criptogr&aacute;ficas.
     * @param cwaConsts Clase de claves p&uacute;blicas CWA-14890.
     * @param cwaPrivConsts Clase de claves privadas CWA-14890. */
	public Cwa14890OneV2Connection(final Cwa14890Card card,
			                       final ApduConnection connection,
			                       final CryptoHelper cryptoHelper,
			                       final Cwa14890PublicConstants cwaConsts,
			                       final Cwa14890PrivateConstants cwaPrivConsts) {
		super(card, connection, cryptoHelper, cwaConsts, cwaPrivConsts);
	}
}