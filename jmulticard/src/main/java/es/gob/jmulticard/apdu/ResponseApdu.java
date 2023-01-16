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
package es.gob.jmulticard.apdu;

/** APDU de respuesta para comunicaci&oacute;n con tarjeta inteligente.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class ResponseApdu extends Apdu {

	private final byte[] encryptedByes;

    /** Construye una APDU de respuesta a partir de su representaci&oacute;n
     * binaria directa.
     * @param fullBytes Representaci&oacute;n binaria directa de la APDU. */
    public ResponseApdu(final byte[] fullBytes) {
        setBytes(fullBytes);
        encryptedByes = null;
    }

    /** Construye una APDU de respuesta a partir de su representaci&oacute;n
     * binaria directa.
     * @param fullBytes Representaci&oacute;n binaria directa de la APDU.
     * @param encrypted Codificaci&oacute;n encriptada de la APDU. */
    public ResponseApdu(final byte[] fullBytes, final byte[] encrypted) {
        setBytes(fullBytes);
        encryptedByes = encrypted != null ? encrypted.clone() : null;
    }

    /** Obtiene el campo de datos de la APDU.
     * @return Campo de datos de la APDU. */
    public byte[] getData() {
        final byte[] dat = new byte[getBytes().length-2];
        System.arraycopy(getBytes(), 0, dat, 0, getBytes().length-2);
        return dat;
    }

    /** Obtiene la palabra de estado (<i>Status Word</i>) de la APDU.
     * @return Palabra de estado (<i>Status Word</i>) de la APDU. */
    public StatusWord getStatusWord() {
        return new StatusWord(getBytes()[getBytes().length - 2], getBytes()[getBytes().length - 1]);
    }

    /** Indica si la APDU es una respuesta correcta o no a un comando.
     * @return <code>true</code> si el comando termin&oacute; con &eacute;xito
     *         (termina en 90-00), <code>false</code> en caso contrario. */
    public boolean isOk() {
        if (getBytes() == null || getBytes().length < 2) {
            return false;
        }
        return getStatusWord().isOk();
    }

	/** Obtiene la codificaci&oacute;n encriptada de la APDU.
	 * @return Codificaci&oacute;n encriptada de la APDU si existe, la
	 *         codificaci&oacute;n en claro si es la &uacute;nica disponible. */
	public byte[] getEncryptedByes() {
		return encryptedByes != null ? encryptedByes : getBytes();
	}
}