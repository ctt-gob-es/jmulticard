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
package es.gob.jmulticard.card.iso7816four;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.Apdu;
import es.gob.jmulticard.apdu.StatusWord;

/** Excepci&oacute;n gen&eacute;rica en tarjetas ISO 7816-4.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class Iso7816FourCardException extends Exception {

	/** C&oacute;digo de retorno que se obtuvo tras producirse el error. */
    private transient final StatusWord returnCode;

    /** Crea una excepci&oacute;n referente a ISO 7816-4 en base a una palabra de estado.
     * @param desc Descripci&oacute;n de la excepci&oacute;n.
     * @param retCode Palabra de estado. */
    public Iso7816FourCardException(final String desc, final StatusWord retCode) {
        super(desc);
        this.returnCode = retCode;
    }

    /** Crea una excepci&oacute;n referente a ISO 7816-4 en base a una palabra de estado.
     * @param retCode Palabra de estado.
     * @param origin APDU que gener&oacute; la palabra de estado. */
    public Iso7816FourCardException(final StatusWord retCode, final Apdu origin) {
        super(
    		"Codigo de retorno: " + retCode + //$NON-NLS-1$
    			", APDU de origen: " + HexUtils.hexify(origin.getBytes(), true) //$NON-NLS-1$
		);
        this.returnCode = retCode;
    }

    /** Crea una excepci&oacute;n referente a ISO 7816-4.
     * @param desc Descripci&oacute;n de la excepci&oacute;n.
     * @param e Excepci&oacute;n de origen. */
    public Iso7816FourCardException(final String desc, final Throwable e) {
    	super(desc, e);
    	this.returnCode = null;
    }

    /** Crea una excepci&oacute;n referente a ISO 7816-4.
     * @param desc Descripci&oacute;n de la excepci&oacute;n. */
    public Iso7816FourCardException(final String desc) {
    	super(desc);
    	this.returnCode = null;
    }

    /** Crea una excepci&oacute;n referente a ISO 7816-4 en base a una palabra de estado.
     * @param retCode Palabra de estado.
     * @param origin APDU que gener&oacute; la palabra de estado.
     * @param desc Descripci&oacute;n de la excepci&oacute;n. */
    public Iso7816FourCardException(final StatusWord retCode, final Apdu origin, final String desc) {
        super(
    		(desc != null ? desc + " - " : "") + //$NON-NLS-1$ //$NON-NLS-2$
    			"Codigo de retorno " + retCode + //$NON-NLS-1$
    				", APDU de origen: " + HexUtils.hexify(origin.getBytes(), true) //$NON-NLS-1$
		);
        this.returnCode = retCode;
    }

    /** Identificador de versi&oacute;n para la serializaci&oacute;n. */
    private static final long serialVersionUID = 5935577997660561619L;

    /** Obtiene el c&oacute;digo de finalizaci&oacute;n (en modo de palabra de estado) que caus&oacute; la
     * excepci&oacute;n.
     * @return C&oacute;digo de finalizaci&oacute;n que caus&oacute; la excepci&oacute;n */
    public StatusWord getStatusWord() {
        return this.returnCode;
    }
}
