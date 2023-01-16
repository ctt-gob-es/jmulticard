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

import java.io.Serializable;

import es.gob.jmulticard.HexUtils;

/** Respuesta al reset (ATR, <i>Answer To Reset</i>) de una tarjeta.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class Atr implements Serializable {

	/** Identificador de versi&oacute;n para la serializaci&oacute;n. */
    private static final long serialVersionUID = 1L;

    /** Octetos del ATR. */
    protected transient final byte[] atrBytes;

    /** M&aacute;scara de posiciones con valor constante dentro de los octetos del ATR. */
    private transient final byte[] mask;

    /** Construye una respuesta al reset.
     * @param cardAtr ATR de la tarjeta
     * @param atrMask M&aacute;scara de comparaci&oacute;n del ATR para determinar modelo espec&iacute;fico
     *        de tarjeta */
    public Atr(final byte[] cardAtr, final byte[] atrMask) {
        if (cardAtr == null || atrMask == null) {
            throw new IllegalArgumentException("El ATR y su mascara no pueden ser nulos"); //$NON-NLS-1$
        }
        atrBytes = new byte[cardAtr.length];
        System.arraycopy(cardAtr, 0, atrBytes, 0, cardAtr.length);
        mask = new byte[atrMask.length];
        System.arraycopy(atrMask, 0, mask, 0, atrMask.length);
    }

    @Override
	public String toString() {
    	return HexUtils.hexify(getBytes(), false);
    }

    /** Obtiene la m&aacute;scara de comparaci&oacute;n del ATR.
     * @return M&aacute;scara de comparaci&oacute;n del ATR. */
    public byte[] getMask() {
    	return mask.clone();
    }

    /** Obtiene los octetos binarios de la respuesta al reset.
     * @return Representaci&oacute;n binaria de la respuesta al reset */
    public byte[] getBytes() {
        final byte[] tmp = new byte[atrBytes.length];
        System.arraycopy(atrBytes, 0, tmp, 0, atrBytes.length);
        return tmp;
    }

    @Override
    public boolean equals(final Object o) {
    	if (!(o instanceof Atr)) {
    		return false;
    	}

    	final byte[] tmpAtrBytes;
    	tmpAtrBytes = ((Atr) o).getBytes();

        if (atrBytes.length < tmpAtrBytes.length) {
        	return false;
        }
        final int offset = atrBytes.length - tmpAtrBytes.length;
        for (int i=tmpAtrBytes.length-1; i>=0; i--) {
            if ((atrBytes[i+offset] & mask[i+offset]) != (tmpAtrBytes[i] & mask[i+offset])) {
                return false;
            }
        }
        return true;
    }

    @Override
    public int hashCode() {
        return hashCode(atrBytes) + hashCode(mask);
    }

    private static int hashCode(final byte[] a) {
        if (a == null) {
            return 0;
        }
        int result = 1;
        for (final byte element : a) {
            result = 31 * result + element;
        }
        return result;
    }
}
