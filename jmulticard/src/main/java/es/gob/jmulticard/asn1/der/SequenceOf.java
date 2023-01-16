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
package es.gob.jmulticard.asn1.der;

import java.util.Vector;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

/** Tipo ASN&#46;1 <i>SequenceOf</i>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class SequenceOf extends DecoderObject {

	/** Tipo ASN&#46;1 <i>SequenceOf</i>. */
    private static final byte TAG_SEQUENCE = (byte) 0x30;

    private transient final Class<? extends DecoderObject> elementsType;

    private transient Vector<DecoderObject> sequenceObjects = null;

	@Override
    protected void decodeValue() throws Asn1Exception, TlvException {
		Tlv tlv = new Tlv(getRawDerValue());
		checkTag(tlv.getTag());
		int offset = 0;
		byte[] remainingBytes;
        DecoderObject tmpDo;
        final byte[] valueBytes = tlv.getValue();
        sequenceObjects = new Vector<>();
        while (offset < valueBytes.length) {
        	remainingBytes = new byte[valueBytes.length - offset];
        	System.arraycopy(valueBytes, offset, remainingBytes, 0, remainingBytes.length);
    		tlv = new Tlv(remainingBytes);
        	try {
        		tmpDo = elementsType.getConstructor().newInstance();
        	}
        	catch (final Exception e) {
        		throw new Asn1Exception(
    				"No se ha podido instanciar un " + elementsType.getName() + " en la secuencia", e  //$NON-NLS-1$ //$NON-NLS-2$
        		);
        	}
        	offset = offset + tlv.getBytes().length;
        	tmpDo.checkTag(tlv.getTag());
        	tmpDo.setDerValue(tlv.getBytes());
        	sequenceObjects.add(tmpDo);
        }
	}

	/** Construye un tipo ASN&#46;1 <i>SequenceOf</i>.
     * Un <i>SequenceOf</i> contiene una secuencia de tipos ASN&#46;1 (que deben ser iguales).
     * @param type Tipos (etiquetas) de objetos ASN&#46;1 (1 a n elementos) que va a contener la secuencia. El orden es irrelevante. */
	protected SequenceOf(final Class<? extends DecoderObject> type) {
	    if (type == null) {
			throw new IllegalArgumentException();
		}
		elementsType = type;
	}

    @Override
    protected byte getDefaultTag() {
        return TAG_SEQUENCE;
    }

    /** Devuelve el elemento situado en la posici&oacute;n indicada.
     * @param index Posici&oacute;n del elemento a recuperar.
     * @return Un objeto de tipo <code>DecoderObject</code> que contiene el TLV deseado.
     * @throws IndexOutOfBoundsException Si el indice indicado no pertenece al rango de la secuencia. */
    protected DecoderObject getElementAt(final int index) {
        return sequenceObjects.elementAt(index);
    }

    /** Obtiene el n&uacute;mero de elementos que contiene la secuencia.
     * @return N&uacute;mero de elementos que contiene la secuencia. */
    protected int getElementCount() {
    	return sequenceObjects.size();
    }

}
