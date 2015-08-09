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

import java.util.ArrayList;
import java.util.List;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

/** Tipo ASN&#46;1 <i>Sequence</i>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public abstract class Sequence extends DecoderObject {

    /** Tipo ASN&#46;1 <i>Sequence</i>. */
    private static final byte TAG_SEQUENCE = (byte) 0x30;

    private final List<DecoderObject> elements = new ArrayList<DecoderObject>();

    private final OptionalDecoderObjectElement[] elementsTypes;

    protected int getElementCount() {
    	return this.elements.size();
    }

    /** Construye un tipo ASN&#46;1 <i>Sequence</i>.
     * Un <i>Sequence</i> contiene una secuencia de tipos ASN&#46;1 (que pueden ser distintos)
     * @param types Tipos (etiquetas) de objetos ASN&#46;1 (cero a n elementos) que va a contener la secuencia. El orden es relevante */
	protected Sequence(final OptionalDecoderObjectElement[] types) {
        super();
        if (types == null) {
            throw new IllegalArgumentException();
        }
        this.elementsTypes = new OptionalDecoderObjectElement[types.length];
        System.arraycopy(types, 0, this.elementsTypes, 0, types.length);
    }

    @Override
    protected void decodeValue() throws Asn1Exception, TlvException {
        final Tlv mainTlv = new Tlv(this.getRawDerValue());
        checkTag(mainTlv.getTag());
        int offset = 0;
        Tlv tlv;
        byte[] remainingBytes;
        DecoderObject tmpDo;
        final byte[] rawValue = mainTlv.getValue();
        for (int i = 0; i < this.elementsTypes.length; i++) {
            remainingBytes = new byte[rawValue.length - offset];
            System.arraycopy(rawValue, offset, remainingBytes, 0, remainingBytes.length);
            try {
            	tlv = new Tlv(remainingBytes);
            	tmpDo = this.elementsTypes[i].getElementType().newInstance();
            	tmpDo.checkTag(tlv.getTag());
                tmpDo.setDerValue(tlv.getBytes());
            }
            catch(final Exception e) {
            	if (this.elementsTypes[i].isOptional()) {
                	// Como no ha avanzado el offset, se reutilizara el tipo en el proximo elemento
            		continue;
            	}
            	throw new Asn1Exception("Error en el elemento " + i + " (" + this.elementsTypes[i].getElementType().getName() + ") de la secuencia ASN.1: " + e, e); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            }
            // El offset se avanza antes del continue de la opcionalidad
            offset = offset + tlv.getBytes().length;
            this.elements.add(tmpDo);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected byte getDefaultTag() {
        return TAG_SEQUENCE;
    }

    /** Devuelve el elemento situado en la posici&oacute;n indicada.
     * @param index Posici&oacute;n del elemento a recuperar
     * @return Un objeto de tipo <code>DecoderObject</code> que contiene el TLV deseado.
     * @throws IndexOutOfBoundsException Si el indice indicado no pertenece al rango de la secuencia */
    protected DecoderObject getElementAt(final int index) {
        return this.elements.get(index);
    }
}