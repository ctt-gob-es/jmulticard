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

/** Registro de objetos ASN&#46;1. Un registro de objetos es una concatenaci&oacute;n directa de tipos ASN&#46;1 pero
 * sin construir un tipo compuesto, por lo que no conforma en si un TLV (y no tiene etiqueta de tipo). Todos los
 * objetos concatenados deben ser del mismo tipo ASN&#46;1.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class Record extends DecoderObject {

    private transient final OptionalDecoderObjectElement[] elementsTypes;

    private transient final List<DecoderObject> elements = new ArrayList<>();

    /** Construye un elemento <i>Record Of</i>.
     * @param types Tipos de los objetos ASN&#46;1 que va a contener el registro (que obligatoriamente deben ser
     *              subclases de <code>DecoderObject</code>. */
	protected Record(final OptionalDecoderObjectElement... types) {
        if (types == null || types.length == 0) {
            throw new IllegalArgumentException(
        		"Los tipos de los elementos del registro no pueden ser nulos ni vacios" //$NON-NLS-1$
            );
        }
        elementsTypes = new OptionalDecoderObjectElement[types.length];
        System.arraycopy(types, 0, elementsTypes, 0, types.length);
    }

    /** Obtiene el n&uacute;mero de elementos en el registro.
     * @return N&uacute;mero de elementos en el registro */
    protected int getElementCount() {
        return elements.size();
    }

    /** Obtiene el elemento ASN&#46;1 situado en una posici&oacute;n concreta del registro.
     * @param pos Posici&oacute;n del elemento deseado.
     * @return Elemento ASN&#46;1 situado en la posici&oacute;n indicada. */
    protected DecoderObject getElementAt(final int pos) {
        if (pos < 0 || pos >= elements.size()) {
            throw new IndexOutOfBoundsException("No existe un elemento en este registro en el indice " + Integer.toString(pos)); //$NON-NLS-1$
        }
        return elements.get(pos);
    }

    @Override
    protected void decodeValue() throws Asn1Exception, TlvException {
        if (getRawDerValue().length == 0) {
            throw new Asn1Exception("El valor del objeto ASN.1 esta vacio"); //$NON-NLS-1$
        }
        int offset = 0;
        Tlv tlv;
        byte[] remainingBytes;
        DecoderObject tmpDo;
        for (int i = 0; i < elementsTypes.length; i++) {
        	try {
	            remainingBytes = new byte[getRawDerValue().length - offset];
	            System.arraycopy(getRawDerValue(), offset, remainingBytes, 0, remainingBytes.length);
	            tlv = new Tlv(remainingBytes);
	            try {
	                tmpDo = elementsTypes[i].getElementType().getConstructor().newInstance();
	            }
	            catch (final Exception e) {
	                throw new Asn1Exception(
	            		"No se ha podido instanciar un " + elementsTypes[i].getElementType().getName() + //$NON-NLS-1$
	                        " en la posicion " + Integer.toString(i) + " del registro", e //$NON-NLS-1$ //$NON-NLS-2$
	                );
	            }
	            tmpDo.checkTag(tlv.getTag());
        	}
        	catch(final Exception e) {
            	if (elementsTypes[i].isOptional()) {
                	// Como no ha avanzado el offset, se reutilizara el tipo en el proximo elemento
            		continue;
            	}
            	throw new Asn1Exception("Error en el elemento " + i + " del registro ASN.1", e); //$NON-NLS-1$ //$NON-NLS-2$
        	}
            offset = offset + tlv.getBytes().length;
        	tmpDo.setDerValue(tlv.getBytes());
            elements.add(tmpDo);
        }
    }

    @Override
    protected byte getDefaultTag() {
        throw new UnsupportedOperationException("No hay tipo por defecto"); //$NON-NLS-1$
    }
}