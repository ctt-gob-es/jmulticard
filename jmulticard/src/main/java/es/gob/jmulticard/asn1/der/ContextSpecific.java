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

import java.lang.reflect.InvocationTargetException;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

/** Tipo ASN&#46;1 espec&iacute;fico del contexto.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class ContextSpecific extends DecoderObject {

    private transient DecoderObject object = null;

    /** Obtiene el objeto ASN&#46;1.
     * @return Objeto ASN&#46;1. */
    protected DecoderObject getObject() {
        if (object == null) {
            throw new IllegalStateException();
        }
        return object;
    }

    @Override
    protected void decodeValue() throws Asn1Exception, TlvException {

        final DecoderObject tmpDo;
        try {
            tmpDo = elementType.getConstructor().newInstance();
        }
        catch (final IllegalAccessException    |
        		     InstantiationException    |
        		     IllegalArgumentException  |
        		     InvocationTargetException |
        		     NoSuchMethodException     |
        		     SecurityException e) {
            throw new Asn1Exception(
        		"No se ha podido instanciar un " + elementType.getName() + " en el contexto especifico", e //$NON-NLS-1$ //$NON-NLS-2$
            );
        }
        final Tlv tlv = new Tlv(getRawDerValue());
        tmpDo.setDerValue(tlv.getValue());
        object = tmpDo;
    }

    private transient final Class<? extends DecoderObject> elementType;

    /** Construye un tipo ASN&#46;1 espec&iacute;fico del contexto.
     * @param type Tipo de elemento contenido dentro de este objeto. */
    public ContextSpecific(final Class<? extends DecoderObject> type) {
        if (type == null) {
            throw new IllegalArgumentException(
        		"El tipo contenido dentro de ContextSpecific no puede ser nulo" //$NON-NLS-1$
    		);
        }
        elementType = type;
    }

    @Override
    protected byte getDefaultTag() {
        throw new UnsupportedOperationException("No hay tipo por defecto"); //$NON-NLS-1$
    }

    @Override
    public void checkTag(final byte tag) throws Asn1Exception {
        if ((tag & 0x0c0) != 0x080) {
            throw new Asn1Exception(
        		"La etiqueta " + HexUtils.hexify(new byte[] { tag }, false) + //$NON-NLS-1$
                    " no es valida para un objeto especifico del contexto" //$NON-NLS-1$
            );
        }
    }
}