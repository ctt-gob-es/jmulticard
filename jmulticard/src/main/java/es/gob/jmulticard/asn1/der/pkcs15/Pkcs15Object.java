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
package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.ContextSpecific;
import es.gob.jmulticard.asn1.der.Sequence;

/** Tipo PKCS#15 ASN&#46;1 <i>PKCS15Object</i> (<i>CIO</i> de ISO 7816-15).
 * <pre>
 *  PKCS15Object ::= SEQUENCE {
 *      commonObjectAttributes CommonObjectAttributes,
 *      classAttributes ClassAttributes,
 *      subclassAttributes SubclassAttributes OPTIONAL,
 *      typeAttributes [1] TypeAttributes
 *  }
 * </pre>
 * @author Gonzalo Henr&iacute;quez Manzano
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class Pkcs15Object extends Sequence {

    /** Construye un tipo PKCS#15 ASN&#46;1 <i>PKCS15Object</i> (<i>CIO</i> de ISO 7816-15).
     * @param classAttributes Tipo de los Atributos espec&iacute;ficos de la clase general del objeto
     * @param subclassAttributes Tipo de los Atributos espec&iacute;ficos de la subclase general del objeto
     * @param typeAttributes Tipo de los Atributos espec&iacute;ficos del tipo concreto del objeto */
	protected Pkcs15Object(final Class<? extends DecoderObject> classAttributes,
			               final Class<? extends ContextSpecific> subclassAttributes,
			               final Class<? extends ContextSpecific> typeAttributes) {
        super(
			new OptionalDecoderObjectElement(
				CommonObjectAttributes.class,
				false
			),
			new OptionalDecoderObjectElement(
				classAttributes,
				false
			),
			new OptionalDecoderObjectElement(
				subclassAttributes,
				true
			),
			new OptionalDecoderObjectElement(
				typeAttributes,
				false
			)
		);
    }

    /** Obtiene los atributos comunes (<i>CommonObjectAttributes</i>).
     * @return Atributos comunes */
    protected final CommonObjectAttributes getCommonObjectAttributes() {
        return (CommonObjectAttributes) getElementAt(0);
    }

    /** Obtiene los atributos espec&iacute;ficos de clase.
     * @return Atributos espec&iacute;ficos de clase */
    public final DecoderObject getClassAttributes() {
        return getElementAt(1);
    }

    /** Obtiene los atributos espec&iacute;ficos de subclase.
     * @return Atributos espec&iacute;ficos de subclase */
    public final DecoderObject getSubclassAttributes() {
    	// Si solo hay tres elementos, es que no hay SubclassAttributes,
    	// ya que es el unico elemento opcional
    	if (getElementCount() == 3) {
    		return null;
    	}
    	return getElementAt(2);
    }

    /** Obtiene los atributos espec&iacute;ficos del tipo.
     * @return Atributos espec&iacute;ficos del tipo */
    public final DecoderObject getTypeAttributes() {
    	if (getElementCount() == 3) {
    		return getElementAt(2);
    	}
    	return getElementAt(3);
    }
}
