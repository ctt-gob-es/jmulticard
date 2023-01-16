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
package es.gob.jmulticard.asn1.custom.fnmt.ceressc;

import javax.security.auth.x500.X500Principal;

import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.der.ContextSpecific;
import es.gob.jmulticard.asn1.der.pkcs15.CommonKeyAttributes;
import es.gob.jmulticard.asn1.der.pkcs15.CommonPrivateKeyAttributesContextSpecific;
import es.gob.jmulticard.asn1.der.pkcs15.Pkcs15Object;

/** Tipo ASN&#46;1 PKCS#15 <i>PrivateKeyObject</i> para tarjetas CERES, donde pueden encontrarse
 * ligeras diferencias respecto a la normativa general.
 * <pre>
 *  PrivateKeyObject {KeyAttributes} ::= PKCS15Object {
 *    CommonKeyAttributes,
 *    CommonPrivateKeyAttributesEmpty,
 *    KeyAttributes
 *  }
 * </pre>
 * Que en el caso de claves privadas RSA (instanciando como
 * <code>PrivateKeyObject {PrivateRSAKeyAttributes}</code>) y deshaciendo <code>PKCS15Object</code>
 * en su secuencia queda la estructura:
 * <pre>
 *  PrivateKeyObject {PrivateRSAKeyAttributes} ::= SEQUENCE {
 *    CommonObjectAttributes,
 *    CommonKeyAttributes,
 *    CommonPrivateKeyAttributesEmpty,
 *    PrivateRsaKeyAttributes
 *  }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CeresScPrivateKeyObject extends Pkcs15Object {

    /** Construye un tipo PrivateKeyObject ASN&#46;1.
     * @param classAttributes Tipo de los Atributos espec&iacute;ficos de la clase general del objeto
     * @param subclassAttributes Tipo de los Atributos espec&iacute;ficos de la subclase general del objeto
     * @param typeAttributes Tipo de los Atributos espec&iacute;ficos del tipo concreto del objeto */
	public CeresScPrivateKeyObject(final Class<? extends DecoderObject> classAttributes,
			                     final Class<? extends ContextSpecific> subclassAttributes,
			                     final Class<? extends ContextSpecific> typeAttributes) {
        super(classAttributes, subclassAttributes, typeAttributes);
	}


	/** Construye un objeto ASN&#46;1 PKCS#15 <i>PrivateKeyObject</i> */
	public CeresScPrivateKeyObject() {
		super(
		 // CommonObjectAttributes (heredado de Pkcs15Object)
			CommonKeyAttributes.class,                            // classAttributes
			CeresScCommonPrivateKeyAttributesContextSpecific.class, // subclassAttributes
			CeresScPrivateRsaKeyAttributesContextSpecific.class     // typeAttributes
		);
	}

	/** Obtiene el identificador de la clave privada.
	 * @return Nombre de la clave privada */
	public byte[] getKeyIdentifier() {
		return ((CommonKeyAttributes) getClassAttributes()).getIdentifier();
	}

	/** Obtiene el nombre de la clave privada.
	 * @return Nombre de la clave privada */
	String getKeyName() {
		return getCommonObjectAttributes().getLabel();
	}

	/** Obtiene la ruta hacia la clave privada.
	 * @return Ruta hacia la clave privada. */
	public String getKeyPath() {
		return ((CeresScPrivateRsaKeyAttributesContextSpecific)getTypeAttributes()).getPath();
	}

	/** Obtiene la longitud de la clave privada.
	 * @return Longitud de la clave privada. */
	int getKeyLength() {
		return ((CeresScPrivateRsaKeyAttributesContextSpecific)getTypeAttributes()).getKeyLength();
	}

	/** Obtiene el <code>Principal</code> X&#46;509 de la clave privada.
	 * @return <code>Principal</code> X&#46;509 de la clave privada. */
	X500Principal getKeyPrincipal() {
		final Object o = getSubclassAttributes();
		if (o instanceof CommonPrivateKeyAttributesContextSpecific) {
			return ((CommonPrivateKeyAttributesContextSpecific)o).getKeyPrincipal();
		}
		return null;
	}

    @Override
    public String toString() {
    	return "Nombre de la clave privada: " + getCommonObjectAttributes().getLabel() + //$NON-NLS-1$
			(getSubclassAttributes() != null ?
			 "\n" + ((CommonPrivateKeyAttributesContextSpecific)getSubclassAttributes()).getKeyPrincipal() : //$NON-NLS-1$
				 ""); //$NON-NLS-1$
    }

	/** Obtiene la referencia de la clave.
	 * @return Referencia de la clave. */
	public byte getKeyReference() {
		return ((CommonKeyAttributes)getClassAttributes()).getReference().getIntegerValue().byteValue();
	}
}
