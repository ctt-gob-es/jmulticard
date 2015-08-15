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

import java.math.BigInteger;

import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.der.ContextSpecific;


/** Tipo PKCS#15 ASN&#46;1 <i>CertificateObject</i> (<i>CertificateInfoObject</i> en ISO 7816-15).
 *  <pre>
 *    CertificateObject {CertAttributes} ::= PKCS15Object {
 *      CommonCertificateAttributes,
 *      NULL,
 *      CertAttributes
 *    }
 *  </pre>
 *  Que en el caso de un certificado X&#46;509 se instancia como
 *  <code>x509Certificate CertificateObject { X509CertificateAttributes }</code>,
 *  quedando la estructura (secuencia deshaciendo el <code>PKCS15Object</code>):
 *  <pre>
 *    CertificateObject {X509CertificateAttributes} ::= SEQUENCE {
 *      CommonObjectAttributes,
 *      CommonCertificateAttributes,
 *      NULL,
 *      X509CertificateAttributes
 *    }
 *
 *    CommonObjectAttributes ::= SEQUENCE {
 *      label Label,
 *      flags CommonObjectFlags OPTIONAL,
 *      authId Identifier OPTIONAL,
 *    }
 *    Label ::= UTF8String (SIZE(0..pkcs15-ub-label))
 *
 *    CommonCertificateAttributes ::= SEQUENCE {
 *      iD Identifier
 *    }
 *    Identifier ::= OCTET STRING (SIZE (0..pkcs15-ub-identifier))
 *
 *    X509CertificateAttributes ::= SEQUENCE {
 *      value ObjectValue { Certificate },
 *      subject Name,
 *      issuer [0] Name,
 *      serialNumber INTEGER
 *    }
 *    Name ::= CHOICE {
 *      rdnSequence RDNSequence
 *    }
 *
 *  </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class CertificateObject extends Pkcs15Object {

	/** Crea un objeto <i>CertificateObject</i>. */
	public CertificateObject() {
		super(
		//  CommonObjectAttributes (se hereda)
			CommonCertificateAttributes.class,
			null,
			X509CertificateAttributesContextSpecific.class
		);
	}

    /** Construye un tipo CertificateObject ASN&#46;1.
     * @param classAttributes Tipo de los Atributos espec&iacute;ficos de la clase general del objeto
     * @param subclassAttributes Tipo de los Atributos espec&iacute;ficos de la subclase general del objeto
     * @param typeAttributes Tipo de los Atributos espec&iacute;ficos del tipo concreto del objeto */
	protected CertificateObject(final Class<? extends DecoderObject> classAttributes,
			               final Class<? extends ContextSpecific> subclassAttributes,
			               final Class<? extends ContextSpecific> typeAttributes) {
        super(classAttributes, subclassAttributes, typeAttributes);
    }

	/** Proporciona el nombre X.500 del emisor del certificado
     * @return Nombre X.500 del emisor del certificado */
    String getIssuer() {
    	return ((X509CertificateAttributesContextSpecific)getTypeAttributes()).getIssuer();
    }

    /** Proporciona el nombre X.500 del titular del certificado
     * @return Nombre X.500 del emisor del certificado */
    String getSubject() {
    	return ((X509CertificateAttributesContextSpecific)getTypeAttributes()).getSubject();
    }

    /** Devuelve la ruta del certificado.
     * @return Ruta (<i>path</i>) del certificado */
    public String getPath() {
    	return ((X509CertificateAttributesContextSpecific)getTypeAttributes()).getPath();
    }

    /** Devuelve la ruta del certificado como array de octetos.
     * @return Ruta (<i>path</i>) del certificado como array de octetos. */
    public byte[] getPathBytes() {
    	return ((X509CertificateAttributesContextSpecific)getTypeAttributes()).getPathBytes();
    }

    /** Obtiene el n&uacute;mero de serie del Certificado.
     * @return N&uacute;mero de serie del Certificado */
    BigInteger getSerialNumber() {
    	return ((X509CertificateAttributesContextSpecific)getTypeAttributes()).getSerialNumber();
    }

	/** Obtiene el identificador binario del certificado.
	 * @return Identificador del certificado */
	public byte[] getIdentifier() {
		return ((CommonCertificateAttributes) getClassAttributes()).getId();
	}

	/** Obtiene el alias del certificado.
	 * @return Alias del certificado */
	public String getAlias() {
		return getCommonObjectAttributes().getLabel();
	}

    /** {@inheritDoc} */
    @Override
    public String toString() {
    	return getTypeAttributes().toString() +
			"\nAlias del certificado: " + getCommonObjectAttributes().getLabel() + //$NON-NLS-1$
			"\nIdentificador del certificado: " + getClassAttributes().toString(); //$NON-NLS-1$
    }

}
