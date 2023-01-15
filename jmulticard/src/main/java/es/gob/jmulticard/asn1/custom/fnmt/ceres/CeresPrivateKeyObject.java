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
package es.gob.jmulticard.asn1.custom.fnmt.ceres;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.der.pkcs15.CommonKeyAttributes;
import es.gob.jmulticard.asn1.der.pkcs15.PrivateKeyObject;

/** Tipo ASN&#46;1 PKCS#15 <i>PrivateKeyObject</i> espec&iacute;fico para ciertas tarjetas FNMT CERES.
 * <pre>
 *  PrivateKeyObject {KeyAttributes} ::= PKCS15Object {
 *    CommonKeyAttributes,
 *    CommonPrivateKeyAttributes,
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
 *    CommonPrivateKeyAttributes,
 *    PrivateRsaKeyAttributes
 *  }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class CeresPrivateKeyObject extends PrivateKeyObject {

	/** Construye un objeto ASN&#46;1 PKCS#15 <i>PrivateKeyObject</i>
	 * espec&iacute;fico para ciertas tarjetas FNMT CERES. */
	public CeresPrivateKeyObject() {
		super(
		 // CommonObjectAttributes (heredado de Pkcs15Object)
			CommonKeyAttributes.class,                              // ClassAttributes
			CeresCommonPrivateKeyAttributesContextSpecific.class,   // SubclassAttributes
			CeresPrivateRsaKeyAttributesContextSpecific.class       // TypeAttributes
		);
	}

	@Override
	public byte[] getKeyIdentifier() {
		return ((CommonKeyAttributes)getClassAttributes()).getIdentifier();
	}

	@Override
	public byte getKeyReference() {
		return ((CommonKeyAttributes)getClassAttributes()).getReference().getIntegerValue().byteValue();
	}

	@Override
	public String getKeyPath() {
		return ((CeresPrivateRsaKeyAttributesContextSpecific)getTypeAttributes()).getPath();
	}

    @Override
    public String toString() {
    	return "Clave privada con ruta '" + getKeyPath() + //$NON-NLS-1$
			"', identificador '" + HexUtils.hexify(getKeyIdentifier(), true) + //$NON-NLS-1$
			"' y referencia '0x" + HexUtils.hexify(new byte[] { getKeyReference() }, false); //$NON-NLS-1$
    }
}
