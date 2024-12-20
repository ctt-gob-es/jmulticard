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

import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.DerInteger;
import es.gob.jmulticard.asn1.der.Sequence;

/** Tipo ASN&#46;1 PKCS#15 <i>PrivateRsaKeyAttributes</i>.
 * <PRE>
 *   PrivateRSAKeyAttributes ::= SEQUENCE {
 *     value          ObjectValue {RSAPrivateKeyObject},
 *     modulusLength  INTEGER, -- modulus length in bits, e.g. 1024
 *     keyInfo        KeyInfo {NULL, PublicKeyOperations} OPTIONAL,
 *     ... -- For future extensions
 *   }
 * </PRE>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PrivateRsaKeyAttributes extends Sequence {

	/** Construye un objeto ASN&#46;1 PKCS#15 <i>PrivateRsaKeyAttributes</i>. */
	public PrivateRsaKeyAttributes() {
		super(
			new OptionalDecoderObjectElement(
				Path.class,
				false
			),
			new OptionalDecoderObjectElement(
				DerInteger.class,
				false
			)
			// Faltaria el KeyInfo, pero es un campo
			// que normalmente no esta
		);
	}

	/** Obtiene la ruta hacia la clave privada.
	 * @return Ruta hacia la clave privada. */
	public String getPath() {
		return ((Path)getElementAt(0)).getPathString();
	}

	/** Obtiene la longitud de la clave privada.
	 * @return Longitud de la clave privada. */
	public int getKeyLength() {
		return ((DerInteger)getElementAt(1)).getIntegerValue().intValue();
	}
}
