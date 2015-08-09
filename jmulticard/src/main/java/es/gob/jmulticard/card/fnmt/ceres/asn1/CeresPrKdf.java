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
package es.gob.jmulticard.card.fnmt.ceres.asn1;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.Record;
import es.gob.jmulticard.asn1.der.pkcs15.PrivateKeyObject;

/** Objeto PKCS#15 PrKDF (<i>Private Key Description File</i>) ASN&#46;1.
 * El PrKDF es una secuencia de estructuras <code>PKCS15PrivateKey</code>:
 * <pre>
 * PKCS15PrivateKey ::= CHOICE {
 *    privateRSAKey [0] PKCS15PrivateKeyObject {
 *        PKCS15PrivateRSAKeyAttributes
 *    },
 *    privateECKey  [1] PKCS15PrivateKeyObject {
 *        PKCS15PrivateECKeyAttributes
 *    },
 *    ... -- More private key types TBD --
 * }
 *
 * PKCS15PrivateKeyObject {KeyAttributes} ::= PKCS15Object {
 *    PKCS15CommonKeyAttributes,
 *    PKCS15CommonPrivateKeyAttributes,
 *    KeyAttributes
 * }
 * </pre>
 * En este caso, las claves siempre ser&aacute;n de tipo RSA.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class CeresPrKdf extends Record {

    /** Construye un objeto PKCS#15 PrKDF (<i>Private Key Description File</i>) ASN&#46;1. */
	public CeresPrKdf() {
		super(
			new OptionalDecoderObjectElement[] {
				// Maximo 10 certificados

				// Estructura antigua, que incumple PKCS#15
				new OptionalDecoderObjectElement(CeresPrivateKeyObject.class, true),
				new OptionalDecoderObjectElement(CeresPrivateKeyObject.class, true),
				new OptionalDecoderObjectElement(CeresPrivateKeyObject.class, true),
				new OptionalDecoderObjectElement(CeresPrivateKeyObject.class, true),
				new OptionalDecoderObjectElement(CeresPrivateKeyObject.class, true),
				new OptionalDecoderObjectElement(CeresPrivateKeyObject.class, true),
				new OptionalDecoderObjectElement(CeresPrivateKeyObject.class, true),
				new OptionalDecoderObjectElement(CeresPrivateKeyObject.class, true),
				new OptionalDecoderObjectElement(CeresPrivateKeyObject.class, true),
				new OptionalDecoderObjectElement(CeresPrivateKeyObject.class, true)

			}
		);
	}

	/** Obtiene el n&uacute;mero de claves del PrKDF.
	 * @return N&uacute;mero de claves del PrKDF */
	public int getKeyCount() {
		return getElementCount();
	}

	/** Obtiene la ruta PKCS#15 hacia la clave indicada.
	 * @param index &Iacute;ndice de la clave.
	 * @return Ruta PKCS#15 hacia la clave indicada. */
	public String getKeyPath(final int index) {
		return ((PrivateKeyObject) getElementAt(index)).getKeyPath();
	}

	/** Obtiene el identificador de la clave indicada.
	 * @param index &Iacute;ndice de la clave.
	 * @return Identificador de la clave indicada. */
	public byte[] getKeyId(final int index) {
		return ((PrivateKeyObject) getElementAt(index)).getKeyIdentifier();
	}

	/** Obtiene la referencia de la clave indicada.
	 * @param index &Iacute;ndice de la clave.
	 * @return Referencia de la clave indicada. */
	public byte getKeyReference(final int index) {
		return ((PrivateKeyObject) getElementAt(index)).getKeyReference();
	}

    /** {@inheritDoc} */
	@Override
    public String toString() {
		final StringBuilder sb = new StringBuilder();
		sb.append("Fichero de Descripcion de Claves Privadas CERES:\n"); //$NON-NLS-1$
		for (int index=0;index<getKeyCount();index++) {
			sb.append(" Clave privada "); //$NON-NLS-1$
			sb.append(Integer.toString(index));
			sb.append("\n  Ruta hacia la clave: "); //$NON-NLS-1$
			sb.append(getKeyPath(index));
			sb.append("\n  Identificador de la clave: "); //$NON-NLS-1$
			sb.append(HexUtils.hexify(getKeyId(index), false));
			sb.append("\n  Referencia de la clave: 0x"); //$NON-NLS-1$
			sb.append(HexUtils.hexify(new byte[] { getKeyReference(index) }, false));
			if (index != getKeyCount() -1) {
				sb.append('\n');
			}
		}
		return sb.toString();
	}

}