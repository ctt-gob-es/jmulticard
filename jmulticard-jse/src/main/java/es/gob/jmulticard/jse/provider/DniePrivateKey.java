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
package es.gob.jmulticard.jse.provider;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.dnie.DniePrivateKeyReference;

/** Clave privada de un DNIe. La clase no contiene la clave privada en s&iacute;, sino
 * una referencia a ella y una referencia al propio DNIe, con el canal seguro establecido.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class DniePrivateKey implements RSAPrivateKey {

	private static final long serialVersionUID = 4403051294889801855L;

	/** Referencia a la clave privada.*/
	private final transient DniePrivateKeyReference dniPrivateKeyReference;

	/** M&oacute;dulo de la clave privada.
	 * Al ser la clave privada interna al DNI, este dato se obtiene de la p&uacute;blica (es igual). */
	private final BigInteger modulus;

	/** Crea una clave privada de DNIe.
	 * @param keyReference Referencia a la clave privada del DNIe.
	 * @param mod M&oacute;dulo de la clave. */
	public DniePrivateKey(final DniePrivateKeyReference keyReference, final BigInteger mod) {
		this.dniPrivateKeyReference = keyReference;
		this.modulus   = mod;
	}

	@Override
	public String getAlgorithm() {
		return "RSA"; //$NON-NLS-1$
	}

	/** Obtiene la tarjeta capaz de operar con esta clave.
	 * @return Tarjeta capaz de operar con esta clave. */
	public CryptoCard getCryptoCard() {
		return this.dniPrivateKeyReference.getDnieCard();
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	/** Recupera el identificador de la clave.
	 * @return Identificador de la clave. */
	byte[] getId() {
		return this.dniPrivateKeyReference.getIdentifier();
	}

	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}

	/** Recupera la ruta hacia la clave.
	 * @return Ruta de la clave. */
	Location getPath() {
		return this.dniPrivateKeyReference.getKeyPath();
	}

	/** No soportado. */
	@Override
	public BigInteger getPrivateExponent() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String toString() {
		return this.dniPrivateKeyReference.getLabel();
	}

	/** Serializaci&oacute;n no soportada, lanza un <code>NotSerializableException</code>.
	 * @param outStream No se usa.
	 * @throws IOException No se lanza, siempre lanza un <code>NotSerializableException</code>. */
	@SuppressWarnings({ "static-method" })
	private void writeObject(final ObjectOutputStream outStream) throws IOException {
		throw new NotSerializableException();
	}

	/** Recupera la referencia interna en tarjeta de la clave.
	 * @return Referencia interna en tarjeta de la clave. */
	byte getKeyReference() {
		return this.dniPrivateKeyReference.getKeyReference();
	}

	/** Obtiene el tam&ntilde;o en bits de la clave.
	 * @return Tam&ntilde;o en bits de la clave. */
	int getKeyBitSize() {
		return this.dniPrivateKeyReference.getKeyBitSize();
	}

	/** Obtiene la referencia de la clave privada.
	 * @return Referencia de la clave privada. */
	public DniePrivateKeyReference getDniePrivateKeyReference() {
		return this.dniPrivateKeyReference;
	}
}