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
package es.gob.jmulticard.jse.provider.gide;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.gide.smartcafe.SmartCafePkcs15Applet;
import es.gob.jmulticard.card.gide.smartcafe.SmartCafePrivateKeyReference;

/** Clave privada de una tarjeta G&amp;D SmartCafe con Applet PKCS#15.
 * La clase no contiene la clave privada en s&iacute;, sino una referencia a ella.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SmartCafePrivateKey implements RSAPrivateKey {

	private static final long serialVersionUID = 4403051294889801855L;

	/** Identificador de la clave. */
	private final int id;

	private final CryptoCard card;

	/** Crea una clave privada de una tarjeta G&amp;D SmartCafe con Applet PKCS#15.
	 * @param keyReference Referencia a la clave privada. */
	SmartCafePrivateKey(final SmartCafePrivateKeyReference keyReference,
			            final SmartCafePkcs15Applet cryptoCard) {
		this.id = keyReference.getKeyOrdinal();
		this.card = cryptoCard;
	}

	/** {@inheritDoc} */
	@Override
	public String getAlgorithm() {
		return "RSA"; //$NON-NLS-1$
	}

	/** {@inheritDoc} */
	@Override
	public byte[] getEncoded() {
		return null;
	}

	/** {@inheritDoc} */
	@Override
	public String getFormat() {
		return null;
	}

	/** Recupera el identificador de la clave.
	 * @return Identificador de la clave. */
	int getId() {
		return this.id;
	}

	/** M&eacute;todo no soportado. */
	@Override
	public BigInteger getModulus() {
		throw new UnsupportedOperationException();
	}

	/** M&eacute;todo no soportado. */
	@Override
	public BigInteger getPrivateExponent() {
		throw new UnsupportedOperationException();
	}

	/** {@inheritDoc} */
	@Override
	public String toString() {
		return "Clave privada para G&D SmartCafe (con Applet PKCS#15) con ordinal " + this.id; //$NON-NLS-1$
	}

	@SuppressWarnings({ "static-method", "unused" })
	private void writeObject(final ObjectOutputStream out) throws IOException {
		throw new NotSerializableException();
	}

	/** Obtiene la tarjeta a la que pertenece esta clave.
	 * @return Tarjeta a la que pertenece esta clave. */
	public CryptoCard getCryptoCard() {
		return this.card;
	}

}