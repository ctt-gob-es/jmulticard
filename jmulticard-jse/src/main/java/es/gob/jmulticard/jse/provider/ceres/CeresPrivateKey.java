package es.gob.jmulticard.jse.provider.ceres;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.fnmt.ceres.Ceres;
import es.gob.jmulticard.card.fnmt.ceres.CeresPrivateKeyReference;

/** Clave privada de una tarjeta FNMT-RCM-CERES. La clase no contiene la clave privada en si, sino
 * una referencia a ella y una referencia a la propia tarjeta.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CeresPrivateKey implements RSAPrivateKey {

	private static final long serialVersionUID = 4403051294889801855L;

	private final Ceres ceres;
	private final CeresPrivateKeyReference keyRef;
	private final BigInteger modulus;

	/** Crea una clave privada de tarjeta FNMT-RCM-CERES.
	 * @param keyReference Referencia a la clave privada de tarjeta FNMT-RCM-CERES.
	 * @param card Tarjeta a la cual pertenece esta clave.
	 * @param mod M&oacute;dulo de la clave privada. */
	CeresPrivateKey(final CeresPrivateKeyReference keyReference, final Ceres card, final BigInteger mod) {
		this.keyRef = keyReference;
		this.ceres = card;
		this.modulus = mod;
	}

	/** {@inheritDoc} */
	@Override
	public String getAlgorithm() {
		return "RSA"; //$NON-NLS-1$
	}

	/** Obtiene la tarjeta capaz de operar con esta clave.
	 * @return Tarjeta capaz de operar con esta clave. */
	CryptoCard getCryptoCard() {
		return this.ceres;
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

	/** Recupera la referencia de la clave.
	 * @return Referencia de la clave. */
	CeresPrivateKeyReference getReference() {
		return this.keyRef;
	}

	/** M&eacute;todo no soportado. */
	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}

	/** M&eacute;todo no soportado. */
	@Override
	public BigInteger getPrivateExponent() {
		throw new UnsupportedOperationException();
	}

	/** {@inheritDoc} */
	@Override
	public String toString() {
		return this.keyRef.toString();
	}

	@SuppressWarnings({ "static-method", "unused" })
	private void writeObject(final ObjectOutputStream out) throws IOException {
		throw new NotSerializableException();
	}
}