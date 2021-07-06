package es.gob.jmulticard.jse.provider;

import java.math.BigInteger;
import java.util.Random;

/** M&oacute;dulo falso de clave privada de DNIe.
 * Permite usar DNIe en establecimientos de sesi&oacute;n SSL, donde se pide
 * el m&aocute;dulo para saber la longitud de clave privada.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class FakeDniePrivateKeyModulus extends BigInteger {

	private static final long serialVersionUID = 3021082633395301169L;

	final int bitLength;

	FakeDniePrivateKeyModulus(final int bitlength) {
		super(bitlength, new Random());
		this.bitLength = bitlength;
	}

    @Override
	public BigInteger nextProbablePrime() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger add(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger subtract(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger multiply(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger divide(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger[] divideAndRemainder(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger remainder(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger pow(final int exponent) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger gcd(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger abs() {
    	throw new UnsupportedOperationException();
    }

	@Override
	public BigInteger negate() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public int signum() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger mod(final BigInteger m) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger modPow(final BigInteger exponent, final BigInteger m) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger modInverse(final BigInteger m) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger shiftLeft(final int n) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger shiftRight(final int n) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger and(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger or(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger xor(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger not() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger andNot(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public boolean testBit(final int n) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger setBit(final int n) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger clearBit(final int n) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger flipBit(final int n) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public int getLowestSetBit() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public int bitLength() {
    	return this.bitLength;
    }

    @Override
	public int bitCount() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public boolean isProbablePrime(final int certainty) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public int compareTo(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public boolean equals(final Object x) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger min(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public BigInteger max(final BigInteger val) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public int hashCode() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public String toString(final int radix) {
    	throw new UnsupportedOperationException();
    }

    @Override
	public String toString() {
        return "Modulo falso de clave privada"; //$NON-NLS-1$
    }

    @Override
	public byte[] toByteArray() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public int intValue() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public long longValue() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public float floatValue() {
    	throw new UnsupportedOperationException();
    }

    @Override
	public double doubleValue() {
    	throw new UnsupportedOperationException();
    }

}

