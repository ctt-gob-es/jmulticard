/*
 * Copyright (c) 2003, 2015, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package es.gob.jmulticard.jse.provider.rsacipher;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.WeakHashMap;

import javax.crypto.BadPaddingException;

import es.gob.jmulticard.apdu.connection.LostChannelException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.jse.provider.DniePrivateKey;

/** Operaciones con claves privadas RSA.
 * No se soporta CRT (Chinese Remainder Theorem).
 * Esta clase no realiza rellenos, estos deben hacerse externamente.
 * Nota: Las claves RSA deben ser de al menos 512 bits.
 * @author  Andreas Sterbenz. */
final class RSACore {

    // globally enable/disable use of blinding
    private final static boolean ENABLE_BLINDING = true;

    // cache for blinding parameters. Map<BigInteger, BlindingParameters>
    // use a weak hashmap so that cached values are automatically cleared
    // when the modulus is GC'ed
    private final static Map<BigInteger, BlindingParameters> blindingCache = new WeakHashMap<>();

    private RSACore() {
        // No instanciable
    }

    /**
     * Return the number of bytes required to store the magnitude byte[] of
     * this BigInteger. Do not count a 0x00 byte toByteArray() would
     * prefix for 2's complement form.
     */
    static int getByteLength(final BigInteger b) {
        final int n = b.bitLength();
        return n + 7 >> 3;
    }

    /** Devuelve el n&uacute;mero de octetos necesarios para almacenar el
     * m&oacute;dulo de una clave RSA.
     * @param key Clave RSA.
     * @return N&uacute;mero de octetos necesarios para almacenar el m&oacute;dulo
     *         de la clave proporcionada. */
    static int getByteLength(final RSAKey key) {
        return getByteLength(key.getModulus());
    }

    static byte[] convert(final byte[] b, final int ofs, final int len) {
        if (ofs == 0 && len == b.length) {
            return b;
        }
		final byte[] t = new byte[len];
		System.arraycopy(b, ofs, t, 0, len);
		return t;
    }

    /** Ejecuta un cifrado RSA con una clave p&uacute;blica. */
    static byte[] rsa(final byte[] msg, final RSAPublicKey key) throws BadPaddingException {
        return crypt(msg, key.getModulus(), key.getPublicExponent());
    }

    /** Ejecuta un cifrado RSA con una clave privada.
     * @throws LostChannelException Si la clave es de un DNIe y se ha perdido el canal seguro.
     * @throws PinException Si la clave es de un DNIe y el PIN introducido es inv&aacute;lido.
     * @throws CryptoCardException Si la clave es de un DNIe y hay problemas con la tarjeta. */
    static byte[] rsa(final byte[] msg, final RSAPrivateKey key) throws BadPaddingException,
                                                                        CryptoCardException,
                                                                        PinException,
                                                                        LostChannelException {
    	if (key instanceof DniePrivateKey) {
    		final Dnie dni = (Dnie) ((DniePrivateKey)key).getCryptoCard();
    		return dni.cipherData(
				msg,
				((DniePrivateKey)key).getDniePrivateKeyReference()
			);
    	}
		return priCrypt(msg, key.getModulus(), key.getPrivateExponent());
    }

    /** Operaci&oacute;n general de cifrado RSA (un <code>modPow()</code>). */
    private static byte[] crypt(final byte[] msg,
    		                    final BigInteger n,
    		                    final BigInteger exp) throws BadPaddingException {

        final BigInteger m = parseMsg(msg, n);
        final BigInteger c = m.modPow(exp, n);
        return toByteArray(c, getByteLength(n));
    }

    /**
     * RSA non-CRT private key operations.
     */
    private static byte[] priCrypt(final byte[] msg,
    		                       final BigInteger n,
    		                       final BigInteger exp) throws BadPaddingException {

        final BigInteger c = parseMsg(msg, n);
        final BigInteger m;
        if (ENABLE_BLINDING) {
        	final BlindingRandomPair brp = getBlindingRandomPair(null, exp, n);
            m = c.multiply(brp.u).mod(n).modPow(exp, n).multiply(brp.v).mod(n);
        }
        else {
            m = c.modPow(exp, n);
        }
        return toByteArray(m, getByteLength(n));
    }

    /**
     * Parse the msg into a BigInteger and check against the modulus n.
     */
    private static BigInteger parseMsg(final byte[] msg,
    		                           final BigInteger n) throws BadPaddingException {

        final BigInteger m = new BigInteger(1, msg);
        if (m.compareTo(n) >= 0) {
            throw new BadPaddingException("El mensaje es mas grande que el modulo"); //$NON-NLS-1$
        }
        return m;
    }

    /**
     * Return the encoding of this BigInteger that is exactly len bytes long.
     * Prefix/strip off leading 0x00 bytes if necessary.
     * Precondition: bi must fit into len bytes
     */
    private static byte[] toByteArray(final BigInteger bi, final int len) {
        final byte[] b = bi.toByteArray();
        final int n = b.length;
        if (n == len) {
            return b;
        }
        // BigInteger prefixed a 0x00 byte for 2's complement form, remove it
        if (n == len + 1 && b[0] == 0) {
            final byte[] t = new byte[len];
            System.arraycopy(b, 1, t, 0, len);
            return t;
        }
        // must be smaller
        assert n < len;
        final byte[] t = new byte[len];
        System.arraycopy(b, 0, t, len - n, n);
        return t;
    }

    /**
     * Parameters (u,v) for RSA Blinding.  This is described in the RSA
     * Bulletin#2 (Jan 96) and other places:
     *
     *     ftp://ftp.rsa.com/pub/pdfs/bull-2.pdf
     *
     * The standard RSA Blinding decryption requires the key exponent
     * (e) and modulus (n), and converts ciphertext (c) to plaintext (p).
     *
     * Before the modular exponentiation operation, the input message should
     * be multiplied by (u (mod n)), and afterward the result is corrected
     * by multiplying with (v (mod n)).  The system should reject messages
     * equal to (0 (mod n)).  That is:
     *
     *     1.  Generate r between 0 and n-1, relatively prime to n.
     *     2.  Compute x = (c*u) mod n
     *     3.  Compute y = (x^d) mod n
     *     4.  Compute p = (y*v) mod n
     *
     * The Java APIs allows for either standard RSAPrivateKey or
     * RSAPrivateCrtKey RSA keys.
     *
     * If the exponent is available to us (e.g. RSAPrivateCrtKey),
     * choose a random r, then let (u, v):
     *
     *     u = r ^ e mod n
     *     v = r ^ (-1) mod n
     *
     * The proof follows:
     *
     *     p = (((c * u) ^ d mod n) * v) mod n
     *       = ((c ^ d) * (u ^ d) * v) mod n
     *       = ((c ^ d) * (r ^ e) ^ d) * (r ^ (-1))) mod n
     *       = ((c ^ d) * (r ^ (e * d)) * (r ^ (-1))) mod n
     *       = ((c ^ d) * (r ^ 1) * (r ^ (-1))) mod n  (see below)
     *       = (c ^ d) mod n
     *
     * because in RSA cryptosystem, d is the multiplicative inverse of e:
     *
     *    (r^(e * d)) mod n
     *       = (r ^ 1) mod n
     *       = r mod n
     *
     * However, if the exponent is not available (e.g. RSAPrivateKey),
     * we mitigate the timing issue by using a similar random number blinding
     * approach using the private key:
     *
     *     u = r
     *     v = ((r ^ (-1)) ^ d) mod n
     *
     * This returns the same plaintext because:
     *
     *     p = (((c * u) ^ d mod n) * v) mod n
     *       = ((c ^ d) * (u ^ d) * v) mod n
     *       = ((c ^ d) * (u ^ d) * ((u ^ (-1)) ^d)) mod n
     *       = (c ^ d) mod n
     *
     * Computing inverses mod n and random number generation is slow, so
     * it is often not practical to generate a new random (u, v) pair for
     * each new exponentiation.  The calculation of parameters might even be
     * subject to timing attacks.  However, (u, v) pairs should not be
     * reused since they themselves might be compromised by timing attacks,
     * leaving the private exponent vulnerable.  An efficient solution to
     * this problem is update u and v before each modular exponentiation
     * step by computing:
     *
     *     u = u ^ 2
     *     v = v ^ 2
     *
     * The total performance cost is small.
     */
    private static final class BlindingRandomPair {
        final BigInteger u;
        final BigInteger v;

        BlindingRandomPair(final BigInteger u, final BigInteger v) {
            this.u = u;
            this.v = v;
        }
    }

    /**
     * Set of blinding parameters for a given RSA key.
     *
     * The RSA modulus is usually unique, so we index by modulus in
     * {@code blindingCache}.  However, to protect against the unlikely
     * case of two keys sharing the same modulus, we also store the public
     * or the private exponent.  This means we cannot cache blinding
     * parameters for multiple keys that share the same modulus, but
     * since sharing moduli is fundamentally broken and insecure, this
     * does not matter.
     */
    private static final class BlindingParameters {

        private final static BigInteger BIG_TWO = BigInteger.valueOf(2L);

        /** Exponente RSA. */
        private final BigInteger e;

        // hash code of RSA private exponent
        private final BigInteger d;

        // r ^ e mod n (CRT), or r mod n (Non-CRT)
        private BigInteger u;

        // r ^ (-1) mod n (CRT) , or ((r ^ (-1)) ^ d) mod n (Non-CRT)
        private BigInteger v;

        // e: the exponent
        // d: the private exponent
        // n: the modulus
        BlindingParameters(final BigInteger e, final BigInteger d, final BigInteger n) {
            this.u = null;
            this.v = null;
            this.e = e;
            this.d = d;

            final int len = n.bitLength();
            final SecureRandom random = new SecureRandom();
            this.u = new BigInteger(len, random).mod(n);
            // Although the possibility is very much limited that u is zero
            // or is not relatively prime to n, we still want to be careful
            // about the special value.
            //
            // Secure random generation is expensive, try to use BigInteger.ONE
            // this time if this new generated random number is zero or is not
            // relatively prime to n.  Next time, new generated secure random
            // number will be used instead.
            if (this.u.equals(BigInteger.ZERO)) {
                this.u = BigInteger.ONE;     // use 1 this time
            }

            try {
                // The call to BigInteger.modInverse() checks that u is
                // relatively prime to n.  Otherwise, ArithmeticException is
                // thrown.
                this.v = this.u.modInverse(n);
            }
            catch (final ArithmeticException ae) {
                // if u is not relatively prime to n, use 1 this time
                this.u = BigInteger.ONE;
                this.v = BigInteger.ONE;
            }

            if (e != null) {
                this.u = this.u.modPow(e, n);   // e: El exponente publico
                                      // u: random ^ e
                                      // v: random ^ (-1)
            }
            else {
                this.v = this.v.modPow(d, n);   // d: El exponente privado
                                      // u: random
                                      // v: random ^ (-d)
            }
        }

        // Devuelve null si se necesitan reiniciar los parametros
        BlindingRandomPair getBlindingRandomPair(final BigInteger exponent,
        		                                 final BigInteger privateRsaExponentHash,
        		                                 final BigInteger n) {

            if (this.e != null && this.e.equals(exponent) ||
                this.d != null && this.d.equals(privateRsaExponentHash)) {

                BlindingRandomPair brp = null;
                synchronized (this) {
                    if (!this.u.equals(BigInteger.ZERO) &&
                        !this.v.equals(BigInteger.ZERO)) {

                        brp = new BlindingRandomPair(this.u, this.v);
                        if (this.u.compareTo(BigInteger.ONE) <= 0 ||
                            this.v.compareTo(BigInteger.ONE) <= 0) {

                            // need to reset the random pair next time
                            this.u = BigInteger.ZERO;
                            this.v = BigInteger.ZERO;
                        }
                        else {
                            this.u = this.u.modPow(BIG_TWO, n);
                            this.v = this.v.modPow(BIG_TWO, n);
                        }
                    } // Otherwise, need to reset the random pair.
                }
                return brp;
            }

            return null;
        }
    }

    private static BlindingRandomPair getBlindingRandomPair(final BigInteger e,
    		                                                final BigInteger d,
    		                                                final BigInteger n) {
        BlindingParameters bps = null;
        synchronized (blindingCache) {
            bps = blindingCache.get(n);
        }

        if (bps == null) {
            bps = new BlindingParameters(e, d, n);
            synchronized (blindingCache) {
            	if (blindingCache.get(n) == null) {
            		blindingCache.put(n, bps);
            	}
            }
        }

        final BlindingRandomPair brp = bps.getBlindingRandomPair(e, d, n);
        if (brp == null) {
            // need to reset the blinding parameters
            bps = new BlindingParameters(e, d, n);
            synchronized (blindingCache) {
            	if (blindingCache.containsKey(n)) {
					blindingCache.put(n, bps);
				}
            }
            return bps.getBlindingRandomPair(e, d, n);
        }

        return brp;
    }
}
