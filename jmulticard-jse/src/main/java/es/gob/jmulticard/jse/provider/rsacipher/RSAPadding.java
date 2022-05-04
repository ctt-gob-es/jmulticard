/*
 * Copyright (c) 2003, 2013, Oracle and/or its affiliates. All rights reserved.
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

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Utilidad para la aplicaci&oacute;n y la retirada de rellenos RSA.
 *
 * The various PKCS#1 versions can be found in the EMC/RSA Labs
 * web site, which is currently:
 *
 *     http://www.emc.com/emc-plus/rsa-labs/index.htm
 *
 * or in the IETF RFCs derived from the above PKCS#1 standards.
 *
 *     RFC 2313: v1.5
 *     RFC 2437: v2.0
 *     RFC 3447: v2.1
 *
 * The format of PKCS#1 v1.5 padding is:
 *
 *   0x00 | BT | PS...PS | 0x00 | data...data
 *
 * where BT is the blocktype (1 or 2). The length of the entire string
 * must be the same as the size of the modulus (i.e. 128 byte for a 1024 bit
 * key). Per spec, the padding string must be at least 8 bytes long. That
 * leaves up to (length of key in bytes) - 11 bytes for the data.
 *
 * OAEP padding was introduced in PKCS#1 v2.0 and is a bit more complicated
 * and has a number of options. We support:
 *
 *   . arbitrary hash functions ('Hash' in the specification), MessageDigest
 *     implementation must be available
 *   . MGF1 as the mask generation function
 *   . the empty string as the default value for label L and whatever
 *     specified in javax.crypto.spec.OAEPParameterSpec
 *
 * The algorithms (representations) are forwards-compatible: that is,
 * the algorithm described in previous releases are in later releases.
 * However, additional comments/checks/clarifications were added to the
 * later versions based on real-world experience (e.g. stricter v1.5
 * format checking.)
 *
 * Note: RSA keys should be at least 512 bits long
 *
 * @since   1.5
 * @author  Andreas Sterbenz
 */
final class RSAPadding {

    // NOTE: the constants below are embedded in the JCE RSACipher class
    // file. Do not change without coordinating the update

    /** Relleno PKCS#1 v1.5, blocktype 1 (firma). */
    final static int PAD_BLOCKTYPE_1 = 1;

    /** Relleno PKCS#1 v1.5, blocktype 2 (cifrado). */
    final static int PAD_BLOCKTYPE_2 = 2;

    /** Sin relleno. Con este tipo la clase no hace nada. */
    final static int PAD_NONE  = 3;

    /** Relleno PKCS#1 v2.1 OAEP. */
    final static int PAD_OAEP_MGF1 = 4;

    // type, one of PAD_*
    private final int type;

    // size of the padded block (i.e. size of the modulus)
    private final int paddedSize;

    // PRNG used to generate padding bytes (PAD_BLOCKTYPE_2, PAD_OAEP_MGF1)
    private SecureRandom random;

    /** Tama&ntilde;o m&aacute;ximo de los datos. */
    private final int maxDataSize;

    // OAEP: main messagedigest
    private MessageDigest md;

    // OAEP: message digest for MGF1
    private MessageDigest mgfMd;

    // OAEP: value of digest of data (user-supplied or zero-length) using md
    private byte[] lHash;

    /**
     * Get a RSAPadding instance of the specified type.
     * Keys used with this padding must be paddedSize bytes long.
     */
    static RSAPadding createInstance(final int type,
    		                         final int paddedSize,
    		                         final SecureRandom random) throws InvalidKeyException,
                                                                       InvalidAlgorithmParameterException {
        return new RSAPadding(type, paddedSize, random, null); // TODO:MAXIMO paddedSize 102????
    }

    /**
     * Get a RSAPadding instance of the specified type, which must be
     * OAEP. Keys used with this padding must be paddedSize bytes long.
     */
    static RSAPadding createInstance(final int type,
    		                         final int paddedSize,
    		                         final SecureRandom random,
    		                         final OAEPParameterSpec spec) throws InvalidKeyException,
                                                                          InvalidAlgorithmParameterException {
        return new RSAPadding(type, paddedSize, random, spec);
    }

    /** Constructor interno. */
    private RSAPadding(final int paddingType,
    		           final int sizeAfterPadding,
    		           final SecureRandom randomSrc,
    		           final OAEPParameterSpec spec) throws InvalidKeyException,
                                                            InvalidAlgorithmParameterException {
        this.type = paddingType;
        this.paddedSize = sizeAfterPadding;
        this.random = randomSrc;
        if (sizeAfterPadding < 64) {
            throw new InvalidKeyException(
        		"El tamano tras el relleno debe ser de al menos 64 octetos, y es de " + sizeAfterPadding + " octetos"//$NON-NLS-1$ //$NON-NLS-2$
    		);
        }
        switch (paddingType) {
	        case PAD_BLOCKTYPE_1:
	        case PAD_BLOCKTYPE_2:
	            this.maxDataSize = sizeAfterPadding - 11;
	            break;
	        case PAD_NONE:
	            this.maxDataSize = sizeAfterPadding;
	            break;
	        case PAD_OAEP_MGF1:
	            String mdName = "SHA-1"; //$NON-NLS-1$
	            String mgfMdName = "SHA-1"; //$NON-NLS-1$
	            byte[] digestInput = null;
	            try {
	                if (spec != null) {
	                    mdName = spec.getDigestAlgorithm();
	                    final String mgfName = spec.getMGFAlgorithm();
	                    if (!"MGF1".equalsIgnoreCase(mgfName)) { //$NON-NLS-1$
	                        throw new InvalidAlgorithmParameterException("Unsupported MGF algo: " + mgfName); //$NON-NLS-1$
	                    }
	                    mgfMdName = ((MGF1ParameterSpec)spec.getMGFParameters())
	                            .getDigestAlgorithm();
	                    final PSource pSrc = spec.getPSource();
	                    final String pSrcAlgo = pSrc.getAlgorithm();
	                    if (!"PSpecified".equalsIgnoreCase(pSrcAlgo)) { //$NON-NLS-1$
	                        throw new InvalidAlgorithmParameterException("Unsupported pSource algo: " + pSrcAlgo); //$NON-NLS-1$
	                    }
	                    digestInput = ((PSource.PSpecified) pSrc).getValue();
	                }
	                this.md = MessageDigest.getInstance(mdName);
	                this.mgfMd = MessageDigest.getInstance(mgfMdName);
	            }
	            catch (final NoSuchAlgorithmException e) {
	                throw new InvalidKeyException("Digest " + mdName + " not available", e); //$NON-NLS-1$ //$NON-NLS-2$
	            }
	            this.lHash = getInitialHash(this.md, digestInput);
	            final int digestLen = this.lHash.length;
	            this.maxDataSize = sizeAfterPadding - 2 - 2 * digestLen;
	            if (this.maxDataSize <= 0) {
	                throw new InvalidKeyException("Key is too short for encryption using OAEPPadding with " + mdName + " and MGF1" + mgfMdName); //$NON-NLS-1$ //$NON-NLS-2$
	            }
	            break;
	        default:
	            throw new InvalidKeyException("Tipo de relleno invalido: " + paddingType); //$NON-NLS-1$
        }
    }

    // cache of hashes of zero length data
    private static final Map<String,byte[]> EMPTY_HASHES =
        Collections.synchronizedMap(new HashMap<String,byte[]>());

    /**
     * Return the value of the digest using the specified message digest
     * <code>md</code> and the digest input <code>digestInput</code>.
     * if <code>digestInput</code> is null or 0-length, zero length
     * is used to generate the initial digest.
     * Note: the md object must be in reset state
     */
    private static byte[] getInitialHash(final MessageDigest md,
        final byte[] digestInput) {
        byte[] result;
        if (digestInput == null || digestInput.length == 0) {
            final String digestName = md.getAlgorithm();
            result = EMPTY_HASHES.get(digestName);
            if (result == null) {
                result = md.digest();
                EMPTY_HASHES.put(digestName, result);
            }
        }
        else {
            result = md.digest(digestInput);
        }
        return result;
    }

    /**
     * Return the maximum size of the plaintext data that can be processed
     * using this object.
     */
    int getMaxDataSize() {
        return this.maxDataSize;
    }

    /** Rellena los datos.
     * Pad the data and return the padded block.
     */
    byte[] pad(final byte[] data, final int ofs, final int len) throws BadPaddingException {
        return pad(RSACore.convert(data, ofs, len));
    }

    /**
     * Pad the data and return the padded block.
     */
    byte[] pad(final byte[] data) throws BadPaddingException {
        if (data.length > this.maxDataSize) {
            throw new BadPaddingException(
        		"Los datos deben ser de tamano inferior a " + (this.maxDataSize + 1) + " octetos" //$NON-NLS-1$ //$NON-NLS-2$
    		);
        }
        switch (this.type) {
	        case PAD_NONE:
	            return data;
	        case PAD_BLOCKTYPE_1:
	        case PAD_BLOCKTYPE_2:
	            return padV15(data);
	        case PAD_OAEP_MGF1:
	            return padOaep(data);
	        default:
	            throw new AssertionError();
        }
    }

    /**
     * Unpad the padded block and return the data.
     */
    byte[] unpad(final byte[] padded) throws BadPaddingException {
        if (padded.length != this.paddedSize) {
            throw new BadPaddingException("El tamano de los datos rellenos no es valido"); //$NON-NLS-1$
        }
        switch (this.type) {
	        case PAD_NONE:
	            return padded;
	        case PAD_BLOCKTYPE_1:
	        case PAD_BLOCKTYPE_2:
	            return unpadV15(padded);
	        case PAD_OAEP_MGF1:
	            return unpadOAEP(padded);
	        default:
	            throw new AssertionError();
        }
    }

    /**
     * PKCS#1 v1.5 padding (blocktype 1 and 2).
     */
    private byte[] padV15(final byte[] data) {
        final byte[] padded = new byte[this.paddedSize];
        System.arraycopy(data, 0, padded, this.paddedSize - data.length, data.length);
        int psSize = this.paddedSize - 3 - data.length;
        int k = 0;
        padded[k++] = 0;
        padded[k++] = (byte)this.type;
        if (this.type == PAD_BLOCKTYPE_1) {
            // blocktype 1: all padding bytes are 0xff
            while (psSize-- > 0) {
                padded[k++] = (byte)0xff;
            }
        }
        else {
            // blocktype 2: padding bytes are random non-zero bytes
            if (this.random == null) {
                this.random = new SecureRandom();
            }
            // generate non-zero padding bytes
            // use a buffer to reduce calls to SecureRandom
            final byte[] r = new byte[64];
            int i = -1;
            while (psSize-- > 0) {
                int b;
                do {
                    if (i < 0) {
                        this.random.nextBytes(r);
                        i = r.length - 1;
                    }
                    b = r[i--] & 0xff;
                } while (b == 0);
                padded[k++] = (byte)b;
            }
        }
        return padded;
    }

    /**
     * PKCS#1 v1.5 unpadding (blocktype 1 (signature) and 2 (encryption)).
     * Note that we want to make it a constant-time operation
     */
    private byte[] unpadV15(final byte[] padded) throws BadPaddingException {
        int k = 0;
        final boolean bp = false;

        if (padded[k++] != 0) {
        	throw new BadPaddingException("Los datos rellenos no empiezan en cero"); //$NON-NLS-1$
        }
//        final byte typeHeader = padded[k++];
//        if (typeHeader != this.type) {
//        	throw new BadPaddingException("La cabecera de los datos rellenos (" + typeHeader + ") no se corresponde con el tipo de relleno (" + this.type + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
//        }
        int p = 0;
        while (k < padded.length) {
            final int b = padded[k++] & 0xff;
            if (b == 0 && p == 0) {
                p = k;
            }
            if (k == padded.length && p == 0) {
            	throw new BadPaddingException("Decryption error"); //$NON-NLS-1$
            }
            if (this.type == PAD_BLOCKTYPE_1 && b != 0xff && p == 0) {
            	throw new BadPaddingException("Decryption error"); //$NON-NLS-1$
            }
        }
        final int n = padded.length - p;
        if (n > this.maxDataSize) {
        	throw new BadPaddingException("El tamano de los datos rellenos (" + n + ") excede del maximo permitido");  //$NON-NLS-1$//$NON-NLS-2$
        }

        // copy useless padding array for a constant-time method
        final byte[] padding = new byte[p];
        System.arraycopy(padded, 0, padding, 0, p);

        final byte[] data = new byte[n];
        System.arraycopy(padded, p, data, 0, n);

        if (bp) {
            throw new BadPaddingException("Decryption error"); //$NON-NLS-1$
        }
		return data;
    }

    /**
     * PKCS#1 v2.0 OAEP padding (MGF1).
     * Paragraph references refer to PKCS#1 v2.1 (June 14, 2002)
     */
    private byte[] padOaep(final byte[] M) throws BadPaddingException {
        if (this.random == null) {
            this.random = new SecureRandom();
        }
        final int hLen = this.lHash.length;

        // 2.d: generate a random octet string seed of length hLen
        // if necessary
        final byte[] seed = new byte[hLen];
        this.random.nextBytes(seed);

        // buffer for encoded message EM
        final byte[] encodedMessage = new byte[this.paddedSize];

        // start and length of seed (as index into EM)
        final int seedStart = 1;
        final int seedLen = hLen;

        // copy seed into EM
        System.arraycopy(seed, 0, encodedMessage, seedStart, seedLen);

        // start and length of data block DB in EM
        // we place it inside of EM to reduce copying
        final int dbStart = hLen + 1;
        final int dbLen = encodedMessage.length - dbStart;

        // start of message M in EM
        final int mStart = this.paddedSize - M.length;

        // build DB
        // 2.b: Concatenate lHash, PS, a single octet with hexadecimal value
        // 0x01, and the message M to form a data block DB of length
        // k - hLen -1 octets as DB = lHash || PS || 0x01 || M
        // (note that PS is all zeros)
        System.arraycopy(this.lHash, 0, encodedMessage, dbStart, hLen);
        encodedMessage[mStart - 1] = 1;
        System.arraycopy(M, 0, encodedMessage, mStart, M.length);

        // produce maskedDB
        mgf1(encodedMessage, seedStart, seedLen, encodedMessage, dbStart, dbLen);

        // produce maskSeed
        mgf1(encodedMessage, dbStart, dbLen, encodedMessage, seedStart, seedLen);

        return encodedMessage;
    }

    /**
     * PKCS#1 v2.1 OAEP unpadding (MGF1).
     */
    private byte[] unpadOAEP(final byte[] padded) throws BadPaddingException {
        final byte[] encodedMessage = padded;
        boolean bp = false;
        final int hLen = this.lHash.length;

        if (encodedMessage[0] != 0) {
            bp = true;
        }

        final int seedStart = 1;
        final int seedLen = hLen;

        final int dbStart = hLen + 1;
        final int dbLen = encodedMessage.length - dbStart;

        mgf1(encodedMessage, dbStart, dbLen, encodedMessage, seedStart, seedLen);
        mgf1(encodedMessage, seedStart, seedLen, encodedMessage, dbStart, dbLen);

        // verify lHash == lHash'
        for (int i = 0; i < hLen; i++) {
            if (this.lHash[i] != encodedMessage[dbStart + i]) {
                bp = true;
				break;
            }
        }

        final int padStart = dbStart + hLen;
        int onePos = -1;

        for (int i = padStart; i < encodedMessage.length; i++) {
            final int value = encodedMessage[i];
            if (onePos == -1) {
                if (value == 0x00) {
                    // continue;
                } else if (value == 0x01) {
                    onePos = i;
                } else {  // Anything other than {0,1} is bad.
                    bp = true;
                }
            }
        }

        // We either ran off the rails or found something other than 0/1.
        if (onePos == -1) {
            bp = true;
            onePos = encodedMessage.length - 1;  // Don't inadvertently return any data.
        }

        final int mStart = onePos + 1;

        // copy useless padding array for a constant-time method
        final byte [] tmp = new byte[mStart - padStart];
        System.arraycopy(encodedMessage, padStart, tmp, 0, tmp.length);

        final byte [] m = new byte[encodedMessage.length - mStart];
        System.arraycopy(encodedMessage, mStart, m, 0, m.length);

        final BadPaddingException bpe = new BadPaddingException("Decryption error"); //$NON-NLS-1$

        if (bp) {
            throw bpe;
        }
		return m;
    }

    /**
     * Compute MGF1 using mgfMD as the message digest.
     * Note that we combine MGF1 with the XOR operation to reduce data
     * copying.
     *
     * We generate maskLen bytes of MGF1 from the seed and XOR it into
     * out[] starting at outOfs;
     */
    private void mgf1(final byte[] seed,
    		          final int seedOfs,
    		          final int seedLen,
    		          final byte[] out,
    		          final int outOffset,
    		          final int maskLength)  throws BadPaddingException {

    	int maskLen = maskLength;
    	int outOfs = outOffset;

        final byte[] counter = new byte[4]; // Contador de 32 bits
        final byte[] digest = new byte[this.mgfMd.getDigestLength()];
        while (maskLen > 0) {
            this.mgfMd.update(seed, seedOfs, seedLen);
            this.mgfMd.update(counter);
            try {
                this.mgfMd.digest(digest, 0, digest.length);
            }
            catch (final DigestException e) {
                // No deberia ocurrir
                throw new BadPaddingException(e.toString());
            }
            for (int i = 0; i < digest.length && maskLen > 0; maskLen--) {
                out[outOfs++] ^= digest[i++];
            }
            if (maskLen > 0) {
                // Incrementamos el contador
                for (int i = counter.length - 1; ++counter[i] == 0 && i > 0; i--) {
                    // vacio
                }
            }
        }
    }
}
