/*
 * Copyright (c) 2003, 2015, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package es.gob.jmulticard.jse.provider.rsacipher;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.connection.LostChannelException;

/**
 * RSA cipher implementation. Supports RSA en/decryption and signing/verifying
 * using PKCS#1 v1.5 padding and without padding (raw RSA). Note that raw RSA
 * is supported mostly for completeness and should only be used in rare cases.
 *
 * Objects should be instantiated by calling Cipher.getInstance() using the
 * following algorithm names:
 *  . "RSA/ECB/PKCS1Padding" (or "RSA") for PKCS#1 padding. The mode (blocktype)
 *    is selected based on the en/decryption mode and public/private key used
 *  . "RSA/ECB/NoPadding" for rsa RSA.
 *
 * We only do one RSA operation per doFinal() call. If the application passes
 * more data via calls to update() or doFinal(), we throw an
 * IllegalBlockSizeException when doFinal() is called (see JCE API spec).
 * Bulk encryption using RSA does not make sense and is not standardized.
 *
 * Note: RSA keys should be at least 512 bits long
 *
 * @since   1.5
 * @author  Andreas Sterbenz
 */
public final class DnieCipherImpl extends CipherSpi {

    // constant for an empty byte array
    private final static byte[] B0 = {};

    // mode constant for public key encryption
    private final static int MODE_ENCRYPT = 1;

    // mode constant for private key decryption
    private final static int MODE_DECRYPT = 2;

    // mode constant for private key encryption (signing)
    private final static int MODE_SIGN    = 3;

    // mode constant for public key decryption (verifying)
    private final static int MODE_VERIFY  = 4;

    /** RSA sin relleno. */
    private final static String PAD_NONE  = "NoPadding"; //$NON-NLS-1$

    /** RSA con relleno PKCS#1 v1.5. */
    private final static String PAD_PKCS1 = "PKCS1Padding"; //$NON-NLS-1$

    // constant for PKCS#2 v2.0 OAEP with MGF1
    private final static String PAD_OAEP_MGF1  = "OAEP"; //$NON-NLS-1$

    // current mode, one of MODE_* above. Set when init() is called
    private int mode;

    // active padding type, one of PAD_* above. Set by setPadding()
    private String paddingType;

    // padding object
    private RSAPadding padding;

    // cipher parameter for OAEP padding and TLS RSA premaster secret
    private AlgorithmParameterSpec spec = null;

    /** <i>Buffer</i> para los datos. */
    private byte[] buffer;

    /** N&uacute;mero de octetos en el <i>buffer</i> (el <i>offset</i>). */
    private int bufOfs;

    /** Tama&ntilde;o de los datos de salida. */
    private int outputSize;

    /** La clave p&uacute;blica, si se ha inicializado el cifrador con una clave p&uacute;blica. */
    private RSAPublicKey publicKey;

    /** Clave privada, si se ha inicializado el cifrador con una clave privada. */
    private RSAPrivateKey privateKey;

    /** Algoritmo de huella para el OAEP. */
    private final String oaepHashAlgorithm = "SHA-1"; //$NON-NLS-1$

    private SecureRandom random;

    /** Construye un cifrador RSA para el DNIe. */
    public DnieCipherImpl() {
        paddingType = PAD_PKCS1;
    }

    @Override
	protected void engineSetMode(final String cipherMode) throws NoSuchAlgorithmException {
        if (cipherMode == null || !"ECB".equalsIgnoreCase(cipherMode)) { //$NON-NLS-1$
            throw new NoSuchAlgorithmException("Modo no soportado: " + cipherMode); //$NON-NLS-1$
        }
    }

    @Override
	protected void engineSetPadding(final String paddingName) throws NoSuchPaddingException {
    	if (paddingName == null) {
    		throw new NoSuchPaddingException("El tipo de relleno no puede ser nulo"); //$NON-NLS-1$
    	}
        if (PAD_NONE.equalsIgnoreCase(paddingName)) {
            paddingType = PAD_NONE;
        }
        else if (PAD_PKCS1.equalsIgnoreCase(paddingName)) {
            paddingType = PAD_PKCS1;
        }
        else if ("oaeppadding".equals(paddingName.toLowerCase(Locale.ENGLISH))) { //$NON-NLS-1$
			paddingType = PAD_OAEP_MGF1;
        }
        throw new NoSuchPaddingException("Relleno no soportado: " + paddingName); //$NON-NLS-1$
    }

    @Override
	protected int engineGetBlockSize() {
    	// Devuelve siempre 0 porque en RSA no se trabaja con bloques
        return 0;
    }

    @Override
	protected int engineGetOutputSize(final int inputLen) {
        return outputSize;
    }

    @Override
	protected byte[] engineGetIV() {
    	// En RSA no hay vectores de inicializacion
        return null;
    }

    @Override
	protected AlgorithmParameters engineGetParameters() {
        if (spec == null || !(spec instanceof OAEPParameterSpec)) {
            return null;
        }
		try {
		    final AlgorithmParameters params = AlgorithmParameters.getInstance("OAEP"); //$NON-NLS-1$
		    params.init(spec);
		    return params;
		}
		catch (final NoSuchAlgorithmException nsae) {
		    // No deberia pasar
		    throw new RuntimeException(
	    		"No se ha encontrado una implementacion OAEP de 'AlgorithmParameters'", nsae //$NON-NLS-1$
    		);
		}
		catch (final InvalidParameterSpecException ipse) {
		    // No deberia pasar
		    throw new RuntimeException("No se soporta OAEPParameterSpec", ipse); //$NON-NLS-1$
		}
    }

    @Override
	protected void engineInit(final int opmode,
			                  final Key key,
			                  final SecureRandom rnd) throws InvalidKeyException {
        try {
            init(opmode, key, rnd, null);
        }
        catch (final InvalidAlgorithmParameterException iape) {
            throw new InvalidKeyException("Parametros invalidos para la inicializacion", iape); //$NON-NLS-1$
        }
    }

    @Override
	protected void engineInit(final int opmode,
			                  final Key key,
			                  final AlgorithmParameterSpec params,
			                  final SecureRandom rnd) throws InvalidKeyException,
	                                                         InvalidAlgorithmParameterException {
        init(opmode, key, rnd, params);
    }

    @Override
	protected void engineInit(final int opmode, final Key key,
			                  final AlgorithmParameters params,
			                  final SecureRandom rnd) throws InvalidKeyException,
	                                                         InvalidAlgorithmParameterException {
        if (params == null) {
            init(opmode, key, rnd, null);
        }
        else {
            try {
                final OAEPParameterSpec paramSpec = params.getParameterSpec(OAEPParameterSpec.class);
                init(opmode, key, rnd, paramSpec);
            }
            catch (final InvalidParameterSpecException ipse) {
                throw new InvalidAlgorithmParameterException(
            		"Parametros invalidos para la inicializacion", ipse //$NON-NLS-1$
        		);
            }
        }
    }

    /** Inicializa el cifrador. */
    private void init(final int opmode,
    		          final Key key, final SecureRandom rnd,
    		          final AlgorithmParameterSpec params) throws InvalidKeyException,
                                                                  InvalidAlgorithmParameterException {
        final boolean encrypt;
        switch (opmode) {
	        case Cipher.ENCRYPT_MODE:
	        case Cipher.WRAP_MODE:
	            encrypt = true;
	            break;
	        case Cipher.DECRYPT_MODE:
	        case Cipher.UNWRAP_MODE:
	            encrypt = false;
	            break;
	        default:
	            throw new InvalidKeyException("Modo no valido: " + opmode); //$NON-NLS-1$
        }
        final RSAKey rsaKey = (RSAKey) key;
        if (key instanceof RSAPublicKey) {
            mode = encrypt ? MODE_ENCRYPT : MODE_VERIFY;
            publicKey = (RSAPublicKey)key;
            privateKey = null;
        }
        else { // RSAPrivateKey
            mode = encrypt ? MODE_SIGN : MODE_DECRYPT;
            privateKey = (RSAPrivateKey)key;
            publicKey = null;
        }
        final int n = RSACore.getByteLength(rsaKey.getModulus());
        outputSize = n;
        bufOfs = 0;
        if (PAD_NONE.equals(paddingType)) {
            if (params != null) {
                throw new InvalidAlgorithmParameterException(
            		"Parametros no soportados para datos sin relleno" //$NON-NLS-1$
        		);
            }
            padding = RSAPadding.createInstance(RSAPadding.PAD_NONE, n, rnd);
            buffer = new byte[n];
        }
        else if (PAD_PKCS1.equals(paddingType)) {
            if (params != null) {
                if (!(params instanceof TlsRsaPremasterSecretParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                		"Parametros no soportados para datos con relleno PKCS#1" //$NON-NLS-1$
            		);
                }

                spec = params;
                random = rnd;   // Para el TLS RSA premaster secret
            }
            final int blockType = mode <= MODE_DECRYPT ?
        		RSAPadding.PAD_BLOCKTYPE_2 :
        			RSAPadding.PAD_BLOCKTYPE_1;
            padding = RSAPadding.createInstance(blockType, n, rnd);
            if (encrypt) {
                final int k = padding.getMaxDataSize();
                buffer = new byte[k];
            }
            else {
                buffer = new byte[n];
            }
        }
        else { // PAD_OAEP_MGF1
            if (mode == MODE_SIGN || mode == MODE_VERIFY) {
                throw new InvalidKeyException(
            		"OAEP no puede usarse para firmar ni para verificar firmas" //$NON-NLS-1$
        		);
            }
            if (params != null) {
                if (!(params instanceof OAEPParameterSpec)) {
                    throw new InvalidAlgorithmParameterException("Parametros invalidos para el relleno OAEP"); //$NON-NLS-1$
                }
                spec = params;
            }
            else {
                spec = new OAEPParameterSpec(
            		oaepHashAlgorithm,
            		"MGF1", //$NON-NLS-1$
            		MGF1ParameterSpec.SHA1,
            		PSource.PSpecified.DEFAULT
        		);
            }
            padding = RSAPadding.createInstance(RSAPadding.PAD_OAEP_MGF1, n, rnd, (OAEPParameterSpec)spec);
            if (encrypt) {
                final int k = padding.getMaxDataSize();
                buffer = new byte[k];
            }
            else {
                buffer = new byte[n];
            }
        }
    }

    private void update(final byte[] inData, final int inOfs, final int inLen) {
        if (inLen == 0 || inData == null) {
            return;
        }
        if (bufOfs + inLen > buffer.length) {
            bufOfs = buffer.length + 1;
            return;
        }
        System.arraycopy(inData, inOfs, buffer, bufOfs, inLen);
        bufOfs += inLen;
    }

    private byte[] doFinal() throws BadPaddingException,
                                    IllegalBlockSizeException,
                                    CryptoCardException,
                                    PinException,
                                    LostChannelException {

        if (bufOfs > buffer.length) {
            throw new IllegalBlockSizeException(
        		"Los datos no pueden exceder los " + buffer.length + " octetos" //$NON-NLS-1$ //$NON-NLS-2$
    		);
        }
        try {
            final byte[] data;
            switch (mode) {
	            case MODE_SIGN:
	                data = padding.pad(buffer, 0, bufOfs);
	                return RSACore.rsa(data, privateKey);
	            case MODE_VERIFY:
	                final byte[] verifyBuffer = RSACore.convert(buffer, 0, bufOfs);
	                data = RSACore.rsa(verifyBuffer, publicKey);
	                return padding.unpad(data);
	            case MODE_ENCRYPT:
	                data = padding.pad(buffer, 0, bufOfs);
	                return RSACore.rsa(data, publicKey);
	            case MODE_DECRYPT:
	                final byte[] decryptBuffer = RSACore.convert(buffer, 0, bufOfs);
	                data = RSACore.rsa(decryptBuffer, privateKey);
	                return padding.unpad(data);
	            default:
	                throw new AssertionError("Modo no soportado: " + mode); //$NON-NLS-1$
            }
        }
        finally {
            bufOfs = 0;
        }
    }

    @Override
	protected byte[] engineUpdate(final byte[] inData, final int inOfs, final int inLen) {
        update(inData, inOfs, inLen);
        return B0;
    }

    @Override
	protected int engineUpdate(final byte[] inData,
			                   final int inOfs,
			                   final int inLen,
			                   final byte[] out,
			                   final int outOfs) {

        update(inData, inOfs, inLen);
        return 0;
    }

    @Override
	protected byte[] engineDoFinal(final byte[] inData,
			                       final int inOfs,
			                       final int inLen) throws BadPaddingException,
	                                                       IllegalBlockSizeException {
        update(inData, inOfs, inLen);
        try {
			return doFinal();
		}
        catch (final CryptoCardException  |
        		     PinException         |
        		     LostChannelException e) {
        	final BadPaddingException bpe = new BadPaddingException("Error en la operacion RSA con el DNIe"); //$NON-NLS-1$
        	bpe.initCause(e);
			throw bpe;
		}
    }

    @Override
	protected int engineDoFinal(final byte[] inData,
			                    final int inOfs,
			                    final int inLen,
			                    final byte[] out,
			                    final int outOfs) throws ShortBufferException,
	                                                     BadPaddingException,
	                                                     IllegalBlockSizeException {
        if (outputSize > out.length - outOfs) {
            throw new ShortBufferException(
        		"Se necesitan al menos " + outputSize + " bytes en el buffer de salida" //$NON-NLS-1$ //$NON-NLS-2$
    		);
        }
        update(inData, inOfs, inLen);
        final byte[] result;
		try {
			result = doFinal();
		}
		catch (final CryptoCardException |
				     PinException        |
				     LostChannelException e) {
        	final BadPaddingException bpe = new BadPaddingException("Error en la operacion RSA con el DNIe"); //$NON-NLS-1$
        	bpe.initCause(e);
			throw bpe;
		}
        final int n = result.length;
        System.arraycopy(result, 0, out, outOfs, n);
        return n;
    }

    @Override
	protected byte[] engineWrap(final Key key) throws InvalidKeyException, IllegalBlockSizeException {
        final byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeyException("No se ha podido obtener la codificacion de la clave"); //$NON-NLS-1$
        }
        if (encoded.length > buffer.length) {
            throw new InvalidKeyException("La cave es demasiado grande como para ser envuelta"); //$NON-NLS-1$
        }
        update(encoded, 0, encoded.length);
        try {
            return doFinal();
        }
        catch (final BadPaddingException e) {
            // No deberia ocurrir
            throw new InvalidKeyException("Ha fallado la envoltura por un relleno invalido", e); //$NON-NLS-1$
        }
        catch (final CryptoCardException |
        		     PinException        |
        		     LostChannelException e) {
        	throw new InvalidKeyException("Error en la operacion RSA con el DNIe", e); //$NON-NLS-1$
		}
    }

    @Override
	protected Key engineUnwrap(final byte[] wrappedKey,
			                   final String algorithm,
			                   final int type) throws InvalidKeyException,
	                                                  NoSuchAlgorithmException {
        if (wrappedKey.length > buffer.length) {
            throw new InvalidKeyException(
        		"La clave es demasiado grande para la desenvoltura" //$NON-NLS-1$
    		);
        }

        final boolean isTlsRsaPremasterSecret = "TlsRsaPremasterSecret".equals(algorithm); //$NON-NLS-1$
        Exception failover = null;

        byte[] encoded = null;

        update(wrappedKey, 0, wrappedKey.length);
        try {
            encoded = doFinal();
        }
        catch (final BadPaddingException e) {
            if (!isTlsRsaPremasterSecret) {
                throw new InvalidKeyException("Ha fallado la desenvoltura", e); //$NON-NLS-1$
            }
			failover = e;
        }
        catch (final IllegalBlockSizeException e) {
            // No deberia ocurrir, esto se controla anteriormente
            throw new InvalidKeyException("Ha fallado la desenvoltura por un tamano de bloque invalido", e); //$NON-NLS-1$
        }
        catch (final CryptoCardException |
	   		         PinException        |
	   		         LostChannelException e) {
        	throw new InvalidKeyException("Error en la operacion RSA con el DNIe", e); //$NON-NLS-1$
		}

        if (isTlsRsaPremasterSecret) {
            if (!(spec instanceof TlsRsaPremasterSecretParameterSpec)) {
                throw new IllegalStateException(
            		"No se ha especificado un TlsRsaPremasterSecretParameterSpec" + //$NON-NLS-1$
        				(spec != null ? ", sino un " + spec.getClass().getName() : "") //$NON-NLS-1$ //$NON-NLS-2$
        		);
            }

            // Preparamos el TLS premaster secret
            encoded = KeyUtil.checkTlsPreMasterSecretKey(
                ((TlsRsaPremasterSecretParameterSpec)spec).getClientVersion(),
                ((TlsRsaPremasterSecretParameterSpec)spec).getServerVersion(),
                random,
                encoded,
                failover != null
            );
        }

        return ConstructKeys.constructKey(encoded, algorithm, type);
    }

    @Override
	protected int engineGetKeySize(final Key key) throws InvalidKeyException {
        return ((RSAKey)key).getModulus().bitLength();
    }

}
