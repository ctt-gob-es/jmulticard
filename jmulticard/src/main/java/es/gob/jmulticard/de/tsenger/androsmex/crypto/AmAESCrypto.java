/**
 *  Copyright 2011, Tobias Senger
 *
 *  This file is part of animamea.
 *
 *  Animamea is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Animamea is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with animamea.  If not, see <http://www.gnu.org/licenses/>.
 */

package es.gob.jmulticard.de.tsenger.androsmex.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.BlockCipherPadding;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import es.gob.jmulticard.CryptoHelper;

/** Implementaci&oacute;n de las operaciones criptogr&aacute;ficas usando AES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s.
 * @author Tobias Senger (tobias@t-senger.de). */
public final class AmAESCrypto {

	private static final BlockCipherPadding ISO7816D4_PADDING = new ISO7816d4Padding();

	/** Tama&ntilde;o de bloque de cifrado. */
	public static final int BLOCK_SIZE = 16;

	// Unicamente anade BouncyCastle si no estaba ya anadido como proveedor
	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private AmAESCrypto() {
		// No instanciable
	}

	/** Obtiene el C&oacute;digo de Autenticaci&oacute;n de Mensaje (MAC) de
	 * tipo AES para los datos proporcionados.
	 * @param data Datos sobre los que calcular el MAC.
	 * @param ssc Contador de secuencia de env&iacute;os (<i>Send Sequence Counter</i>).
	 * @param keyBytes Clave de creaci&oacute;n de MAC.
	 * @param cryptoHelper Utilidad para las operaciones criptogr&aacute;ficas.
	 * @return MAC de los datos.
	 * @throws NoSuchAlgorithmException Si no se encuentra el algoritmo de creaci&oacute;n
	 *                                  del MAC.
	 * @throws InvalidKeyException Si la clave de creaci&oacute;n del MAC es inv&aacute;lida. */
	public static byte[] getMac(final byte[] data,
			                    final byte[] ssc,
			                    final byte[] keyBytes,
			                    final CryptoHelper cryptoHelper) throws InvalidKeyException,
	                                                                    NoSuchAlgorithmException {
		final byte[] n = new byte[ssc.length + data.length];
		System.arraycopy(ssc, 0, n, 0, ssc.length);
		System.arraycopy(data, 0, n, ssc.length, data.length);
		return cryptoHelper.doAesCmac(addPadding(n), keyBytes);
	}

	/** Encripta un bloque usando AES.
	 * @param aesKey Clave AES.
	 * @param z Bloque a crifrar (debe tener el tama&ntilde;o justo para la clave proporcionada).
	 * @return Bloque cifrado.
	 * @throws NoSuchPaddingException No debe producirse, no se aplica relleno a los datos de entrada.
	 * @throws NoSuchAlgorithmException Si no se encuentra un cifrador para el algoritmo 'AES/ECB/NoPadding'.
	 * @throws InvalidKeyException Si la clave proporcionada no es una clave AES v&aacute;lida.
	 * @throws BadPaddingException No debe producirse, no se aplica relleno a los datos de entrada.
	 * @throws IllegalBlockSizeException Si los datos proporcionados no miden exactamente un bloque AES (16 octetos). */
	private static byte[] encryptBlock(final byte[] aesKey,
			                           final byte[] z) throws NoSuchAlgorithmException,
	                                                          NoSuchPaddingException,
	                                                          InvalidKeyException,
	                                                          IllegalBlockSizeException,
	                                                          BadPaddingException {
		final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding"); //$NON-NLS-1$
		final SecretKey originalKey = new SecretKeySpec(aesKey, "AES"); //$NON-NLS-1$
		cipher.init(Cipher.ENCRYPT_MODE, originalKey);
		return cipher.doFinal(z);
	}

	/** Encripta datos (AES/CBC/ISO7816d4Padding).
	 * @param in Datos en claro (a cifrar).
	 * @param aesKey Clave de cifrado.
	 * @param ssc Contador de secuencia de env&iacute;os (<i>Send Sequence Counter</i>).
	 * @param ch Utilidad para las operaciones criptogr&aacute;ficas.
	 * @return Datos cifrados.
	 * @throws AmCryptoException En cualquier error. */
	public static byte[] encrypt(final byte[] in,
			                     final byte[] aesKey,
			                     final byte[] ssc,
			                     final CryptoHelper ch) throws AmCryptoException {
		try {
			return ch.aesEncrypt(
				in,
				encryptBlock(aesKey, ssc),
				aesKey,
				"ISO7816-4Padding" //$NON-NLS-1$
			);
		}
		catch (final InvalidKeyException       |
		             NoSuchAlgorithmException  |
		             NoSuchPaddingException    |
		             IllegalBlockSizeException |
		             BadPaddingException e1) {
			throw new AmCryptoException(
				"Error creando el vector de inicializacion AES mediante un cifrado de bloque AES: " + e1, e1 //$NON-NLS-1$
			);
		}
		catch (final IOException e) {
			throw new AmCryptoException(
				"Error en el cifrado AES: " + e, e //$NON-NLS-1$
			);
		}

	}

	/** Desencripta datos (el algoritmo depende de la implementaci&oacute;n
	 * concreta de la clase).
	 * @param in Datos cifrados.
	 * @param key Clave de descifrado.
	 * @param ssc Contador de secuencia de env&iacute;os (<i>Send Sequence Counter</i>).
	 * @param ch Utilidad para las operaciones criptogr&aacute;ficas.
	 * @return Datos descifrados (en claro).
	 * @throws AmCryptoException En cualquier error. */
	public static byte[] decrypt(final byte[] in,
                                 final byte[] key,
                                 final byte[] ssc,
                                 final CryptoHelper ch) throws AmCryptoException {

		int noBytesRead = 0; // Numero de octetos leidos de la entrada
		int noBytesProcessed = 0; // Numero de octetos procesados

		final BufferedBlockCipher decryptCipher = new PaddedBufferedBlockCipher(
			new CBCBlockCipher(
				new AESEngine()
			),
			ISO7816D4_PADDING
		);
		// Creamos los parametros de descifrado con el vector de inicializacion (iv)
		final ParametersWithIV parameterIV;
		try {
			parameterIV = new ParametersWithIV(
				new KeyParameter(key),
				encryptBlock(key, ssc)
			);
		}
		catch (final InvalidKeyException       |
			         NoSuchAlgorithmException  |
			         NoSuchPaddingException    |
			         IllegalBlockSizeException |
			         BadPaddingException e1) {
			throw new AmCryptoException(
				"Error creando el vector de inicializacion AES mediante un cifrado de bloque AES: " + e1, e1 //$NON-NLS-1$
			);
		}
		// Inicializamos
		decryptCipher.init(false, parameterIV);

		// Buffers para mover octetos de un flujo a otro
		final byte[] buf = new byte[16]; // Buffer de entrada
		final byte[] obuf = new byte[512]; // Buffer de salida

		try (
			final InputStream bin = new ByteArrayInputStream(in);
			final ByteArrayOutputStream bout = new ByteArrayOutputStream()
		) {
			try {
				while ((noBytesRead = bin.read(buf)) >= 0) {
					noBytesProcessed = decryptCipher.processBytes(
						buf,
						0,
						noBytesRead,
						obuf,
						0
					);
					bout.write(obuf, 0, noBytesProcessed);
				}
			}
			catch (final Exception e) {
				throw new AmCryptoException(e);
			}

			try {
				noBytesProcessed = decryptCipher.doFinal(obuf, 0);
				bout.write(obuf, 0, noBytesProcessed);
				bout.flush();
				return bout.toByteArray();
			}
			catch (final Exception e) {
				throw new AmCryptoException(e);
			}
		}
		catch (final IOException ioe) {
			throw new AmCryptoException(ioe);
		}
	}

	/** A&ntilde;ade un relleno ISO9797-1 (m&eacute;todo 2) / ISO7816d4-Padding
	 * a los datos proporcionados.
	 * @param data Datos a rellenar.
	 * @return Datos con el relleno aplicado. */
	public static byte[] addPadding(final byte[] data) {
		final int len = data.length;
		final int nLen = (len / BLOCK_SIZE + 1) * BLOCK_SIZE;
		final byte[] n = new byte[nLen];
		System.arraycopy(data, 0, n, 0, data.length);
		ISO7816D4_PADDING.addPadding(n, len);
		return n;
	}

	/** Retira un relleno (<i>padding</i>) ISO9797-1 / ISO7816d4-Padding.
	 * @param b Array de octetos con relleno.
	 * @return Array de octetos sin relleno. */
	public static byte[] removePadding(final byte[] b) {
		int i = b.length - 1;
		do {
			i--;
		} while (b[i] == (byte) 0x00);

		if (b[i] == (byte) 0x80) {
			final byte[] rd = new byte[i];
			System.arraycopy(b, 0, rd, 0, rd.length);
			return rd;
		}
		return b;
	}
}
