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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.CryptoHelper.Padding;

/** Implementaci&oacute;n de las operaciones criptogr&aacute;ficas usando AES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s.
 * @author Tobias Senger (tobias@t-senger.de). */
public final class AmAESCrypto {

	/** Tama&ntilde;o de bloque de cifrado. */
	public static final int BLOCK_SIZE = 16;

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
				encryptBlock(aesKey, ssc), // Vector de inicializacion
				aesKey,
				Padding.ISO7816_4PADDING
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
	 * @param aesKey Clave de descifrado.
	 * @param ssc Contador de secuencia de env&iacute;os (<i>Send Sequence Counter</i>).
	 * @param ch Utilidad para las operaciones criptogr&aacute;ficas.
	 * @return Datos descifrados (en claro).
	 * @throws AmCryptoException En cualquier error. */
	public static byte[] decrypt(final byte[] in,
                                 final byte[] aesKey,
                                 final byte[] ssc,
                                 final CryptoHelper ch) throws AmCryptoException {
		try {
			return ch.aesDecrypt(
				in,
				encryptBlock(aesKey, ssc), // Vector de inicializacion
				aesKey,
				Padding.ISO7816_4PADDING
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

	/** A&ntilde;ade un relleno ISO9797-1 (m&eacute;todo 2) / ISO7816d4-Padding
	 * a los datos proporcionados.
	 * @param data Datos a rellenar.
	 * @return Datos con el relleno aplicado. */
	public static byte[] addPadding(final byte[] data) {
		int len = data.length;
		final int nLen = (len / BLOCK_SIZE + 1) * BLOCK_SIZE;
		final byte[] in = new byte[nLen];
		System.arraycopy(data, 0, in, 0, data.length);

        in [len]= (byte) 0x80;
        len ++;
        while (len < in.length) {
            in[len] = (byte) 0;
            len++;
        }
        return in;
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
