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
import java.security.Security;

import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.jce.provider.BouncyCastleProvider;

/** Operaciones criptogr&aacute;ficas de utilidad para el canal inal&aacute;mbrico.
 * @author Tobias Senger (tobias@t-senger.de). */
public abstract class AmCryptoProvider {

	/** Cifrador. */
	protected PaddedBufferedBlockCipher encryptCipher = null;

	/** Descifrador. */
	protected PaddedBufferedBlockCipher decryptCipher = null;

	// Buffers para mover octetos de un flujo a otro
	private final byte[] buf = new byte[16]; // Buffer de entrada
	private final byte[] obuf = new byte[512]; // Buffer de salida

	/** Crea el objeto de operaciones criptogr&aacute;ficas.
	 * &Uacute;nicamente a&ntilde;ade BouncyCastle si no estaba ya a&ntilde;adido como
	 * proveedor. */
	public AmCryptoProvider() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/** Inicializa el motor criptogr&aacute;fico con la clave y el contador de secuencia de env&iacute;os
	 * (<i>Send Sequence Counter</i>: SSC).
	 * @param keyBytes Clave.
	 * @param ssc Contador de secuencia de env&iacute;os (Send Sequence Counter). */
	public abstract void init(byte[] keyBytes, byte[] ssc);

	/** Obtiene el tama&ntilde;o de bloque de cifrado.
	 * @return Obtiene el tama&ntilde;o de bloque de cifrado */
	public abstract int getBlockSize();

	/** Obtiene el Codigo de Autenticaci&oacute;n de Mensaje (MAC) de los datos proporcionados.
	 * El algoritmo depende de la implementaci&oacute;n concreta de la clase.
	 * @param data Datos sobre los que calcular el MAC.
	 * @return MAC de los datos. */
	public abstract byte[] getMAC(byte[] data);

	/** Encripta datos (el algoritmo depende de la implementaci&oacute;n concreta de la clase).
	 * @param in Datos en claro (a cifrar).
	 * @return Datos cifrados.
	 * @throws AmCryptoException En cualquier error. */
	public final byte[] encrypt(final byte[] in) throws AmCryptoException {

		int noBytesRead = 0; // Numero de octetos leidos de la entrada
		int noBytesProcessed = 0; // Numero de octetos procesados

		try (
			final InputStream bin = new ByteArrayInputStream(in);
			final ByteArrayOutputStream bout = new ByteArrayOutputStream()
		) {
			try {
				while ((noBytesRead = bin.read(this.buf)) >= 0) {
					noBytesProcessed = this.encryptCipher.processBytes(
						this.buf,
						0,
						noBytesRead,
						this.obuf,
						0
					);
					bout.write(this.obuf, 0, noBytesProcessed);
				}
			}
			catch (final DataLengthException | IllegalStateException | IOException e) {
				throw new AmCryptoException(e);
			}

			try {
				noBytesProcessed = this.encryptCipher.doFinal(this.obuf, 0);
				bout.write(this.obuf, 0, noBytesProcessed);
				bout.flush();
				return bout.toByteArray();
			}
			catch (final DataLengthException | IllegalStateException | InvalidCipherTextException | IOException e) {
				throw new AmCryptoException(e);
			}
		}
		catch (final IOException ioe) {
			throw new AmCryptoException(ioe);
		}
	}

	/** Desencripta datos (el algoritmo depende de la implementaci&oacute;n concreta de la clase).
	 * @param in Datos cifrados.
	 * @return Datos descifrados (en claro).
	 * @throws AmCryptoException En cualquier error. */
	public final byte[] decrypt(final byte[] in) throws AmCryptoException {

		int noBytesRead = 0; // Numero de octetos leidos de la entrada
		int noBytesProcessed = 0; // Numero de octetos procesados

		try (
			final InputStream bin = new ByteArrayInputStream(in);
			final ByteArrayOutputStream bout = new ByteArrayOutputStream()
		) {
			try {
				while ((noBytesRead = bin.read(this.buf)) >= 0) {
					noBytesProcessed = this.decryptCipher.processBytes(
						this.buf,
						0,
						noBytesRead,
						this.obuf,
						0
					);
					bout.write(this.obuf, 0, noBytesProcessed);
				}
			}
			catch (final DataLengthException | IllegalStateException | IOException e) {
				throw new AmCryptoException(e);
			}

			try {
				noBytesProcessed = this.decryptCipher.doFinal(this.obuf, 0);
				bout.write(this.obuf, 0, noBytesProcessed);
				bout.flush();
				return bout.toByteArray();
			}
			catch (final DataLengthException | IllegalStateException | InvalidCipherTextException | IOException e) {
				throw new AmCryptoException(e);
			}
		}
		catch (final IOException ioe) {
			throw new AmCryptoException(ioe);
		}
	}

	/** A&ntilde;ade un rellano ISO9797-1 (m&eacute;todo 2) / ISO7816d4-Padding a los datos proporcionados.
	 * @param data Datos a rellenar.
	 * @return Datos con el relleno aplicado. */
	public final byte[] addPadding(final byte[] data) {
		final int len = data.length;
		final int nLen = (len / getBlockSize() + 1) * getBlockSize();
		final byte[] n = new byte[nLen];
		System.arraycopy(data, 0, n, 0, data.length);
		new ISO7816d4Padding().addPadding(n, len);
		return n;
	}

	/** Retira un relleno (<i>padding</i>) ISO9797-1 / ISO7816d4-Padding.
	 * @param b Array de octetos con relleno.
	 * @return Array de octetos sin relleno. */
	public static final byte[] removePadding(final byte[] b) {
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
