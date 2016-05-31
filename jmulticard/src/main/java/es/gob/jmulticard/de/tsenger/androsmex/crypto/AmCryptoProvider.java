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
import java.security.Security;

import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public abstract class AmCryptoProvider {

	protected PaddedBufferedBlockCipher encryptCipher = null;
	protected PaddedBufferedBlockCipher decryptCipher = null;

	// Buffer are used to transport the bytes from one stream to another
	byte[] buf = new byte[16]; // input buffer
	byte[] obuf = new byte[512]; // output buffer

	/**
	 * Asigna un proveedor criptogr&aacute;fico.
	 */
	public AmCryptoProvider() {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Initialisiert die Crypto-Engine mit dem angegebenen Schlüssel und dem
	 * Send Sequence Counter (SSC)
	 *
	 * @param keyBytes
	 *            Schlüssel
	 * @param ssc
	 *            Send Sequence Counter
	 */
	public abstract void init(byte[] keyBytes, byte[] ssc);

	/** Obtiene el tama&ntilde;o de bloque de cifrado.
	 * @return Obtiene el tama&ntilde;o de bloque de cifrado */
	public abstract int getBlockSize();

	/** Obtiene el array de bytes descifrado.
	 * @param key Clave de cifrado.
	 * @param z Clave de cifrado.
	 * @return Obtiene el array de bytes descifrado.
	 */
	public abstract byte[] decryptBlock(byte[] key, byte[] z);

	/**
	 * Berechnet den Mac der übergebenen Daten ohne vorherige Initialisierung
	 * (@see #init(byte[], long). Es wird daher kein SSC benötigt.
	 *
	 * @param key
	 *            Schlüssel
	 * @param data
	 *            Die Daten über die der MAC gebildet werden soll.
	 * @return MAC
	 */
	public abstract byte[] getMAC(byte[] key, byte[] data);

	/**
	 * Berechnet den Message Authentication Code (MAC) aus dem übergebenen
	 * ByteArray. Die Parametern werden vorher mit der Methode @see
	 * #init(byte[], long) eingestellt.
	 *
	 * @param data
	 *            Die Daten über die der MAC gebildet werden soll.
	 * @return MAC
	 */
	public abstract byte[] getMAC(byte[] data);

	/**
	 * Verschlüsselt das übergebene ByteArray mit den Parametern die beim @see
	 * #init(byte[], long) eingestellt wurden.
	 *
	 * @param in
	 *            ByteArray mit den zu verschlüsselnden Daten
	 * @return ByteArray mit den entschlüsselten Daten.
	 * @throws AmCryptoException On any error.
	 */
	public byte[] encrypt(final byte[] in) throws AmCryptoException {

		final ByteArrayInputStream bin = new ByteArrayInputStream(in);
		final ByteArrayOutputStream bout = new ByteArrayOutputStream();

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed

		try {
			while ((noBytesRead = bin.read(this.buf)) >= 0) {
				noBytesProcessed = this.encryptCipher.processBytes(this.buf, 0, noBytesRead,
						this.obuf, 0);
				bout.write(this.obuf, 0, noBytesProcessed);
			}
		} catch (final DataLengthException e) {
			throw new AmCryptoException(e);
		} catch (final IllegalStateException e) {
			throw new AmCryptoException(e);
		} catch (final IOException e) {
			throw new AmCryptoException(e);
		}

		try {
			noBytesProcessed = this.encryptCipher.doFinal(this.obuf, 0);
			bout.write(this.obuf, 0, noBytesProcessed);

			bout.flush();

			bin.close();
			bout.close();
			return bout.toByteArray();
		} catch (final DataLengthException e) {
			throw new AmCryptoException(e);
		} catch (final IllegalStateException e) {
			throw new AmCryptoException(e);
		} catch (final InvalidCipherTextException e) {
			throw new AmCryptoException(e);
		} catch (final IOException e) {
			throw new AmCryptoException(e);
		}


	}

	/**
	 * Entschlüsselt das übergebene ByteArray mit den Parametern die beim @see
	 * #init(byte[], long) eingestellt wurden.
	 *
	 * @param in
	 *            BytrArray mit den verschlüsselten Daten
	 * @return ByteArray mit den entschlüsselten Daten
	 * @throws AmCryptoException On any error.
	 */
	public byte[] decrypt(final byte[] in) throws AmCryptoException {

		final ByteArrayInputStream bin = new ByteArrayInputStream(in);
		final ByteArrayOutputStream bout = new ByteArrayOutputStream();

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed

		try {
			while ((noBytesRead = bin.read(this.buf)) >= 0) {
				noBytesProcessed = this.decryptCipher.processBytes(this.buf, 0, noBytesRead,
						this.obuf, 0);
				bout.write(this.obuf, 0, noBytesProcessed);
			}
		} catch (final DataLengthException e) {
			throw new AmCryptoException(e);
		} catch (final IllegalStateException e) {
			throw new AmCryptoException(e);
		} catch (final IOException e) {
			throw new AmCryptoException(e);
		}

		try {
			noBytesProcessed = this.decryptCipher.doFinal(this.obuf, 0);

			bout.write(this.obuf, 0, noBytesProcessed);

			bout.flush();

			bin.close();
			bout.close();
			return bout.toByteArray();
		} catch (final DataLengthException e) {
			throw new AmCryptoException(e);
		} catch (final IllegalStateException e) {
			throw new AmCryptoException(e);
		} catch (final InvalidCipherTextException e) {
			throw new AmCryptoException(e);
		} catch (final IOException e) {
			throw new AmCryptoException(e);
		}

	}

	/**
	 * Diese Methode füllt ein Byte-Array mit dem Wert 0x80 und mehreren 0x00
	 * bis die Länge des übergebenen Byte-Array ein Vielfaches der Blocklänge
	 * ist. Dies ist die ISO9797-1 Padding-Methode 2 bzw. ISO7816d4-Padding
	 *
	 * @param data
	 *            Das Byte-Array welches aufgefüllt werden soll.
	 * @return Das gefüllte Byte-Array.
	 */
	public byte[] addPadding(final byte[] data) {

		final int len = data.length;
		final int nLen = (len / getBlockSize() + 1) * getBlockSize();
		final byte[] n = new byte[nLen];
		System.arraycopy(data, 0, n, 0, data.length);
		new ISO7816d4Padding().addPadding(n, len);
		return n;
	}

	/**
	 * Entfernt aus dem übergebenen Byte-Array das Padding nach ISO9797-1
	 * Padding-Methode 2 bzw. ISO7816d4-Padding.
	 *
	 * @param b
	 *            Byte-Array aus dem das Padding entfernt werden soll
	 * @return Padding-bereinigtes Byte-Array
	 */
	public static byte[] removePadding(final byte[] b) {
		byte[] rd = null;
		int i = b.length - 1;
		do {
			i--;
		} while (b[i] == (byte) 0x00);

		if (b[i] == (byte) 0x80) {
			rd = new byte[i];
			System.arraycopy(b, 0, rd, 0, rd.length);
			return rd;
		}
		return b;
	}
}
