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

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.Mac;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.macs.CMac;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */

public class AmAESCrypto extends AmCryptoProvider {

	private byte[] keyBytes = null;
	private KeyParameter keyP = null;
	private byte[] IV = null;
	private byte[] sscBytes = null;

	/** Tama&ntilde;o de bloque de cifrado */
	public static int blockSize = 16;

	private void initCiphers(final byte[] key, final byte[] iv) {

		// get the keyBytes
		this.keyBytes = new byte[key.length];
		System.arraycopy(key, 0, this.keyBytes, 0, key.length);

		this.keyP = new KeyParameter(this.keyBytes);

		// get the IV
		this.IV = new byte[blockSize];
		System.arraycopy(iv, 0, this.IV, 0, this.IV.length);

		// create the ciphers
		// AES block cipher in CBC mode with ISO7816d4 padding
		this.encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new AESFastEngine()), new ISO7816d4Padding());

		this.decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new AESFastEngine()), new ISO7816d4Padding());

		// create the IV parameter
		final ParametersWithIV parameterIV = new ParametersWithIV(this.keyP, this.IV);

		this.encryptCipher.init(true, parameterIV);
		this.decryptCipher.init(false, parameterIV);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#init(byte[], byte[])
	 */
	@Override
	public void init(final byte[] keyBytes1, final byte[] ssc) {

		this.sscBytes = ssc.clone();

		final byte[] iv = encryptBlock(keyBytes1, this.sscBytes);

		initCiphers(keyBytes1, iv);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#getMAC(byte[])
	 */
	@Override
	public byte[] getMAC(final byte[] data) {

		byte[] n = new byte[this.sscBytes.length + data.length];
		System.arraycopy(this.sscBytes, 0, n, 0, this.sscBytes.length);
		System.arraycopy(data, 0, n, this.sscBytes.length, data.length);
		n = addPadding(n);

		final BlockCipher cipher = new AESFastEngine();
		final Mac mac = new CMac(cipher, 64);

		mac.init(this.keyP);
		mac.update(n, 0, n.length);
		final byte[] out = new byte[mac.getMacSize()];

		mac.doFinal(out, 0);

		return out;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#getMAC(byte[], byte[])
	 */
	@Override
	public byte[] getMAC(final byte[] key, final byte[] data) {
		final BlockCipher cipher = new AESFastEngine();
		final Mac mac = new CMac(cipher, 64);

		final KeyParameter keyP1 = new KeyParameter(key);
		mac.init(keyP1);

		mac.update(data, 0, data.length);

		final byte[] out = new byte[8];

		mac.doFinal(out, 0);

		return out;
	}

	/**
	 * Dekodiert einen Block mit AES
	 *
	 * @param key
	 *            Byte-Array enthält den AES-Schlüssel
	 * @param z
	 *            verschlüsselter Block
	 * @return entschlüsselter block
	 */
	@Override
	public byte[] decryptBlock(final byte[] key, final byte[] z) {
		final byte[] s = new byte[blockSize];
		final KeyParameter encKey = new KeyParameter(key);
		final BlockCipher cipher = new AESFastEngine();
		cipher.init(false, encKey);
		cipher.processBlock(z, 0, s, 0);
		return s;
	}

	/**
	 * Kodiert einen Block mit AES
	 *
	 * @param key
	 *            Byte-Array enthält den AES-Schlüssel
	 * @param z
	 *            verschlüsselter Block
	 * @return entschlüsselter block
	 */

	public static byte[] encryptBlock(final byte[] key, final byte[] z) {
		final byte[] s = new byte[blockSize];
		final KeyParameter encKey = new KeyParameter(key);
		final BlockCipher cipher = new AESFastEngine();
		cipher.init(true, encKey);
		cipher.processBlock(z, 0, s, 0);
		return s;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#getBlockSize()
	 */
	@Override
	public int getBlockSize() {
		return blockSize;
	}

}
