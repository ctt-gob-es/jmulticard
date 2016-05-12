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
import org.spongycastle.crypto.engines.DESEngine;
import org.spongycastle.crypto.engines.DESedeEngine;
import org.spongycastle.crypto.macs.ISO9797Alg3Mac;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class AmDESCrypto extends AmCryptoProvider {

	/** Tama&ntilde;o de bloque de cifrado */
	public static int blockSize = 8;
	private byte[] keyBytes;
	private KeyParameter keyP = null;
	private byte[] IV = null;
	private byte[] sscBytes = null;

	private void initCiphers(final byte[] key, final byte[] iv) {
		// get the keyBytes
		this.keyBytes = new byte[key.length];
		System.arraycopy(key, 0, this.keyBytes, 0, key.length);

		// get the IV
		this.IV = new byte[blockSize];
		System.arraycopy(iv, 0, this.IV, 0, iv.length);

		this.keyP = new KeyParameter(this.keyBytes);

		this.encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new DESedeEngine()), new ISO7816d4Padding());
		this.decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new DESedeEngine()), new ISO7816d4Padding());

		// create the IV parameter
		final ParametersWithIV parameterIV = new ParametersWithIV(this.keyP, this.IV);

		this.encryptCipher.init(true, parameterIV);
		this.decryptCipher.init(false, parameterIV);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#init(byte[], long)
	 */
	@Override
	public void init(final byte[] keyBytes1, final byte[] ssc) {
		this.sscBytes = ssc.clone();
		initCiphers(keyBytes1, new byte[blockSize]);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#getMAC(byte[])
	 */
	@Override
	public byte[] getMAC(final byte[] data) {

		final byte[] n = new byte[8 + data.length];
		System.arraycopy(this.sscBytes, 0, n, 0, 8);
		System.arraycopy(data, 0, n, 8, data.length);

		final BlockCipher cipher = new DESEngine();
		final Mac mac = new ISO9797Alg3Mac(cipher, 64, new ISO7816d4Padding());

		final ParametersWithIV parameterIV = new ParametersWithIV(this.keyP, this.IV);

		mac.init(parameterIV);
		mac.update(n, 0, n.length);

		final byte[] out = new byte[8];

		mac.doFinal(out, 0);

		return out;
	}

	/**
	 * Dekodiert einen Block mit DES
	 *
	 * @param key
	 *            Byte-Array enthält den 3DES-Schlüssel
	 * @param z
	 *            verschlüsselter Block
	 * @return entschlüsselter block
	 */
	@Override
	public byte[] decryptBlock(final byte[] key, final byte[] z) {
		final byte[] s = new byte[16];
		final KeyParameter encKey = new KeyParameter(key);
		final BlockCipher cipher = new DESedeEngine();
		cipher.init(false, encKey);
		cipher.processBlock(z, 0, s, 0);
		return s;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#getMAC(byte[], byte[])
	 */
	@Override
	public byte[] getMAC(final byte[] key, final byte[] data) {
		final BlockCipher cipher = new DESEngine();
		final Mac mac = new ISO9797Alg3Mac(cipher, 64, new ISO7816d4Padding());

		final KeyParameter keyP1 = new KeyParameter(key);
		mac.init(keyP1);
		mac.update(data, 0, data.length);

		final byte[] out = new byte[8];

		mac.doFinal(out, 0);

		return out;
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
