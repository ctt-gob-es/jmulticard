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

	public static int blockSize = 8;
	private byte[] keyBytes;
	private KeyParameter keyP = null;
	private byte[] IV = null;
	private byte[] sscBytes = null;

	private void initCiphers(byte[] key, byte[] iv) {
		// get the keyBytes
		keyBytes = new byte[key.length];
		System.arraycopy(key, 0, keyBytes, 0, key.length);

		// get the IV
		IV = new byte[blockSize];
		System.arraycopy(iv, 0, IV, 0, iv.length);

		keyP = new KeyParameter(keyBytes);

		encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new DESedeEngine()), new ISO7816d4Padding());
		decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new DESedeEngine()), new ISO7816d4Padding());

		// create the IV parameter
		ParametersWithIV parameterIV = new ParametersWithIV(keyP, IV);

		encryptCipher.init(true, parameterIV);
		decryptCipher.init(false, parameterIV);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#init(byte[], long)
	 */
	@Override
	public void init(byte[] keyBytes, byte[] ssc) {
		sscBytes = ssc.clone();
		initCiphers(keyBytes, new byte[blockSize]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#getMAC(byte[])
	 */
	@Override
	public byte[] getMAC(byte[] data) {

		byte[] n = new byte[8 + data.length];
		System.arraycopy(sscBytes, 0, n, 0, 8);
		System.arraycopy(data, 0, n, 8, data.length);

		BlockCipher cipher = new DESEngine();
		Mac mac = new ISO9797Alg3Mac(cipher, 64, new ISO7816d4Padding());

		ParametersWithIV parameterIV = new ParametersWithIV(keyP, IV);

		mac.init(parameterIV);
		mac.update(n, 0, n.length);

		byte[] out = new byte[8];

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
	public byte[] decryptBlock(byte[] key, byte[] z) {
		byte[] s = new byte[16];
		KeyParameter encKey = new KeyParameter(key);
		BlockCipher cipher = new DESedeEngine();
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
	public byte[] getMAC(byte[] key, byte[] data) {
		BlockCipher cipher = new DESEngine();
		Mac mac = new ISO9797Alg3Mac(cipher, 64, new ISO7816d4Padding());

		KeyParameter keyP = new KeyParameter(key);
		mac.init(keyP);
		mac.update(data, 0, data.length);

		byte[] out = new byte[8];

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
