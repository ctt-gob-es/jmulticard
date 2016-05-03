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

	public static int blockSize = 16;

	private void initCiphers(byte[] key, byte[] iv) {

		// get the keyBytes
		keyBytes = new byte[key.length];
		System.arraycopy(key, 0, keyBytes, 0, key.length);

		keyP = new KeyParameter(keyBytes);

		// get the IV
		IV = new byte[blockSize];
		System.arraycopy(iv, 0, IV, 0, IV.length);

		// create the ciphers
		// AES block cipher in CBC mode with ISO7816d4 padding
		encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new AESFastEngine()), new ISO7816d4Padding());

		decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new AESFastEngine()), new ISO7816d4Padding());

		// create the IV parameter
		ParametersWithIV parameterIV = new ParametersWithIV(keyP, IV);

		encryptCipher.init(true, parameterIV);
		decryptCipher.init(false, parameterIV);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#init(byte[], byte[])
	 */
	@Override
	public void init(byte[] keyBytes, byte[] ssc) {

		sscBytes = ssc.clone();

		byte[] iv = encryptBlock(keyBytes, sscBytes);

		initCiphers(keyBytes, iv);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#getMAC(byte[])
	 */
	@Override
	public byte[] getMAC(byte[] data) {

		byte[] n = new byte[sscBytes.length + data.length];
		System.arraycopy(sscBytes, 0, n, 0, sscBytes.length);
		System.arraycopy(data, 0, n, sscBytes.length, data.length);
		n = addPadding(n);

		BlockCipher cipher = new AESFastEngine();
		Mac mac = new CMac(cipher, 64);

		mac.init(keyP);
		mac.update(n, 0, n.length);
		byte[] out = new byte[mac.getMacSize()];

		mac.doFinal(out, 0);

		return out;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.crypto.AmCryptoProvider#getMAC(byte[], byte[])
	 */
	@Override
	public byte[] getMAC(byte[] key, byte[] data) {
		BlockCipher cipher = new AESFastEngine();
		Mac mac = new CMac(cipher, 64);

		KeyParameter keyP1 = new KeyParameter(key);
		mac.init(keyP1);

		mac.update(data, 0, data.length);

		byte[] out = new byte[8];

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
	public byte[] decryptBlock(byte[] key, byte[] z) {
		byte[] s = new byte[blockSize];
		KeyParameter encKey = new KeyParameter(key);
		BlockCipher cipher = new AESFastEngine();
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

	public byte[] encryptBlock(byte[] key, byte[] z) {
		byte[] s = new byte[blockSize];
		KeyParameter encKey = new KeyParameter(key);
		BlockCipher cipher = new AESFastEngine();
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
