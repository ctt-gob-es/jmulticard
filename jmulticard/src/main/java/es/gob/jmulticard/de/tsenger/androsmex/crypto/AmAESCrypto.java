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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import es.gob.jmulticard.CryptoHelper;

/** Implementaci&oacute;n de las operaciones criptogr&aacute;ficas usando AES.
 * @author Tobias Senger (tobias@t-senger.de). */
public final class AmAESCrypto extends AmCryptoProvider {

	private byte[] keyBytes = null;
	private byte[] IV = null;
	private byte[] sscBytes = null;
	private CryptoHelper cryptoHelper = null;

	/** Crea el objeto de operaciones criptogr&aacute;ficas.
	 * &Uacute;nicamente a&ntilde;ade BouncyCastle si no estaba ya a&ntilde;adido como
	 * proveedor. */
	public AmAESCrypto() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private void initCiphers(final byte[] key, final byte[] iv) {

		// Obtenemos los octetos de la clave
		this.keyBytes = new byte[key.length];
		System.arraycopy(key, 0, this.keyBytes, 0, key.length);

		// Obtenemos el vector de inicializacion (IV)
		this.IV = new byte[BLOCK_SIZE];
		System.arraycopy(iv, 0, this.IV, 0, this.IV.length);

		// Creamos los cifradores
		// AES block cipher en modo CBC con padding ISO7816d4
		this.encryptCipher = new PaddedBufferedBlockCipher(
			new CBCBlockCipher(
				new AESEngine()
			),
			new ISO7816d4Padding()
		);

		this.decryptCipher = new PaddedBufferedBlockCipher(
			new CBCBlockCipher(
				new AESEngine()
			),
			new ISO7816d4Padding()
		);

		// Creamos los parametros de cifrado con el vector de inicializacion (IV)
		final ParametersWithIV parameterIV = new ParametersWithIV(
			new KeyParameter(this.keyBytes),
			this.IV
		);

		this.encryptCipher.init(true, parameterIV);
		this.decryptCipher.init(false, parameterIV);
	}

	@Override
	public void init(final byte[] keyBytes1,
			         final byte[] ssc,
			         final CryptoHelper ch) {

		this.sscBytes = ssc.clone();
		this.cryptoHelper = ch;
		final byte[] iv = encryptBlock(keyBytes1, this.sscBytes);
		initCiphers(keyBytes1, iv);
	}

	@Override
	public byte[] getMAC(final byte[] data) throws InvalidKeyException,
	                                               NoSuchAlgorithmException {

		byte[] n = new byte[this.sscBytes.length + data.length];
		System.arraycopy(this.sscBytes, 0, n, 0, this.sscBytes.length);
		System.arraycopy(data, 0, n, this.sscBytes.length, data.length);
		n = addPadding(n);

		return this.cryptoHelper.doAesCmac(n, this.keyBytes);
	}

	/** Encripta un bloque usando AES.
	 * @param key Clave AES.
	 * @param z Bloque a crifrar.
	 * @return Bloque cifrado. */
	public static byte[] encryptBlock(final byte[] key, final byte[] z) {
		final byte[] s = new byte[BLOCK_SIZE];
		final KeyParameter encKey = new KeyParameter(key);
		final BlockCipher cipher = new AESEngine();
		cipher.init(true, encKey);
		cipher.processBlock(z, 0, s, 0);
		return s;
	}
}
