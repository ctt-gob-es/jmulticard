package es.gob.jmulticard.de.tsenger.androsmex.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import es.gob.jmulticard.HexUtils;

/** Funciones criptogr&aacute;ficas auxiliares. */
public final class Crypto {

	private Crypto() {
		// No instanciable
	}

	/** Rellena un array de octetos seg&uacute;n ISO9797-1 (m&eacute;todo 2).
	 * @param data Datos de entrada a rellenar.
	 * @return Datos con el relleno aplicado. */
	private static byte[] padByteArray(final byte[] data) {

		int i = 0;
		final byte[] tempdata = new byte[data.length + 8];

		for (i = 0; i < data.length; i++) {
			tempdata[i] = data[i];
		}

		tempdata[i] = (byte) 0x80;

		for (i = i + 1; i % 8 != 0; i++) {
			tempdata[i] = (byte) 0;
		}

		final byte[] filledArray = new byte[i];
		System.arraycopy(tempdata, 0, filledArray, 0, i);
		return filledArray;
	}

	/** Calcula un MAC seg&uacute;n ISO/IEC 9797-1 Alg 3 con cifrado 3DES, vector de
	 * inicializaci&oacute;n a ceros (IV=0 de 8 octetos) y relleno ISO9797-1 (m&eacute;todo 2).
	 * @param key Clave 3DES.
	 * @param pt Datos sobre los que calcular el MAC.
	 * @return MAC de 8 octetos.
	 * @throws NoSuchPaddingException Si no se soporta el relleno aplicado al 3DES.
	 * @throws NoSuchAlgorithmException Si no se soporta el cifrado 'DES/ECB/NoPadding'.
	 * @throws InvalidKeyException Si la clave 3DES no es v&aacute;lida.
	 * @throws BadPaddingException Si el relleno aplicado al 3DES no es v&aacute;lido.
	 * @throws IllegalBlockSizeException Si hay problemas con el ECB. */
	public static byte[] computeMAC(final byte[] key, final byte[] pt) throws NoSuchAlgorithmException,
	                                                                          NoSuchPaddingException,
	                                                                          InvalidKeyException,
	                                                                          IllegalBlockSizeException,
	                                                                          BadPaddingException {
		Cipher des;
		final byte[] ka = new byte[8];
		final byte[] kb = new byte[8];
		System.arraycopy(key, 0, ka, 0, 8);
		System.arraycopy(key, 8, kb, 0, 8);

		final SecretKeySpec skeya = new SecretKeySpec(ka, "DES"); //$NON-NLS-1$
		final SecretKeySpec skeyb = new SecretKeySpec(kb, "DES"); //$NON-NLS-1$
		final byte[] current = new byte[8];
		byte[] mac = {
			(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0
		};

		final byte[] plaintext = padByteArray(pt);

		for (int i = 0; i < plaintext.length; i += 8) {
			System.arraycopy(plaintext, i, current, 0, 8);
			mac = HexUtils.xor(current, mac);
			des = Cipher.getInstance("DES/ECB/NoPadding"); //$NON-NLS-1$
			des.init(Cipher.ENCRYPT_MODE, skeya);
			mac = des.update(mac);
		}
		des = Cipher.getInstance("DES/ECB/NoPadding"); //$NON-NLS-1$
		des.init(Cipher.DECRYPT_MODE, skeyb);
		mac = des.update(mac);

		des.init(Cipher.ENCRYPT_MODE, skeya);
		return des.doFinal(mac);
	}

}
