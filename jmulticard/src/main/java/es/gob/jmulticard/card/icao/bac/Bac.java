package es.gob.jmulticard.card.icao.bac;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.CryptoHelper.DigestAlgorithm;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.iso7816four.ExternalAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.GetChallengeApduCommand;
import es.gob.jmulticard.card.icao.MrzInfo;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.de.tsenger.androsmex.crypto.Crypto;

/** Implementaci&oacute;n del protocolo BAC (<i>basic Access Control</i>).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Bac {

	private static final byte CLA = (byte) 0x00;

	private static final byte[] KENC_PADDING = {
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
	};

	private static final byte[] KMAC_PADDING = {
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02
	};

	/** Constante para ajustar la paridad de un array de octetos. */
	private static final byte[] PARITY = {
		8, 1, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 2, 8,
		0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 3,
		0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 0,
		8, 0, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8,
		0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 0,
		8, 0, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8,
		8, 0, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8,
		0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 0,
		0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 0,
		8, 0, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8,
		8, 0, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8,
		0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 0,
		8, 0, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8,
		0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 0,
		4, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 0,
		8, 5, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 6, 8
	};

	/** Establecimiento de canal BAC.
	 * @param mrz MRZ del documento de identidad electr&oacute;nico (MRTD).
	 * @param ch Utilidad de operaciones criptogr&aacute;ficas.
	 * @param conn Conexi&oacute;n con el MRTD.
	 * @throws IOException Si hay problemas en el tratamiento de datos.
	 * @throws Iso7816FourCardException Si hay problemas en el di&aacute;logo con el IC del MRTD. */
	public static void doBac(final String mrz,
			                 final CryptoHelper ch,
			                 final ApduConnection conn) throws IOException, Iso7816FourCardException {

		// Obtenemos el Kseed
		final MrzInfo mi = new MrzInfo(mrz);
		final byte[] kSeed = truncateMrzPwd(mi.getMrzPswd());

//final byte[] kSeed = new byte[] {
//	(byte)0x23, (byte)0x9A, (byte)0xB9, (byte)0xCB, (byte)0x28, (byte)0x2D, (byte)0xAF, (byte)0x66,
//	(byte)0x23, (byte)0x1D, (byte)0xC5, (byte)0xA4, (byte)0xDF, (byte)0x6B, (byte)0xFB, (byte)0xAE
//};
		System.out.println("keySeed: " + HexUtils.hexify(kSeed, false));

		// D.1 Calculamos las claves a partir de Kseed

		// Concatenamos Kseed con el relleno Enc
		final byte[] dEnc = HexUtils.concatenateByteArrays(
			kSeed,
			KENC_PADDING
		);

		// Calculamos el SHA-1 de dEnc
		final byte[] hSha1DEnc = ch.digest(DigestAlgorithm.SHA1, dEnc);

		// Creamos las claves 3DES kEnc
		final byte[] kEncA = new byte[8];
		System.arraycopy(hSha1DEnc, 0, kEncA, 0, 8);
		final byte[] kEncB = new byte[8];
		System.arraycopy(hSha1DEnc, 8, kEncB, 0, 8);

		// Ajustamos la paridad
//		adjustParity(kEncA);
//		adjustParity(kEncB);

//		System.out.println("kEncA = " + HexUtils.hexify(kEncA, false));
//		System.out.println("kEncB = " + HexUtils.hexify(kEncB, false));

		// Concatenamos Kseed con el relleno Mac
		final byte[] dMac = HexUtils.concatenateByteArrays(
			kSeed,
			KMAC_PADDING
		);

		// Calculamos el SHA-1 de dMac
		final byte[] hSha1DMac = ch.digest(DigestAlgorithm.SHA1, dMac);

		// Creamos las claves kMac
		final byte[] kMacA = new byte[8];
		System.arraycopy(hSha1DMac, 0, kMacA, 0, 8);
		final byte[] kMacB = new byte[8];
		System.arraycopy(hSha1DMac, 8, kMacB, 0, 8);

		// Ajustamos la paridad
//		adjustParity(kMacA);
//		adjustParity(kMacB);

//		System.out.println();
//		System.out.println("kMacA = " + HexUtils.hexify(kMacA, false));
//		System.out.println("kMacB = " + HexUtils.hexify(kMacB, false));

		// D.2 Derivamos las claves BAC kEnc y kMac
		final byte[] kEnc = HexUtils.concatenateByteArrays(kEncA, kEncB);
		final byte[] kMac = HexUtils.concatenateByteArrays(kMacA, kMacB);

		System.out.println();
		System.out.println("kEnc = " + HexUtils.hexify(kEnc, false));
		System.out.println("kMac = " + HexUtils.hexify(kMac, false));

		// D.3 Autenticacion y establecimiento de las claves de sesion

		if (!conn.isOpen()) {
			conn.open();
		}

		CommandApdu command;
		ResponseApdu response;

		command = new GetChallengeApduCommand(CLA);
		response = conn.transmit(command);
		if (!response.isOk()) {
			throw new Iso7816FourCardException(
				response.getStatusWord(),
				command,
				"Error obteniendo un desafio aleatorio (8 octetos) del MRTD" //$NON-NLS-1$
			);
		}
		final byte[] rndIc = response.getData();
//final byte[] rndIc = new byte[] { (byte) 0x46, (byte)0x08, (byte)0xF9, (byte)0x19, (byte)0x88, (byte)0x70, (byte)0x22, (byte)0x12 };

		System.out.println();
		System.out.println("RND.IC: " + HexUtils.hexify(rndIc, false));

		final byte[] rndIfd = ch.generateRandomBytes(8);
//final byte[] rndIfd = new byte[] { (byte) 0x78, (byte)0x17, (byte)0x23, (byte)0x86, (byte)0x0C, (byte)0x06, (byte)0xC2, (byte)0x26 };
		final byte[] kIfd = ch.generateRandomBytes(16);
//final byte[] kIfd = new byte[] { (byte) 0x0B, (byte)0x79, (byte)0x52, (byte)0x40, (byte)0xCB, (byte)0x70, (byte)0x49, (byte)0xB0, (byte)0x1C, (byte)0x19, (byte)0xB3, (byte)0x3E, (byte)0x32, (byte)0x80, (byte)0x4F, (byte)0x0B };

		System.out.println();
		System.out.println("RND.IFD: " + HexUtils.hexify(rndIfd, false));
		System.out.println("kIFD: " + HexUtils.hexify(kIfd, false));

		final byte[] s = HexUtils.concatenateByteArrays(rndIfd, rndIc, kIfd);
		System.out.println();
		System.out.println("S: " + HexUtils.hexify(s, true));

		final byte[] eIfd = ch.desedeEncrypt(s, kEnc);
		System.out.println();
		System.out.println("eIFD: " + HexUtils.hexify(eIfd, true));

		// Calculamos el MAC de eIFD con kMac como clave 3DES
		final byte[] mIfd;
		try {
			mIfd = Crypto.computeMAC(kMac, eIfd);
		}
		catch (final InvalidKeyException       |
				     NoSuchAlgorithmException  |
				     NoSuchPaddingException    |
				     IllegalBlockSizeException |
				     BadPaddingException e) {
			throw new IOException(e);
		}

		// Construimos el comando para la autenticacion externa
		final byte[] extAuthCmdData = HexUtils.concatenateByteArrays(eIfd, mIfd);
		System.out.println("cmd_data: " + HexUtils.hexify(extAuthCmdData, false));

		command = new ExternalAuthenticateApduCommand(CLA, extAuthCmdData);
		response = conn.transmit(command);
		if (!response.isOk()) {
			throw new Iso7816FourCardException(
				response.getStatusWord(),
				command,
				"Error en el inicio de la autenticacion externa" //$NON-NLS-1$
			);
		}

		System.out.println("APDU de autenticacion externa: " + command);
		System.out.println();
		System.out.println("resp_data: " + HexUtils.hexify(response.getData(), false));
//
//		// Desencriptamos la respuesta con kEnc
//		final byte[] externalAuthResponse = ch.desedeDecrypt(response.getData(), kEnc);
//
//		System.out.println();
//		System.out.println(HexUtils.hexify(externalAuthResponse, false));

	}

	private static byte[] truncateMrzPwd(final byte[] mrzInfoPwd) {
		if (mrzInfoPwd == null || mrzInfoPwd.length < 16) {
			throw new IllegalArgumentException(
				"La huella del 'MRZ Information' no puede ser nula ni tener menos de 16 octetos" //$NON-NLS-1$
			);
		}
	    final byte[] keySeed = new byte[16];
	    System.arraycopy(mrzInfoPwd, 0, keySeed, 0, 16);
	    return keySeed;
	}

	/** Ajusta la paridad de una clave binaria.
	 * Cada octeto tendr&aacute; un n&uacute;mero impar de bits a '1' (el &uacute;timo bit de cada octeto no se usa).
	 * @param key Clave binaria de entrada. */
	private static void adjustParity(final byte[] key) {
		for (int i = 0; i < 8; i++) {
			key[i] ^= PARITY[key[i] & 0xff] == 8 ? 1 : 0;
		}
	}

}
