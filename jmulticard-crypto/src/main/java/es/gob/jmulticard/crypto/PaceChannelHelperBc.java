package es.gob.jmulticard.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.CryptoHelper.BlockMode;
import es.gob.jmulticard.CryptoHelper.PaceChannelHelper;
import es.gob.jmulticard.CryptoHelper.Padding;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.iso7816four.GeneralAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.card.AbstractSmartCard;
import es.gob.jmulticard.card.icao.IcaoException;
import es.gob.jmulticard.card.icao.InvalidCanOrMrzException;
import es.gob.jmulticard.card.icao.WirelessInitializer;
import es.gob.jmulticard.card.icao.pace.PaceException;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessaging;

/** Utilidades para el establecimiento de un canal <a href="https://www.bsi.bund.de/EN/Publications/TechnicalGuidelines/TR03110/BSITR03110.html">PACE</a>
 * (Password Authenticated Connection Establishment).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PaceChannelHelperBc extends PaceChannelHelper {

	/** Tama&ntilde;o de bloque de cifrado AES. */
	public static final int BLOCK_SIZE = 16;

	/** Constructor
	 * @param ch Utilidad para operaciones criptogr&aacute;ficas. */
	public PaceChannelHelperBc(final CryptoHelper ch) {
		super(ch);
	}

	@Override
	public SecureMessaging openPaceChannel(final byte cla,
			                               final WirelessInitializer pi,
			                               final ApduConnection conn) throws ApduConnectionException,
			                                                                 IcaoException {
		if (conn == null) {
			throw new IllegalArgumentException(
				"El canal de conexion no puede ser nulo" //$NON-NLS-1$
			);
		}
		if (pi == null) {
			throw new IllegalArgumentException(
				"Es necesario proporcionar un inicializador para abrir canal PACE" //$NON-NLS-1$
			);
		}
		if (this.cryptoHelper == null) {
			throw new IllegalArgumentException(
				"El CryptoHelper no puede ser nulo" //$NON-NLS-1$
			);
		}

		if (!conn.isOpen()) {
			conn.open();
		}

		ResponseApdu res;
		CommandApdu comm;

		// 1.3.2 - Establecemos el algoritmo para PACE con el comando MSE Set:

		comm = new MseSetPaceAlgorithmApduCommand(
			cla,
			MseSetPaceAlgorithmApduCommand.PaceAlgorithmOid.PACE_ECDH_GM_AES_CBC_CMAC_128,
			pi.getPasswordType(),
			MseSetPaceAlgorithmApduCommand.PaceAlgorithmParam.BRAINPOOL_256_R1
		);
		res = conn.transmit(comm);

		if (!res.isOk()) {
			throw new PaceException(
				res.getStatusWord(),
				comm,
				"Error estableciendo el algoritmo del protocolo PACE (fallo en el MSE Set)" //$NON-NLS-1$
			);
		}

		// 1.3.3 - Primer comando General Autenticate - Get Nonce

		comm = new GeneralAuthenticateApduCommand(
			(byte) 0x10,
			new byte[] { (byte) 0x7C, (byte) 0x00 }
		);
		res = conn.transmit(comm);

		if (!res.isOk()) {
			throw new PaceException(
				res.getStatusWord(),
				comm,
				"Error solicitando el aleatorio de calculo PACE (Nonce)" //$NON-NLS-1$
			);
		}

		// Calcular nonce devuelto por la tarjeta que se empleara en los calculos
		final byte[] nonce;
		try {
			nonce = new Tlv(new Tlv(res.getData()).getValue()).getValue();
		}
		catch (final TlvException e) {
			throw new PaceException(
				"El aleatorio de calculo PACE (Nonce) obtenido (" + //$NON-NLS-1$
					HexUtils.hexify(res.getData(), true) +
						") no sigue el formato esperado", e //$NON-NLS-1$
			);
		}

		// Calcular sk = SHA-1( CAN/MRZ || 00000003 );
		// La clave son los 16 bytes MSB del hash

		final byte[] sk = new byte[16];
		try {
			System.arraycopy(
				this.cryptoHelper.digest(
					CryptoHelper.DigestAlgorithm.SHA1,
					HexUtils.concatenateByteArrays(
						pi.getBytes(),
						CAN_MRZ_PADDING
					)
				),
				0,
				sk,
				0,
				16
			);
		}
		catch (final IOException e) {
			throw new PaceException(
				"Error obteniendo el 'sk' a partir del CAN/MRZ", e //$NON-NLS-1$
			);
		}

		// Calcular secret = AES_Dec(nonce,sk);

		final byte[] secretNonce;
		try {
			secretNonce = this.cryptoHelper.aesDecrypt(
				nonce,
				new byte[0],
				sk,
				BlockMode.CBC,
				Padding.NOPADDING // Sin relleno
			);
		}
		catch (final IOException e) {
			throw new PaceException(
				"Error descifrando el 'nonce'", e //$NON-NLS-1$
			);
		}

		// 1.3.4 - Segundo comando General Autenticate - Map Nonce

		// Generamos un par de claves efimeras EC para el DH

		final X9ECParameters ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp256r1"); //$NON-NLS-1$
		final ECPoint pointG = ecdhParameters.getG();
		final Fp curve = (ECCurve.Fp) ecdhParameters.getCurve();

		// La privada del terminal se genera aleatoriamente (PrkIFDDH1)
		// La publica de la tarjeta sera devuelta por ella misma al enviar nuesra publica (pukIFDDH1)
		final Random rnd = new SecureRandom();
		rnd.setSeed(rnd.nextLong());
		final byte[] x1 = new byte[curve.getFieldSize()/8];
		rnd.nextBytes(x1);
		final BigInteger prkIFDDH1 = new BigInteger(1, x1);
		// Enviamos nuestra clave publica (pukIFDDH1 = G*PrkIFDDH1)
		final ECPoint pukIFDDH1 = pointG.multiply(prkIFDDH1);
		final byte[] pukIFDDH1UncompressedBytes = pukIFDDH1.getEncoded(false);

		Tlv tlv = new Tlv(
			TAG_DYNAMIC_AUTHENTICATION_DATA,
			new Tlv(
				TAG_GEN_AUTH_2,
				pukIFDDH1UncompressedBytes
			).getBytes()
		);

		// ... Y la enviamos a la tarjeta
		comm = new GeneralAuthenticateApduCommand(
			(byte) 0x10, // CLA
			tlv.getBytes()
		);

		res = conn.transmit(comm);

		if (!res.isOk()) {
			throw new PaceException(
				res.getStatusWord(),
				comm,
				"Error mapeando el aleatorio de calculo PACE (Nonce)" //$NON-NLS-1$
			);
		}

		// Se obtiene la clave publica de la tarjeta
		final byte[] pukIccDh1;
		try {
			pukIccDh1 = unwrapEcKey(res.getData());
		}
		catch(final TlvException e) {
			throw new PaceException(
				"Error obteniendo la clave efimera EC publica de la tarjeta", e //$NON-NLS-1$
			);
		}

		// calcular blinding point H = PrkIFDDH1 * PukICCDH1
		final ECPoint y1FromG = byteArrayToECPoint(pukIccDh1, curve);

		//Calculamos el punto H secreto
		final ECPoint sharedSecretH = y1FromG.multiply(prkIFDDH1);

		//Se calcula el nuevo punto G' = nonce*G + H
		final BigInteger ms = new BigInteger(1, secretNonce);
		final ECPoint gTemp = pointG.multiply(ms);
		final ECPoint newPointG = gTemp.add(sharedSecretH);


		// 1.3.5 Tercer comando General Authenticate

		//Se calcula la coordenada X de G' y generamos con la tarjeta un nuevo acuerdo de claves
		// La privada del terminal se genera aleatoriamente (PrkIFDDH2)
		// La publica de la tarjeta sera devuelta por ella misma al enviar nuesra publica (pukIFDDH2)
		final byte[] x2 = new byte[curve.getFieldSize()/8];
		rnd.setSeed(rnd.nextLong());
		rnd.nextBytes(x2);
		final BigInteger prkIFDDH2 = new BigInteger(1, x2);

		// Enviamos nuestra clave publica (pukIFDDH2 = G'*PrkIFDDH2)
		final ECPoint pukIFDDH2 = newPointG.multiply(prkIFDDH2);

		// ... La metemos en un TLV de autenticacion ...
		tlv = new Tlv(
			TAG_DYNAMIC_AUTHENTICATION_DATA,
			new Tlv(
				TAG_GEN_AUTH_3,
				pukIFDDH2.getEncoded(false)
			).getBytes()
		);


		comm = new GeneralAuthenticateApduCommand(
			(byte) 0x10, // CLA
			tlv.getBytes()
		);

		res = conn.transmit(comm);

		// Se obtiene la clave publica de la tarjeta (pukIccDh2) que es la coordenada Y del nuevo Punto G'
		final byte[] pukIccDh2;
		try {
			pukIccDh2 = unwrapEcKey(res.getData());
		}
		catch(final TlvException e) {
			throw new PaceException(
				"Error obteniendo la clave efimera EC publica de la tarjeta", e //$NON-NLS-1$
			);
		}

		final ECPoint y2FromNewG = byteArrayToECPoint(pukIccDh2, curve);

		// Se calcula el secreto k = PukICCDH2 * PrkIFDDH2
		final ECPoint.Fp sharedSecretK = (ECPoint.Fp) y2FromNewG.multiply(prkIFDDH2);
		final byte[] secretK = bigIntToByteArray(sharedSecretK.normalize().getXCoord().toBigInteger());

		// 1.3.6 Cuarto comando General Authenticate
		// Se validan las claves de sesion generadas en el paso anterior,
		// por medio de un MAC que calcula el terminal y comprueba la tarjeta,
		// la cual devolvera un segundo MAC.

		// Calcular kenc = SHA-1( k || 00000001 );
		final byte[] kenc = new byte[16];
		try {
			System.arraycopy(
				this.cryptoHelper.digest(
					CryptoHelper.DigestAlgorithm.SHA1,
					HexUtils.concatenateByteArrays(
						secretK,
						KENC_PADDING
					)
				),
				0,
				kenc,
				0,
				16
			);
		}
		catch (final IOException e) {
			throw new PaceException(
				"Error obteniendo el 'kenc' a partir del CAN/MRZ", e //$NON-NLS-1$
			);
		}

		// Calcular kmac = SHA-1( k || 00000002 );
		final byte[] kmac = new byte[16];
		try {
			System.arraycopy(
				this.cryptoHelper.digest(
					CryptoHelper.DigestAlgorithm.SHA1,
					HexUtils.concatenateByteArrays(
						secretK,
						KMAC_PADDING
					)
				),
				0,
				kmac,
				0,
				16
			);
		}
		catch (final IOException e) {
			throw new PaceException(
				"Error obteniendo el 'kmac' a partir del CAN", e //$NON-NLS-1$
			);
		}

		// Elimina el byte '04' del inicio que es el indicador de punto descomprimido
		final byte[] pukIccDh2Descompressed = new byte[pukIccDh2.length-1];
		System.arraycopy(pukIccDh2, 1, pukIccDh2Descompressed, 0, pukIccDh2.length-1);

		// Se calcula el Mac del terminal: data = '7f494F06' + oid + '864104' + PukICCDH2;
		final byte[] data = HexUtils.concatenateByteArrays(
			MAC_PADDING,
			HexUtils.concatenateByteArrays(
				MseSetPaceAlgorithmApduCommand.PaceAlgorithmOid.PACE_ECDH_GM_AES_CBC_CMAC_128.getBytes(),
				HexUtils.concatenateByteArrays(
					MAC2_PADDING,
					pukIccDh2Descompressed
				)
			)
		);

		final byte[] mac8bytes;
		try {
			mac8bytes = this.cryptoHelper.doAesCmac(
				data,
				kmac
			);
		}
		catch (final InvalidKeyException | NoSuchAlgorithmException e) {
			throw new PaceException(
				"Error descifrando el 'nonce'", e //$NON-NLS-1$
			);
		}

		// ... La metemos en un TLV de autenticacion ...
		tlv = new Tlv(
			TAG_DYNAMIC_AUTHENTICATION_DATA,
			new Tlv(
				TAG_GEN_AUTH_4,
				mac8bytes
			).getBytes()
		);

		// Se envia el comando General Authenticate y se recupera el MAC devuelto por la tarjeta.
		comm = new GeneralAuthenticateApduCommand(
			(byte) 0x00,
			tlv.getBytes()
		);

		res = conn.transmit(comm);

		// Se obtiene un MAC con respuesta 90-00 indicando que se ha establecido el canal correctamente
		if (!res.isOk()) {
			throw new InvalidCanOrMrzException(
				res.getStatusWord(),
				comm,
				"Error estableciendo el algoritmo del protocolo PACE (fallo en el General Authenticate)" //$NON-NLS-1$
			);
		}

		// Se inicializa el contador de secuencia a ceros
		final byte[] ssc = new byte[16];
		Arrays.fill(ssc, (byte)0);

		if (AbstractSmartCard.DEBUG) {
			LOGGER.info("Canal Pace abierto"); //$NON-NLS-1$
			LOGGER.info(
				"\nKenc: " + HexUtils.hexify(kenc, true) + //$NON-NLS-1$
				"\nKmac: " + HexUtils.hexify(kmac, true) + //$NON-NLS-1$
				"\nSsc: " + HexUtils.hexify(ssc, true) //$NON-NLS-1$
			);
		}

		return new SecureMessaging(
			kenc,
			kmac,
			new byte[BLOCK_SIZE], // El tamano de bloque AES es el SSC inicial
			this.cryptoHelper
		);
	}

	private static ECPoint byteArrayToECPoint(final byte[] value, final ECCurve.Fp curve) {
		final byte[] x = new byte[(value.length - 1) / 2];
		final byte[] y = new byte[(value.length - 1) / 2];
		if (value[0] != (byte) 0x04) {
			throw new IllegalArgumentException("No se ha encontrado un punto no comprimido"); //$NON-NLS-1$
		}
		System.arraycopy(value, 1, x, 0, (value.length - 1) / 2);
		System.arraycopy(value, 1 + (value.length - 1) / 2, y, 0, (value.length - 1) / 2);
		final ECFieldElement.Fp xE = (ECFieldElement.Fp) curve.fromBigInteger(new BigInteger(1, x));
		final ECFieldElement.Fp yE = (ECFieldElement.Fp) curve.fromBigInteger(new BigInteger(1, y));

		return curve.createPoint(xE.toBigInteger(), yE.toBigInteger());
	}

}