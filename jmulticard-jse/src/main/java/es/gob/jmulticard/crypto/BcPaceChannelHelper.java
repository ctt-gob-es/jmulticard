package es.gob.jmulticard.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.CryptoHelper.BlockMode;
import es.gob.jmulticard.CryptoHelper.PaceChannelHelper;
import es.gob.jmulticard.CryptoHelper.Padding;
import es.gob.jmulticard.DigestAlgorithm;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JmcLogger;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.iso7816four.pace.GeneralAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.PaceChat;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.icao.CardAccess;
import es.gob.jmulticard.card.icao.IcaoException;
import es.gob.jmulticard.card.icao.InvalidCanOrMrzException;
import es.gob.jmulticard.card.icao.WirelessInitializer;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.pace.PaceException;
import es.gob.jmulticard.connection.pace.SecureMessaging;

/** Utilidades para el establecimiento de un canal PACE (Password Authenticated Connection Establishment).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class BcPaceChannelHelper extends PaceChannelHelper {

	private final CardAccess cardAccess;
	private final PaceChat paceChat;

	/** Constructor.
	 * @param ch Utilidad para operaciones criptogr&aacute;ficas.
	 * @param crdAccess CardAccess de la tarjeta.
	 * @param paceCht PACE CHAT a usar en el establecimiento del canal PACE. */
	public BcPaceChannelHelper(final CryptoHelper ch, final CardAccess crdAccess, final PaceChat paceCht) {
		super(ch);
		cardAccess = crdAccess;
		paceChat = paceCht;
	}

	@Override
	public SecureMessaging openPaceChannel(final byte cla,
			                               final WirelessInitializer pi,
			                               final ApduConnection conn) throws ApduConnectionException,
			                                                                 IcaoException {
		if (conn == null) {
			throw new IllegalArgumentException("El canal de conexion no puede ser nulo"); //$NON-NLS-1$
		}
		if (pi == null) {
			throw new IllegalArgumentException("Es necesario proporcionar un inicializador para abrir canal PACE"); //$NON-NLS-1$
		}
		if (cryptoHelper == null) {
			throw new IllegalArgumentException("El CryptoHelper no puede ser nulo"); //$NON-NLS-1$
		}

		if (!conn.isOpen()) {
			conn.open();
		}

		// Sacamos del CardAccess la algoritmia a usar
		final CardAccess.PaceAlgorithm paceAlgorithm = cardAccess.getPaceAlgorithm();
		final CardAccess.PaceAlgorithmParam paceAlgorithmParam = cardAccess.getPaceAlgorithmParam();

		// 1.3.2 - Establecemos el algoritmo para PACE con el comando MSE Set:

		CommandApdu comm = new MseSetPaceAlgorithmApduCommand(
			cla,
			paceAlgorithm,
			pi.getPasswordType(), // CAN, MRZ, PIN o PUK
			paceChat,
			paceAlgorithmParam
		);
		ResponseApdu res = conn.transmit(comm);
		if (!res.isOk()) {
			throw new PaceException(
				res.getStatusWord(),
				comm,
				"Error estableciendo el algoritmo del protocolo PACE (fallo en el MSE Set)" //$NON-NLS-1$
			);
		}

		JmcLogger.info(
			BcPaceChannelHelper.class.getName(),
			"openPaceChannel", //$NON-NLS-1$
			"Establecido el algoritmo para PACE con el comando MSE Set" //$NON-NLS-1$
		);

		// 1.3.3 - Primer comando General Autenticate - Get Nonce

		comm = new GeneralAuthenticateApduCommand((byte) 0x10, new GeneralAuthenticateApduCommand.DataEncryptedNonce());
		res = conn.transmit(comm);
		if (!res.isOk()) {
			throw new PaceException(res.getStatusWord(), comm, "Error solicitando el aleatorio de calculo PACE (nonce)"); //$NON-NLS-1$
		}

		JmcLogger.info(
			BcPaceChannelHelper.class.getName(),
			"openPaceChannel", //$NON-NLS-1$
			"Solicitado el aleatorio de calculo PACE (Nonce) con el primer comando General Autenticate" //$NON-NLS-1$
		);

		// Calcular 'nonce' devuelto por la tarjeta que se empleara en los calculos
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

		// 1.3.4 - Segundo comando General Autenticate - Map Nonce

		// Generamos un par de claves efimeras EC para el DH

		final X9ECParameters ecdhParameters = TeleTrusTNamedCurves.getByName(paceAlgorithmParam.getCurveName());
		final ECPoint pointG = ecdhParameters.getG();
		final Fp curve = (ECCurve.Fp) ecdhParameters.getCurve();

		// La privada del terminal se genera aleatoriamente (PrkIFDDH1)
		// La publica de la tarjeta sera devuelta por ella misma al enviar nuestra publica (pukIFDDH1)
		final Random rnd = new SecureRandom();
		final byte[] x1 = new byte[curve.getFieldSize()/8];
		rnd.nextBytes(x1);
		final BigInteger prkIFDDH1 = new BigInteger(1, x1);

		// Obtenemos la clave publica (pukIFDDH1 = G*PrkIFDDH1)
		final ECPoint pukIFDDH1 = pointG.multiply(prkIFDDH1);
		final byte[] pukIFDDH1UncompressedBytes = pukIFDDH1.getEncoded(false);

		// Y enviamos nuestra clave publica a la tarjeta
		comm = new GeneralAuthenticateApduCommand(
			(byte) 0x10,
			new GeneralAuthenticateApduCommand.DataMapNonce(pukIFDDH1UncompressedBytes)
		);
		res = conn.transmit(comm);
		if (!res.isOk()) {
			throw new PaceException(res.getStatusWord(), comm, "Error mapeando el aleatorio de calculo PACE (nonce)"); //$NON-NLS-1$
		}

		JmcLogger.info(
			BcPaceChannelHelper.class.getName(),
			"openPaceChannel", //$NON-NLS-1$
			"Mapeado el aleatorio de calculo PACE (Nonce) con el segundo comando General Autenticate" //$NON-NLS-1$
		);

		// Se obtiene la clave publica de la tarjeta
		final byte[] pukIccDh1;
		try {
			pukIccDh1 = unwrapEcKey(res.getData());
		}
		catch(final TlvException e) {
			throw new PaceException("Error obteniendo la clave efimera EC publica de la tarjeta", e); //$NON-NLS-1$
		}

		// Calculamos el punto H secreto: H = PrkIFDDH1 * PukICCDH1
		final ECPoint sharedSecretH = byteArrayToECPoint(pukIccDh1, curve).multiply(prkIFDDH1);

		// Se calcula el nuevo punto G' = nonce*G + H
		final BigInteger ms = new BigInteger(
			1,
			getSecretNonce(
				pi,
				nonce,
				paceAlgorithm.getKeyLength(),
				cardAccess.getPaceDigestAlgorithm()
			)
		);
		final ECPoint gTemp = pointG.multiply(ms);
		final ECPoint newPointG = gTemp.add(sharedSecretH);


		// 1.3.5 Tercer comando General Authenticate

		// Se calcula la coordenada X de G' y generamos con la tarjeta un nuevo acuerdo de claves.
		// La privada del terminal se genera aleatoriamente (PrkIFDDH2).
		// La publica de la tarjeta sera devuelta por ella misma al enviar nuestra publica (pukIFDDH2).
		final byte[] x2 = new byte[curve.getFieldSize()/8];
		rnd.setSeed(rnd.nextLong());
		rnd.nextBytes(x2);
		final BigInteger prkIFDDH2 = new BigInteger(1, x2);

		// Enviamos nuestra clave publica (pukIFDDH2 = G'*PrkIFDDH2)
		final ECPoint pukIFDDH2 = newPointG.multiply(prkIFDDH2);
		final byte[] pukIFDDH2UncompressedBytes = pukIFDDH2.getEncoded(false);

		// Creamos la APDU y la enviamos
		comm = new GeneralAuthenticateApduCommand(
			(byte) 0x10,
			new GeneralAuthenticateApduCommand.DataPerformKeyAgreement(pukIFDDH2UncompressedBytes)
		);
		res = conn.transmit(comm);

		if (!res.isOk()) {
			throw new PaceException(res.getStatusWord(), comm, "Error en el tercer comando General Authenticate"); //$NON-NLS-1$
		}

		// Se obtiene la clave publica de la tarjeta (pukIccDh2) que es la coordenada Y del nuevo Punto G'
		final byte[] pukIccDh2;
		try {
			pukIccDh2 = unwrapEcKey(res.getData());
		}
		catch(final TlvException e) {
			throw new PaceException("Error obteniendo la clave efimera EC publica de la tarjeta", e); //$NON-NLS-1$
		}
		final ECPoint y2FromNewG = byteArrayToECPoint(pukIccDh2, curve);

		// Se calcula el secreto k = PukICCDH2 * PrkIFDDH2
		final ECPoint.Fp sharedSecretK = (ECPoint.Fp) y2FromNewG.multiply(prkIFDDH2);
		final byte[] secretK = bigIntToByteArray(sharedSecretK.normalize().getXCoord().toBigInteger());

		JmcLogger.info(
			BcPaceChannelHelper.class.getName(),
			"openPaceChannel", //$NON-NLS-1$
			"Acordadas claves de canal con el tercer comando General Authenticate" //$NON-NLS-1$
		);

		// 1.3.6 Cuarto comando General Authenticate
		// Se validan las claves de sesion generadas en el paso anterior por medio de un MAC
		// que calcula el terminal y comprueba la tarjeta, la cual devolvera un segundo MAC.

		// Calcular kenc = n octetos MSB del resultado de SHA-x(k || 00000001); [n nos lo da el tamano de clave del algoritmo PACE]
		final byte[] kenc;
		try {
			kenc = padAndDigest(secretK, KENC_PADDING, cardAccess.getPaceDigestAlgorithm(), paceAlgorithm.getKeyLength());
		}
		catch (final IOException e) {
			throw new PaceException("Error obteniendo el 'kenc' a partir del CAN/MRZ/PIN", e); //$NON-NLS-1$
		}

		// Calcular kmac = SHA-x(k || 00000002);
		final byte[] kmac;
		try {
			kmac = padAndDigest(secretK, KMAC_PADDING, cardAccess.getPaceDigestAlgorithm(), paceAlgorithm.getKeyLength());
		}
		catch (final IOException e) {
			throw new PaceException("Error obteniendo el 'kmac' a partir del CAN/MRZ/PIN", e); //$NON-NLS-1$
		}

		// Elimina el byte '04' del inicio que es el indicador de punto descomprimido
		final byte[] pukIccDh2Descompressed = new byte[pukIccDh2.length-1];
		System.arraycopy(pukIccDh2, 1, pukIccDh2Descompressed, 0, pukIccDh2.length-1);

		// Se calcula el Mac del terminal: data = '7f494F06' + oid + '864104' + PukICCDH2;
		// Cuidado, el 'oid' debe tener el '0a' de longitud del TLV antes (ya se incluye desde CardAccess.PaceAlgorithm).
		final byte[] data = HexUtils.concatenateByteArrays(
			MAC_PADDING_PRE,
			HexUtils.concatenateByteArrays(
				paceAlgorithm.getBytes(),
				HexUtils.concatenateByteArrays(MAC2_PADDING_POST, pukIccDh2Descompressed)
			)
		);

		final byte[] mac8bytes;
		try {
			mac8bytes = cryptoHelper.doAesCmac(data, kmac);
		}
		catch (final InvalidKeyException | NoSuchAlgorithmException e) {
			throw new PaceException("Error descifrando el 'nonce'", e); //$NON-NLS-1$
		}

		// Se envia el comando General Authenticate y se recupera el MAC devuelto por la tarjeta.
		comm = new GeneralAuthenticateApduCommand(
			(byte) 0x00,
			new GeneralAuthenticateApduCommand.DataMutualAuthentication(mac8bytes)
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
		final byte[] ssc = new byte[paceAlgorithm.getKeyLength() / 8]; // El tamano de bloque AES es el tamano del SSC
		Arrays.fill(ssc, (byte)0);

		JmcLogger.info(BcPaceChannelHelper.class.getName(), "openPaceChannel", "Canal Pace abierto"); //$NON-NLS-1$ //$NON-NLS-2$
		JmcLogger.debug(
			BcPaceChannelHelper.class.getName(),
			"openPaceChannel", //$NON-NLS-1$
			"Claves de canal Pace:" + //$NON-NLS-1$
				"\n  Kenc: " + HexUtils.hexify(kenc, true) + //$NON-NLS-1$
				"\n  Kmac: " + HexUtils.hexify(kmac, true) + //$NON-NLS-1$
				"\n  Ssc: " + HexUtils.hexify(ssc, true) //$NON-NLS-1$
		);

		return new SecureMessaging(
			kenc,
			kmac,
			new byte[paceAlgorithm.getKeyLength() / 8], // El tamano de bloque AES es el SSC inicial
			cryptoHelper
		);
	}

	protected byte[] padAndDigest(final byte[] input,
			                      final byte[] padding,
			                      final DigestAlgorithm digestAlgorithm,
			                      final int resultBitLength) throws IOException {
		final byte[] dest = new byte[resultBitLength / 8];
		System.arraycopy(
			cryptoHelper.digest(
				digestAlgorithm,
				HexUtils.concatenateByteArrays(input, padding)
			),
			0,                  // Source position
			dest,               // Destination
			0,                  // Destination position
			resultBitLength / 8 // Length (en bytes)
		);
		return dest;
	}

	protected byte[] getSecretNonce(final WirelessInitializer pi,
			                        final byte[] nonce,
			                        final int aesKeyLength,
			                        final DigestAlgorithm digestAlgorithm) throws PaceException {

		// Calcular sk = SHA-x(CAN/MRZ/PIN/PUK || 00000003)
		// La clave AES son los MSB del hash (16 bytes en AES-128, 24 en AES-192, etc.)
		final byte[] sk;
		try {
			sk = padAndDigest(pi.getBytes(), CAN_MRZ_PADDING, digestAlgorithm, aesKeyLength);
		}
		catch (final IOException e) {
			throw new PaceException("Error obteniendo el 'sk' a partir del " + pi.getPasswordType(), e); //$NON-NLS-1$
		}

		// Calcular secret = AES_Dec(nonce, sk);
		try {
			return cryptoHelper.aesDecrypt(
				nonce,
				new byte[0], // Vector de inicializacion vacio
				sk,
				BlockMode.CBC,
				Padding.NOPADDING // Sin relleno
			);
		}
		catch (final IOException e) {
			throw new PaceException("Error descifrando el 'nonce'", e); //$NON-NLS-1$
		}
	}

	protected static ECPoint byteArrayToECPoint(final byte[] value, final ECCurve.Fp curve) {
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