package es.gob.jmulticard.card.pace;

import java.io.IOException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;

/** Valor MRZ para inicializaci&oacute;n de un canal PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Ignacio Mar&iacute;n. */
public final class PaceInitializerMrz extends PaceInitializer {

	private final byte[] k;

	/** Contiene los datos necesarios de la MRZ para la generaci&oacute;n de la clave.
	 * Los datos contenidos son: n&uacute;mero del documento, fecha de nacimiento,
	 * fecha de expiraci&oacute;n y los digitos de comprobaci&oacute;n de cada uno de ellos. */
	private static final class MrzInfoData {

		MrzInfoData() {
			// Vacio
		}

		private String number;
		String getNumber() {
			return this.number;
		}
		void setNumber(final String n) {
			this.number = n;
		}

		private String birth;
		String getBirth() {
			return this.birth;
		}
		void setBirth(final String b) {
			this.birth = b;
		}

		private String expiry;
		String getExpiry() {
			return this.expiry;
		}
		void setExpiry(final String e) {
			this.expiry = e;
		}

		private byte[] numberCheck;
		byte[] getNumberCheck() {
			return this.numberCheck != null ? this.numberCheck.clone() : null;
		}
		void setNumberCheck(final byte[] nc) {
			this.numberCheck = nc != null ? nc.clone() : null;
		}

		private byte[] birthCheck;
		byte[] getBirthCheck() {
			return this.birthCheck != null ? this.birthCheck.clone() : null;
		}
		void setBirthCheck(final byte[] nc) {
			this.birthCheck = nc != null ? nc.clone() : null;
		}

		private byte[] expiryCheck;
		byte[] getExpiryCheck() {
			return this.expiryCheck != null ? this.expiryCheck.clone() : null;
		}
		void setExpiryCheck(final byte[] nc) {
			this.expiryCheck = nc != null ? nc.clone() : null;
		}
	}

	/** Construye una MRZ para inicializaci&oacute;n de un canal PACE.
	 * @param mrz MRZ. */
	private PaceInitializerMrz(final byte[] mrz) {
		super();
		this.k = mrz;
	}

	@Override
	public String toString() {
		return null;
	}

	@Override
	public byte[] getBytes() {
		return this.k;
	}

	@Override
	public PacePasswordType getPasswordType() {
		return MseSetPaceAlgorithmApduCommand.PacePasswordType.MRZ;
	}

	/** Genera el inicializador necesario para la clave partiendo de la MRZ.
	 * @param mrz MRZ.
	 * @return Inicializador necesario para la clave.
	 * @throws MalformedMrzException Si la MRZ est&aacute; mal formada. */
	public static PaceInitializerMrz deriveMrz(final String mrz) throws MalformedMrzException {
		if (mrz == null || mrz.isEmpty()) {
			throw new IllegalArgumentException(
				"El valor no puede ser nulo ni vacio" //$NON-NLS-1$
			);
		}
		try {
			final byte[] k = getMrzPswd(mrz);
			return new PaceInitializerMrz(k);
		}
		catch (final IOException ex) {
			throw new MalformedMrzException("La MRZ no tiene formato valido: " + ex, ex); //$NON-NLS-1$
		}
	}

	/** Calcula el valor de inicializaci&oacute;n partiendo de una MRZ.
	 * Siguiendo la especificaci&oacute;n ICAO 9303:<br>
	 * <code>KDF&pi;(&pi;) = KDF(f(&pi;),3)</code><br>
	 * <code>K= f(&pi;) = SHA-1(Serial Number || Date of Birth || Date of Expiry)</code><br>
	 * En este m&eacute;todo se genera el valor de K que deber&aacute; posteriormente ser
	 * pasado como par&aacute;metro de la funci&oacute;n KDF(K,3) para generar la contrase&ntilde;a.
	 * @param mrz MRZ completa.
	 * @return K Valor de inicializaci&oacute;n.
	 * @throws IOException Si no se puede obtener el valor. */
	private static byte[] getMrzPswd(final String mrz) throws IOException {

		final MrzInfoData mrzData = parseMrzInfo(mrz);
		final byte[] numberBytes = mrzData.getNumber().getBytes();
		final byte[] birthBytes  = mrzData.getBirth().getBytes();
		final byte[] expiryBytes = mrzData.getExpiry().getBytes();

		final byte[] concatenation = HexUtils.concatenateByteArrays(
			numberBytes,
			mrzData.getNumberCheck(),
			birthBytes,
			mrzData.getBirthCheck(),
			expiryBytes,
			mrzData.getExpiryCheck()
		);

		final CryptoHelper cryptoHelper = new JseCryptoHelper();
		return cryptoHelper.digest(CryptoHelper.DigestAlgorithm.SHA1, concatenation);
	}

	/** Analiza la MRZ y extrae la informaci&oacute;n necesaria para la derivaci&oacute;n de la clave.
	 * @param mrz MRZ
	 * @return Informaci&oacute;n necesaria para la derivaci&oacute;n de la clave. */
	private static MrzInfoData parseMrzInfo(final String mrz) {
		final MrzInfoData data = new MrzInfoData();
		final MrzInfo mrzInfo = new MrzInfo();
		mrzInfo.setMrz(mrz);
		data.setNumber(mrzInfo.getDocumentNumber());
		data.setBirth(mrzInfo.getDateOfBirth());
		data.setExpiry(mrzInfo.getDateOfExpiry());

		data.setNumberCheck(
			new byte[] { (byte) MrzInfo.checkDigit(data.getNumber()) }
		);
		data.setBirthCheck(
			new byte[] { (byte) MrzInfo.checkDigit(data.getBirth()) }
		);
		data.setExpiryCheck(
			new byte[] { (byte) MrzInfo.checkDigit(data.getExpiry()) }
		);

		return data;
	}

}
