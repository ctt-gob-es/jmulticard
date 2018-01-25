package es.gob.jmulticard.card.pace;

import java.io.IOException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;

/**
 * Valor MRZ para inicializacion de un canal PACE.
 * 
 *  @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s.
 * @author Ignacio Mar&iacute;n 
*/

public final class PaceInitializerMrz extends PaceInitializer {

	private byte[] k;

	/**
	 * Contiene los datos necesarios de la MRZ para la generaci&oacute;n de la clave.
	 * <br></br>
	 * Los datos contenidos son:  numero del documento,  fecha de nacimiento,  fecha de expiraci&oacute;n y los digitos de comprobaci&oacute;n de cada uno de ellos. 
	 *
	 */
	private static class MrzInfoData {
		private String number;
		private String birth;
		private String expiry;

		private byte[] numberCheck;
		private byte[] birthCheck;
		private byte[] expiryCheck;
	}

	/**
	 * Construye una MRZ para inicialización de un canal PACE.
	 * 
	 * @param mrz
	 *            MRZ.
	 * @throws IOException
	 */
	private PaceInitializerMrz(final byte[] mrz) throws MalformedMrzException {
		super();
		this.k = mrz;
	}

	@Override
	public String toString() {
		return null;
	}

	@Override
	public byte[] getBytes() {
		return k;
	}

	@Override
	public PacePasswordType getPasswordType() {
		return MseSetPaceAlgorithmApduCommand.PacePasswordType.MRZ;
	}
	
	/**
	 * Genera el inicializador necesario para la clave partiendo de la MRZ.
	 *
	 * @param mrz
	 * @return PaceInitializerMrz
	 * @throws MalformedMrzException
	 */
	
	public static PaceInitializerMrz deriveMrz(String mrz) throws MalformedMrzException {
		if (mrz == null || mrz.isEmpty()) {
			throw new IllegalArgumentException("El valor no puede ser nulo ni vacio" //$NON-NLS-1$
			);
		}
		PaceInitializerMrz result;
		try {
			byte[] k = getMrzPswd(mrz);
			result = new PaceInitializerMrz(k);
		} catch (IOException ex) {
			throw new MalformedMrzException("MRZ no tiene formato valido");
		}
		return result;
	}

	/**
	 * Calcula el valor de inicializaci&oacute;n partiendo de una MRZ. <br>
	 * <br>
	 * Siguiendo la especificación ICAO 9303:<br>
	 * <code>KDF&pi;(&pi;) = KDF(f(&pi;),3)</code><br>
	 * <code>K= f(&pi;) = SHA-1(Serial Number || Date of Birth || Date of Expiry)</code><br>
	 * En este método se genera el valor de K que deberá posteriormente ser
	 * pasado como parámetro de la función KDF(K,3) para generar la contraseña.
	 * 
	 * @param mrz
	 *            String con la mrz completa
	 * @return K
	 * @throws IOException
	 */
	private static byte[] getMrzPswd(String mrz) throws IOException {

		final MrzInfoData mrzData = parseMrzInfo(mrz);
		byte[] numberBytes = mrzData.number.getBytes();
		byte[] birthBytes = mrzData.birth.getBytes();
		byte[] expiryBytes = mrzData.expiry.getBytes();

		byte[] concatenation = HexUtils.concatenateByteArrays(numberBytes, mrzData.numberCheck, birthBytes,
				mrzData.birthCheck, expiryBytes, mrzData.expiryCheck);

		CryptoHelper cryptoHelper = new JseCryptoHelper();

		byte[] k = cryptoHelper.digest(CryptoHelper.DigestAlgorithm.SHA1, concatenation);

		return k;
	}

	/**
	 * Parsea la MRZ y extrae la informaci&oacute;n necesaria para la deriaci&oacute;n de la clave.
	 * @param mrz
	 * @return MrzInfoData 
	 */
	private static MrzInfoData parseMrzInfo(String mrz) {
		final MrzInfoData data = new MrzInfoData();
		MrzInfo mrzInfo = new MrzInfo();
		mrzInfo.setMrz(mrz);
		data.number = mrzInfo.getDocumentNumber();
		data.birth = mrzInfo.getDateOfBirth();
		data.expiry = mrzInfo.getDateOfExpiry();

		data.numberCheck = new byte[] { (byte) MrzInfo.checkDigit(data.number) };
		data.birthCheck = new byte[] { (byte) MrzInfo.checkDigit(data.birth) };
		data.expiryCheck = new byte[] { (byte) MrzInfo.checkDigit(data.expiry) };

		return data;
	}

	

}
