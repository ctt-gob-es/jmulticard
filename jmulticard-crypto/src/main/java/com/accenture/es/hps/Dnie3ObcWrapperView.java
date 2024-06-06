package com.accenture.es.hps;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;

import org.bouncycastle.util.encoders.Base64;

import es.gob.jmulticard.JmcLogger;
import es.gob.jmulticard.asn1.icao.OptionalDetails;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.card.icao.Gender;
import es.gob.jmulticard.card.icao.InvalidCanOrMrzException;
import es.gob.jmulticard.card.icao.MrtdLds1;
import es.gob.jmulticard.card.icao.Mrz;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.crypto.BcCryptoHelper;

/** Envoltura a las funcionalidades de firma del DNIe v3 que permite operar
 * intercambiando JSON en vez de tratar objetos y excepciones Java.
 * Esto permite una operaci&oacute;n mucho m&aacute;s limpia cuando se usa
 * c&oacute;digo traducido de Java a Objective-C (J2Obc).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Dnie3ObcWrapperView {

	private MrtdLds1 dnie3;

	/** Inicializa la conexi&oacute;n con un DNIe y devuelve los datos que se
	 * pueden encontrar impresos tanto en anverso como en reverso, incluyendo fotos.
	 * @param can CAN.
	 * @return Un JSON con los datos o con un error seg&uacute;n esta codificaci&oacute;n:
	 * <dl>
	 *  <dt>00</dt><dd>La tarjeta detectada no es un DNIe.</dd>
	 *  <dt>01</dt><dd>El DNIe tiene su memoria vol&aacute;til borrada.</dd>
	 *  <dt>02</dt><dd>Error gen&eacute;rico en la conexi&oacute;n.</dd>
	 *  <dt>03</dt><dd>Error gen&eacute;rico.</dd>
	 *  <dt>04</dt><dd>El DNIe detectado no es compatible con la biblioteca.</dd>
	 *  <dt>05</dt><dd>El DNIe tiene el PIN bloqueado.</dd>
	 *  <dt>06</dt><dd>Error gen&eacute;rico en el DNIe.</dd>
	 *  <dt>12</dt><dd>Error leyendo los datos del titular del DNIe</dd>
	 *  <dt>14</dt><dd>CAN incorrecto.</dd>
	 * </dl>
	 */
	public String getDnieVisualData(final String can) {
		final MrtdLds1 dnie;
		try {
			dnie = DnieFactory.getEmrtdNfc(
				new IosNfcConnection(),
				new BcCryptoHelper(),
				new DnieCallbackHandler(can, (char[]) null)
			);
		}
		catch (final ApduConnectionException e) {
			if (e.getCause() instanceof InvalidCanOrMrzException) {
				return buildErrorJson("14", e); //$NON-NLS-1$
			}
			return buildErrorJson("02", e); //$NON-NLS-1$
		}
		catch (final Exception e) {
			return buildErrorJson("03", e); //$NON-NLS-1$
		}
		if (!(dnie instanceof Dnie3)) {
			return buildErrorJson("04", null); //$NON-NLS-1$
		}

		dnie3 = dnie;

		// Estos dos DG estan presentes en todos los eMRTD
		final Mrz mrz;
		final String SubjectPhotoAsJpeg2kBase64;
		final String birthDate;
		final String expirationDate;
		final SimpleDateFormat dateFormat = new SimpleDateFormat("dd MM yyyy"); //$NON-NLS-1$
		try {
			mrz = dnie3.getDg1();
			SubjectPhotoAsJpeg2kBase64 = Base64.toBase64String(dnie3.getDg2().getSubjectPhotoAsJpeg2k());
			birthDate = dateFormat.format(mrz.getDateOfBirth());
			expirationDate = dateFormat.format(mrz.getDateOfExpiry());

		}
		catch (final Exception e) {
			return buildErrorJson("12", e); //$NON-NLS-1$
		}

		// DG opcionales
		String SubjectSignatureAsJpeg2kBase64 = ""; //$NON-NLS-1$
		OptionalDetails dg13 = null;
		try {
			dg13 = dnie3.getDg13();
			SubjectSignatureAsJpeg2kBase64 = Base64.toBase64String(dnie3.getDg7().getSubjectSignaturePhotoAsJpeg2k());
		}
		catch (final Exception e) {
			JmcLogger.severe("No se han encontrado los DG opcionales del eMRTD: " + e); //$NON-NLS-1$
		}

		return buildDniVisualDataJson(
			mrz.getName(),
			mrz.getSurname(),
			Gender.MALE.equals(mrz.getSex()) ? "M" : "F", //$NON-NLS-1$ //$NON-NLS-2$
			mrz.getNationality(),
			birthDate,
			dg13 != null ? dg13.getSupportNumber() : "", //$NON-NLS-1$
			expirationDate,
			mrz.getDocumentNumber(),
			SubjectPhotoAsJpeg2kBase64,
			SubjectSignatureAsJpeg2kBase64,
			dg13 != null ? dg13.getAddress() + "\\n" + dg13.getCity() + "\\n" + (OptionalDetails.SPAIN.equals(dg13.getCountry()) ? dg13.getProvince() : dg13.getCountry()) : "", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			dg13 != null ? dg13.getBirthCity() + "\\n" + (OptionalDetails.SPAIN.equals(dg13.getBirthCountry()) ? dg13.getBirthProvince() : dg13.getBirthCity()) : "", //$NON-NLS-1$ //$NON-NLS-2$
			dg13 != null ? dg13.getParentsNames() : "", //$NON-NLS-1$
			"00000AAAA", // Equipo //$NON-NLS-1$
			mrz.toString()
		);
	}

	private static String buildErrorJson(final String code,
			                             final String info,
			                             final Throwable e) {
		final String sStackTrace;
		if (e != null) {
			final StringWriter sw = new StringWriter();
			final PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			sStackTrace = sw.toString()
				.replace("\n", "\\n") //$NON-NLS-1$ //$NON-NLS-2$
				.replace("\"", "'") //$NON-NLS-1$ //$NON-NLS-2$
				.replace("\r", "") //$NON-NLS-1$ //$NON-NLS-2$
				.replace("\t", "   "); //$NON-NLS-1$ //$NON-NLS-2$
		}
		else {
			sStackTrace = ""; //$NON-NLS-1$
		}
		return "{\n \"code\": " + code + ",\n \"info\": \"" + info + "\",\n \"stacktrace\": \"" + sStackTrace + "\"\n}"; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
	}

	private static String buildErrorJson(final String code,
                                         final Throwable e) {
		return buildErrorJson(code, "", e); //$NON-NLS-1$
	}

	private static String buildDniVisualDataJson(final String name,
                                                 final String surname,
                                                 final String sex,
                                                 final String nationality,
                                                 final String birthDate,
                                                 final String supportNo,
                                                 final String validity,
                                                 final String id,
                                                 final String photo,
                                                 final String signature,
                                                 final String address,
                                                 final String birthPlace,
                                                 final String parents,
                                                 final String team,
                                                 final String mrz) {
		return
			"{\n" //$NON-NLS-1$
				+ "  \"name\": \"" + name + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"surname\": \"" + surname + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"sex\": \"" + sex + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"nationality\": \"" + nationality + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"birthDate\": \"" + birthDate + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"supportNo\": \"" + supportNo + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"validity\": \"" + validity + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"dni\": \"" + id + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"photo\": \"" + photo + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"signature\": \"" + signature + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"address\": \"" + address + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"birthPlace\": \"" + birthPlace + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"parents\": \"" + parents + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"team\": \"" + team + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
				+ "  \"mrz\": \"" + mrz + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
			+ "}"; //$NON-NLS-1$
	}
}
