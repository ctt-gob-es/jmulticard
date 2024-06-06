package com.accenture.es.hps;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;

import es.gob.jmulticard.asn1.icao.OptionalDetails;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.BurnedDnieCardException;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.card.icao.InvalidCanOrMrzException;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.crypto.BcCryptoHelper;

/** Envoltura a las funcionalidades de firma del DNIe v3 que permite operar
 * intercambiando JSON en vez de tratar objetos y excepciones Java.
 * Esto permite una operaci&oacute;n mucho m&aacute;s limpia cuando se usa
 * c&oacute;digo traducido de Java a Objective-C (J2Obc).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Dnie3ObcWrapperSign {

    /** Alias del certificado de firma del DNIe (siempre el mismo en el DNIe y tarjetas derivadas). */
	private static final String CERT_ALIAS_SIGN = "CertFirmaDigital"; //$NON-NLS-1$

	private Dnie3 dnie3;
	private ApduConnection conn;


	/** Inicializa la conexi&oacute;n con el DNIe y devuelve los datos necesarios para
	 * una prefirma o la obtenci&oacute;n de datos del titular previa a la firma.
	 * @param can CAN.
	 * @param pin PIN.
	 * @return Un JSON con los datos o con un error seg&uacute;n esta codificaci&oacute;n:
	 * <dl>
	 *  <dt>00</dt><dd>La tarjeta detectada no es un DNIe.</dd>
	 *  <dt>01</dt><dd>El DNIe tiene su memoria vol&aacute;til borrada.</dd>
	 *  <dt>02</dt><dd>Error gen&eacute;rico en la conexi&oacute;n.</dd>
	 *  <dt>03</dt><dd>Error gen&eacute;rico.</dd>
	 *  <dt>04</dt><dd>El DNIe detectado no es compatible con la biblioteca.</dd>
	 *  <dt>05</dt><dd>El DNIe tiene el PIN bloqueado.</dd>
	 *  <dt>06</dt><dd>Error gen&eacute;rico en el DNIe.</dd>
	 *  <dt>07</dt><dd>PIN incorrecto.</dd>
	 *  <dt>08</dt><dd>El DNIe no tiene certificado de firma (puede ser de un menor o de un adulto sin firma).</dd>
	 *  <dt>09</dt><dd>El certificado de firma est&aacute; caducado.</dd>
	 *  <dt>10</dt><dd>El certificado de firma a&uacute;n no es v&aacute;lido.</dd>
	 *  <dt>11</dt><dd>El certificado de firma est&aacute; corrupto.</dd>
	 *  <dt>12</dt><dd>Error leyendo los datos del titular del DNIe</dd>
	 *  <dt>14</dt><dd>CAN incorrecto.</dd>
	 * </dl>
	 */
	public String getDnieData(final String pin,
			                  final String can) {

		conn = new IosNfcConnection();

		final Dnie dnie;
		try {
			dnie = DnieFactory.getDnieNfc(
				conn,
				new BcCryptoHelper(),
				new DnieCallbackHandler(can, pin.toCharArray())
			);
		}
		catch (final InvalidCardException e) {
			return buildErrorJson(
				"00", //$NON-NLS-1$
				e.getExpectedAtr() != null ? e.getExpectedAtr().toString() : "", //$NON-NLS-1$
				e
			);
		}
		catch (final BurnedDnieCardException e) {
			return buildErrorJson("01", e); //$NON-NLS-1$
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

		dnie3 = (Dnie3) dnie;

		final X509Certificate signCert;
		signCert = dnie3.getCertificate(CERT_ALIAS_SIGN);

		if (signCert == null) {
			return buildErrorJson("08", null); //$NON-NLS-1$
		}

		try {
			signCert.checkValidity();
		}
		catch (final CertificateExpiredException e) {
			return buildErrorJson("09", e); //$NON-NLS-1$
		}
		catch (final CertificateNotYetValidException e) {
			return buildErrorJson("10", e); //$NON-NLS-1$
		}

		final String signCertBase64;
		try {
			signCertBase64 = Base64.toBase64String(signCert.getEncoded());
		}
		catch (final CertificateEncodingException e) {
			return buildErrorJson("11", e); //$NON-NLS-1$
		}

		try {
			dnie3.openSecureChannelIfNotAlreadyOpened(true);
		}
		catch (final CryptoCardException e) {
			return buildErrorJson("06", e); //$NON-NLS-1$
		}
		catch (final PinException e) {
			return buildErrorJson(
				"07", //$NON-NLS-1$
				e instanceof BadPinException ?
					Integer.toString(((BadPinException)e).getRemainingRetries()) : "", //$NON-NLS-1$
				e
			);
		}

		final OptionalDetails dg13;
		try {
			dg13 = dnie3.getDg13();
		}
		catch (final Exception e) {
			return buildErrorJson("12", e); //$NON-NLS-1$
		}

		return buildDniDataJson(
			signCertBase64,
			dg13.getName(),
			dg13.getFirstSurname(),
			dg13.getSecondSurname(),
			dg13.getIdNumber(),
			dg13.getAddress(),
			dg13.getCity(),
			dg13.getProvince(),
			dg13.getCountry()
		);
	}

	/** Firma datos con DNIe y el certificado de firma.
	 * @param dataBase64 Datos a firmar en Base64.
	 * @param signAlgorithm Algoritmo de firma.
	 * @return Un JSON con la firma o con un error seg&uacute;n esta codificaci&oacute;n:
	 * <dl>
	 *  <dt>05</dt><dd>El DNIe tiene el PIN bloqueado.</dd>
	 *  <dt>07</dt><dd>PIN incorrecto.</dd>
	 *  <dt>08</dt><dd>El DNIe no tiene certificado de firma (puede ser de un menor).</dd>
	 *  <dt>13</dt><dd>DNI no inicializado.</dd>
	 *  <dt>15</dt><dd>Error gen&eacute;rico en el DNIe.</dd>
	 *  <dt>16</dt><dd>Error gen&eacute;rico.</dd>
	 *  <dt>17</dt><dd>No se han proporcionado datos para firmar.</dd>
	 * </dl>
	 */
	public String sign(final String dataBase64,
	                   final String signAlgorithm) {

		if (dnie3 == null) {
			return buildErrorJson("13", null); //$NON-NLS-1$
		}

		if (dataBase64 == null || dataBase64.trim().isEmpty()) {
			return buildErrorJson("17", null); //$NON-NLS-1$
		}

		final PrivateKeyReference pke = dnie3.getPrivateKey(CERT_ALIAS_SIGN);
		if (pke == null) {
			return buildErrorJson("08", null); //$NON-NLS-1$
		}

		final byte[] data = Base64.decode(
			dataBase64.replace("-", "+").replace("_", "/") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		);

		try {
			dnie3.openSecureChannelIfNotAlreadyOpened(true);
		}
		catch (final AuthenticationModeLockedException e) {
			return buildErrorJson("05", e); //$NON-NLS-1$
		}
		catch (final CryptoCardException e) {
			return buildErrorJson("06", e); //$NON-NLS-1$
		}
		catch (final PinException e) {
			return buildErrorJson(
				"07", //$NON-NLS-1$
				e instanceof BadPinException ?
					Integer.toString(((BadPinException)e).getRemainingRetries()) : "", //$NON-NLS-1$
				e
			);
		}

		final byte[] p1signature;
		try {
			p1signature = dnie3.sign(data, signAlgorithm, pke);
		}
		catch (final AuthenticationModeLockedException e) {
			return buildErrorJson("05", e); //$NON-NLS-1$
		}
		catch (final CryptoCardException e) {
			return buildErrorJson("15", e); //$NON-NLS-1$
		}
		catch (final PinException e) {
			return buildErrorJson(
				"07", //$NON-NLS-1$
				e instanceof BadPinException ?
					Integer.toString(((BadPinException)e).getRemainingRetries()) : "", //$NON-NLS-1$
				e
			);
		}
		catch(final Exception e) {
			return buildErrorJson("16", e); //$NON-NLS-1$
		}

		return buildSignatureJson(Base64.toBase64String(p1signature));
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

	private static String buildDniDataJson(final String certificate,
			                               final String name,
			                               final String surname1,
			                               final String surname2,
			                               final String id,
			                               final String address,
			                               final String city,
			                               final String province,
			                               final String country) {
		return
			"{\n" //$NON-NLS-1$
			+ "  \"certificate\": \"" + certificate + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
			+ "  \"dni\": \"" + id + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
			+ "  \"name\": \"" + name + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
			+ "  \"surname1\": \"" + surname1 + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
			+ "  \"surname2\": \"" + surname2 + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
			+ "  \"address\": \"" + address + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
			+ "  \"city\": \"" + city + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
			+ "  \"province\": \"" + province + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
			+ "  \"country\": \"" + country + "\"\n" + //$NON-NLS-1$ //$NON-NLS-2$
			"}"; //$NON-NLS-1$
	}

	private static String buildSignatureJson(final String sig) {
		return
			"{\n" //$NON-NLS-1$
			+ "  \"signature\": \"" + sig + "\"\n" + //$NON-NLS-1$ //$NON-NLS-2$
			"}"; //$NON-NLS-1$
	}
}
