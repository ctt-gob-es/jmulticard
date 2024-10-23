package test.es.gob.jmulticard;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.TextInputCallback;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.icao.AdditionalPersonalDetails;
import es.gob.jmulticard.asn1.icao.Com;
import es.gob.jmulticard.asn1.icao.OptionalDetails;
import es.gob.jmulticard.asn1.icao.SecurityOptions;
import es.gob.jmulticard.asn1.icao.Sod;
import es.gob.jmulticard.asn1.icao.SubjectFacePhoto;
import es.gob.jmulticard.asn1.icao.SubjectSignaturePhoto;
import es.gob.jmulticard.callback.CustomTextInputCallback;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.card.dnie.Dnie3Cwa14890Constants;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.card.dnie.DnieNfc;
import es.gob.jmulticard.card.icao.MrtdLds1;
import es.gob.jmulticard.card.icao.Mrz;
import es.gob.jmulticard.card.icao.bac.IcaoMrtdWithBac;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.cwa14890.Cwa14890OneV1Connection;
import es.gob.jmulticard.crypto.BcCryptoHelper;
import es.gob.jmulticard.jse.provider.ProviderUtil;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de operaciones en DNIe sin PIN.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestDnieLow {

//	private static final String MRZ = ""; //$NON-NLS-1$
//	private static final String CAN = "630208"; //$NON-NLS-1$
//	private static final String CAN = "961984"; //$NON-NLS-1$
	private static final String CAN = "203136"; //$NON-NLS-1$

	private static final String PIN = "PIN"; //$NON-NLS-1$

	private static final CryptoHelper CH = new BcCryptoHelper();

	/** Alias del certificado de autenticaci&oacute;n del DNIe (siempre el mismo en el DNIe y tarjetas derivadas). */
	private static final String CERT_ALIAS_AUTH = "CertAutenticacion"; //$NON-NLS-1$

    /** Alias del certificado de firma del DNIe (siempre el mismo en el DNIe y tarjetas derivadas). */
	private static final String CERT_ALIAS_SIGN = "CertFirmaDigital"; //$NON-NLS-1$

    /** Alias del certificado de CA intermedia (siempre el mismo en el DNIe). */
	private static final String CERT_ALIAS_INTERMEDIATE_CA = "CertCAIntermediaDGP"; //$NON-NLS-1$

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		new TestDnieLow().testDnieReadDgs();
	}

	/** Prueba la obtenci&oacute;n de los intentos restantes de PIN.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
 	void testDniePinRetries() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			CH,
			new TestingDnieCallbackHandler(CAN, (char[])null),
			false
		);
		Assertions.assertNotNull(dnie);
		System.out.println(dnie);
		final X509Certificate signCert = dnie.getCertificate(CERT_ALIAS_SIGN);
		if (signCert != null) {
			final X509Certificate intCaCert = dnie.getCertificate(CERT_ALIAS_INTERMEDIATE_CA);
			System.out.println("CA intermedia: " + intCaCert.getSubjectX500Principal()); //$NON-NLS-1$
			System.out.println("Certificado: " + signCert.getSubjectX500Principal()); //$NON-NLS-1$
		}
		else {
			System.out.println("No hay certificado de firma"); //$NON-NLS-1$
		}
		dnie.openSecureChannelIfNotAlreadyOpened(false);
		System.out.println("Intentos restantes de PIN: " + dnie.getPinRetriesLeft()); //$NON-NLS-1$
	}

	/** Prueba de apertura de canal de PIN con CHV.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testOpenPinChannel() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			CH,
			new TestingDnieCallbackHandler(CAN, PIN),
			false
		);
		Assertions.assertNotNull(dnie);
		System.out.println(dnie);
		dnie.openSecureChannelIfNotAlreadyOpened(true);
	}

	/** Prueba de la factor&iacute;a de DNIe para obtenci&oacute;n de un eMRTD.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
 	void testDnieFactoryMrtd() throws Exception {
		final MrtdLds1 eMrtd = DnieFactory.getEmrtdNfc(
			ProviderUtil.getDefaultConnection(),
			CH,
			new TestingDnieCallbackHandler(CAN, (char[])null)
		);
		Assertions.assertNotNull(eMrtd);
		System.out.println(eMrtd);
		final Com com = eMrtd.getCom();
		System.out.println(com);
		if (com.isDg2Present()) {
			final SubjectFacePhoto dg2 = eMrtd.getDg2();
			final byte[] photo = dg2.getSubjectPhotoAsJpeg2k();
			System.out.println(photo.length);
		}
	}

	/** Prueba de la factor&iacute;a de DNIe.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
 	void testDnieFactory() throws Exception {

//		TS2 - 3B-7F-38-00-00-00-6A-44-4E-49-65-10-02-4C-34-01-13-03-90-00
//		TS3 = 3B-7F-96-00-00-00-6A-44-4E-49-65-10-01-01-55-04-21-03-90-00
//		TJ3 = 3B-7F-96-00-00-00-6A-44-4E-49-65-10-01-01-55-04-21-03-90-00
//		TJ4 = 3B-7F-96-00-00-00-6A-44-4E-49-65-20-01-01-55-04-21-03-90-00

		final Dnie dnie = DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			CH,
			null,
			false
		);
		Assertions.assertNotNull(dnie);
		System.out.println(dnie);
	}

	/** Prueba la obtenci&oacute;n y verificaci&oacute;n del SOD.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testDnieSod() throws Exception {
		final Dnie3 dnie = (Dnie3) DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			CH,
			new TestingDnieCallbackHandler(CAN, PIN),
			false
		);
		Assertions.assertNotNull(dnie);
		System.out.println(dnie);
		dnie.openSecureChannelIfNotAlreadyOpened(false);
		final Sod sod = dnie.getSod();
		System.out.println(sod);
		System.out.println();
		final X509Certificate[] certChain = dnie.checkSecurityObjects();
		System.out.println(certChain[0].getSubjectX500Principal());
	}

	/** Prueba simple de firma de DNIe 3 o 4 por NFC.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testDnie3Nfc() throws Exception {
		final Dnie3 dni = new DnieNfc(
			new SmartcardIoConnection(), // Conexion, debe ser NFC
			null,
			new BcCryptoHelper(),
			new TestingDnieCallbackHandler(CAN, PIN)
		);
		Assertions.assertNotNull(dni);
		final PrivateKeyReference pke = dni.getPrivateKey(CERT_ALIAS_SIGN);
		final byte[] datosFirmados = dni.sign(
			"hola mundo".getBytes(), //$NON-NLS-1$
			"SHA256withRSA", //$NON-NLS-1$ // Probar con SHA512withRSA
			pke
		);
		System.out.println(new String(datosFirmados));

	}

	/** Prueba directa de firma.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testDnieSign() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			CH,
			new TestingDnieCallbackHandler(CAN, PIN),
			true
		);
		Assertions.assertNotNull(dnie);
		System.out.println();
		System.out.println(dnie);
		System.out.println();
		if (!(dnie instanceof Dnie3)) {
			System.out.println("No es un DNIe 3.0 o 4.0"); //$NON-NLS-1$
		}

		final X509Certificate dniIntCert = dnie.getCertificate(CERT_ALIAS_INTERMEDIATE_CA);
		if (dniIntCert != null) {
			System.out.println("Certificado intermedio de DNI encontrado: " + dniIntCert.getSubjectX500Principal()); //$NON-NLS-1$
		}
		else {
			System.out.println("Certificado intermedio de DNI NO encontrado"); //$NON-NLS-1$
		}
		System.out.println();

		final String[] aliases = dnie.getAliases();
		System.out.println("ALIAS ENCONTRADOS:"); //$NON-NLS-1$
		for (final String a : aliases) {
			System.out.println("    " + a); //$NON-NLS-1$
		}
		System.out.println();

		System.out.println("CERTIFICADOS ENCONTRADOS:"); //$NON-NLS-1$
		for (final String a : aliases) {
			System.out.println("    " + dnie.getCertificate(a).getSubjectX500Principal()); //$NON-NLS-1$
		}
		System.out.println();

		PrivateKeyReference pkr = dnie.getPrivateKey(CERT_ALIAS_SIGN);
		if (pkr == null) {
			System.out.println("El DNI no tiene certificado de firma, se usa el de autenticacion"); //$NON-NLS-1$
			pkr = dnie.getPrivateKey(CERT_ALIAS_AUTH);
		}

		System.out.println();
		System.out.println(pkr);

		final byte[] sign = dnie.sign("Hola mundo".getBytes(), "SHA256withRSA", pkr); //$NON-NLS-1$ //$NON-NLS-2$

		System.out.println();
		System.out.println("Firma generada: " + HexUtils.hexify(sign, true)); //$NON-NLS-1$
	}

	/** Prueba una autenticaci&oacute; pasiva de DNIe (sin PIN).
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testAuthNoPin() throws Exception {

		final CryptoHelper cryptoHelper = new BcCryptoHelper();

		final Dnie3 dnie = (Dnie3) DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			cryptoHelper,
			new TestingDnieCallbackHandler(CAN, (String)null), // No usamos el PIN
			false // No cargamos certificados ni nada
		);
		Assertions.assertNotNull(dnie);

		final RSAPublicKey iccCertPuk = dnie.getIccCertPublicKey();

		final X509Certificate iccIntCert = dnie.getCertificate(CERT_ALIAS_INTERMEDIATE_CA);
		try (OutputStream fos = new FileOutputStream(File.createTempFile("CERT_INTER_DNI_", ".cer"))) { //$NON-NLS-1$ //$NON-NLS-2$
			fos.write(iccIntCert.getEncoded());
		}
		System.out.println("Certificado intermedio: " + iccIntCert.getSubjectX500Principal()); //$NON-NLS-1$

        final byte[] randomIfd = cryptoHelper.generateRandomBytes(8);

        final Dnie3Cwa14890Constants constants = DnieFactory.getDnie3UsrCwa14890Constants(dnie.getIdesp());

        // Nos validamos contra la tarjeta como controlador
        dnie.verifyIfdCertificateChain(constants);

		// Ahora hacemos una autenticacion interna con un aleatorio generado externamente
		final byte[] sigMinCiphered = Cwa14890OneV1Connection.internalAuthGetInternalAuthenticateMessage(
			dnie,
			constants,
			randomIfd
		);

		System.out.println("SigMin cifrado: " + HexUtils.hexify(sigMinCiphered, false)); //$NON-NLS-1$

		// Validamos esa autenticacion interna
		Cwa14890OneV1Connection.internalAuthValidateInternalAuthenticateMessage(
			constants.getChrCCvIfd(),     // CHR de la clave publica del certificado de terminal
			sigMinCiphered,               // Mensaje de autenticacion generado por la tarjeta.
			randomIfd,                    // Aleatorio del desafio del terminal.
			constants.getIfdPrivateKey(), // Clave privada del certificado de terminal.
			constants.getIfdKeyLength(),  // Longitud en octetos de las claves RSA del certificado de componente del terminal.
			constants,                    // Constantes publicas para la apertura de canal CWA-14890.
			iccCertPuk,                   // Clave publica del certificado de componente.
			cryptoHelper                  // Utilidad para la ejecucion de funciones criptograficas.
		);

		System.out.println("Autenticacion interna correcta"); //$NON-NLS-1$

		// Abrimos canal de usuario (sin PIN), lo que reinicia la autenticacion interna
		dnie.openSecureChannelIfNotAlreadyOpened(false);

		// Obtenemos el SOD
		final Sod sod = dnie.getSod();
		System.out.println(sod);

		// Obtenemos los datos del DNI

		final Com com = dnie.getCom();
		System.out.println(com);
		System.out.println();

		final Mrz dg1 = dnie.getDg1();
		System.out.println("DG1: " + dg1); //$NON-NLS-1$
		System.out.println();

		final byte[] dg2 = dnie.getDg2().getBytes(); // Foto del rostro
		try (OutputStream fos = new FileOutputStream(File.createTempFile("MRTD_ROSTRO_", ".jp2"))) { //$NON-NLS-1$ //$NON-NLS-2$
			fos.write(dg2);
		}

		//final ResponseApdu res = dnie.sendArbitraryApdu(null);

		// 3 no hay permisos

		// 4, 5, 6 no presentes en el DNI
		final byte[] dg7 = dnie.getDg7().getBytes(); // Imagen de la firma manuscrita
		try (OutputStream fos = new FileOutputStream(File.createTempFile("MRTD_FIRMA_", ".jp2"))) { //$NON-NLS-1$ //$NON-NLS-2$
			fos.write(dg7);
		}

		// 8, 9 y 10 no presente en el DNI
		final AdditionalPersonalDetails dg11 = dnie.getDg11(); // Detalles personales adicionales
		System.out.println("DG11: " + HexUtils.hexify(dg11.getBytes(), false)); //$NON-NLS-1$
		System.out.println();
		// 12 no presente en el DNI

		final OptionalDetails dg13 = dnie.getDg13(); // Detalles opcionales
		System.out.println(dg13);
		System.out.println();

		final SecurityOptions dg14 = dnie.getDg14(); // Opciones de seguridad
		System.out.println("DG14:\n" + dg14); //$NON-NLS-1$
	}

	private static void printDgs(final Com com, final MrtdLds1 dnie3) throws Exception {
		for (final String dg : com.getPresentDgs()) {
			System.out.println("Leyendo " + dg); //$NON-NLS-1$
			System.out.println();
			byte[] dgContent = null;
			switch(dg) {
				case "DG1": //$NON-NLS-1$
					final Mrz dg1 = dnie3.getDg1();
					dgContent = dg1.getBytes();
					System.out.println(dg1);
					System.out.println();
					break;
				case "DG2": //$NON-NLS-1$
					final SubjectFacePhoto dg2 = dnie3.getDg2();
					dgContent = dg2.getBytes();
//					final byte[] photo = dg2.getSubjectPhotoAsJpeg2k();
//					final JFrame framePhoto = new JFrame();
//					framePhoto.add(new JLabel(new ImageIcon(ImageIO.read(new ByteArrayInputStream(photo))))); // width = 307 height = 378
//					framePhoto.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
//					framePhoto.pack();
//					framePhoto.setVisible(true);
					break;
				case "DG3": //$NON-NLS-1$
					// Necesita permisos administrativos
//					dgContent = dnie3.getDg3();
					break;
				case "DG4": //$NON-NLS-1$
					dgContent = dnie3.getDg4();
					break;
				case "DG5": //$NON-NLS-1$
					dgContent = dnie3.getDg5();
					break;
				case "DG6": //$NON-NLS-1$
					dgContent = dnie3.getDg6();
					break;
				case "DG7": //$NON-NLS-1$
					final SubjectSignaturePhoto dg7 = dnie3.getDg7();
					dgContent = dg7.getBytes();
//					final JFrame frameRubric = new JFrame();
//					frameRubric.add(
//						new JLabel(
//							new ImageIcon(
//								ImageIO.read(
//									new ByteArrayInputStream(
//										dg7.getSubjectSignaturePhotoAsJpeg2k()
//									)
//								)
//							)
//						)
//					);
//					frameRubric.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
//					frameRubric.pack();
//					frameRubric.setVisible(true);
					break;
				case "DG8": //$NON-NLS-1$
					dgContent = dnie3.getDg8();
					break;
				case "DG9": //$NON-NLS-1$
					dgContent = dnie3.getDg9();
					break;
				case "DG10": //$NON-NLS-1$
					dgContent = dnie3.getDg10();
					break;
				case "DG11": //$NON-NLS-1$
					final AdditionalPersonalDetails dg11 = dnie3.getDg11();
					dgContent = dg11.getBytes();
					System.out.println(dg11);
					System.out.println();
					break;
				case "DG12": //$NON-NLS-1$
					dgContent = dnie3.getDg12();
					break;
				case "DG13": //$NON-NLS-1$
					final OptionalDetails dg13 = dnie3.getDg13();
					dgContent = dg13.getBytes();
					System.out.println(dg13);
					System.out.println();
					break;
				case "DG14": //$NON-NLS-1$
					final SecurityOptions dg14 = dnie3.getDg14();
					dgContent = dg14.getBytes();
					System.out.println(dg14);
					System.out.println();
					break;
				case "DG15": //$NON-NLS-1$
					dgContent = dnie3.getDg15();
					break;
				case "DG16": //$NON-NLS-1$
					dgContent = dnie3.getDg16();
					break;
				default:
					break;
			}
			if (dgContent != null) {
				try (OutputStream fos = new FileOutputStream(File.createTempFile("DNI_" + dg + "_", ".bin"))) { //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
					fos.write(dgContent);
				}
			}
		}
	}

	/** Prueba de lectura de DG en MRTD por NFC.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testDnieReadDgs() throws Exception {

		final MrtdLds1 dnie = DnieFactory.getEmrtdNfc(
			ProviderUtil.getDefaultConnection(),
			new BcCryptoHelper(),
			new TestingDnieCallbackHandler(CAN, (String)null) // No usamos el PIN
		);
		Assertions.assertNotNull(dnie);
		System.out.println();
		System.out.println(dnie);
		System.out.println();

		// COM
		try {
			final Com com = dnie.getCom();
			System.out.println("COM:"); //$NON-NLS-1$
			System.out.println(com);
			System.out.println();
			try (OutputStream fos = new FileOutputStream(File.createTempFile("DNI_COM_", ".bin"))) { //$NON-NLS-1$ //$NON-NLS-2$
				fos.write(com.getBytes());
			}
			printDgs(com, dnie);
		}
		catch(final Exception e) {
			System.out.println("No se ha podido leer el COM: " + e); //$NON-NLS-1$
			return;
		}

		// CARD ACCESS
		try {
			final byte[] cardAccess = dnie.getCardAccess();
			System.out.println("CardAccess:"); //$NON-NLS-1$
			System.out.println(HexUtils.hexify(cardAccess, true));
			System.out.println();
			System.out.println(Base64.getEncoder().encodeToString(cardAccess));
			System.out.println();
			try (OutputStream fos = new FileOutputStream(File.createTempFile("DNI_CARDACCESS_", ".bin"))) { //$NON-NLS-1$ //$NON-NLS-2$
				fos.write(cardAccess);
			}
		}
		catch(final Exception e) {
			System.out.println("No se ha podido leer el CardAccess: " + e); //$NON-NLS-1$
		}

		// DIR
		try {
			final byte[] dir = dnie.getDir();
			System.out.println("DIR:"); //$NON-NLS-1$
			System.out.println(HexUtils.hexify(dir, true));
			System.out.println();
			System.out.println(Base64.getEncoder().encodeToString(dir));
			System.out.println();
			try (OutputStream fos = new FileOutputStream(File.createTempFile("DNI_DIR_", ".bin"))) { //$NON-NLS-1$ //$NON-NLS-2$
				fos.write(dir);
			}
		}
		catch(final Exception e) {
			System.out.println("No se ha podido leer el DIR: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] atrInfo = dnie.getAtrInfo();
			System.out.println("ATR/INFO:"); //$NON-NLS-1$
			System.out.println(HexUtils.hexify(atrInfo, true));
			System.out.println();
			try (OutputStream fos = new FileOutputStream(File.createTempFile("DNI_ATRINFO_", ".bin"))) { //$NON-NLS-1$ //$NON-NLS-2$
				fos.write(atrInfo);
			}
		}
		catch(final Exception e) {
			System.out.println("No se ha podido leer la informacion del ATR: " + e); //$NON-NLS-1$
		}

		// Abrimos canal seguro sin verificar el PIN
		if (dnie instanceof Dnie3) {
			final Dnie3 dnie3 = (Dnie3) dnie;
			try {
				dnie3.openSecureChannelIfNotAlreadyOpened(false);
			}
			catch(final Exception e) {
				System.out.println("No se ha podido abrir canal seguro: " + e); //$NON-NLS-1$
			}

			try {
				final Sod sod = dnie3.getSod();
				System.out.println("SOD:"); //$NON-NLS-1$
				System.out.println(sod);
				System.out.println();
				try (OutputStream fos = new FileOutputStream(File.createTempFile("DNI_SOD_", ".bin"))) { //$NON-NLS-1$ //$NON-NLS-2$
					fos.write(sod.getBytes());
				}
			}
			catch(final Exception e) {
				System.out.println("No se ha podido leer el SOD: " + e); //$NON-NLS-1$
			}

			System.out.println("Certificados del DNIe:"); //$NON-NLS-1$
			try {
				for (final String alias : dnie3.getAliases()) {
					System.out.println("   " + dnie3.getCertificate(alias).getSubjectX500Principal()); //$NON-NLS-1$
				}
			}
			catch(final Exception e) {
				System.out.println("Error obteniendo los certificados"); //$NON-NLS-1$
				e.printStackTrace();
			}
		}

		for (;;) {
			// Vacio, para mantener las imagenes abiertas y visibles
		}
	}

	/** Prueba de lectura del DG13.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testDnie3Dg13Parser() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			new BcCryptoHelper(),
			null,
			false
		);
		Assertions.assertNotNull(dnie);
		if (!(dnie instanceof Dnie3)) {
			System.out.println("No es un DNIe v3.0"); //$NON-NLS-1$
			return;
		}
		dnie.openSecureChannelIfNotAlreadyOpened();

		final Dnie3 dnie3 = (Dnie3) dnie;

		final OptionalDetails dnie3Dg13Identity = dnie3.getDg13();

		System.out.println("Name: "            + dnie3Dg13Identity.getName());           //$NON-NLS-1$
		System.out.println("Second surname: "  + dnie3Dg13Identity.getSecondSurname());  //$NON-NLS-1$
		System.out.println("First surname: "   + dnie3Dg13Identity.getFirstSurname());   //$NON-NLS-1$
		System.out.println("ID number: "       + dnie3Dg13Identity.getIdNumber());      //$NON-NLS-1$
		System.out.println("Birth date: "      + dnie3Dg13Identity.getBirthDate());      //$NON-NLS-1$
		System.out.println("Nationality: "     + dnie3Dg13Identity.getNationality());    //$NON-NLS-1$
		System.out.println("Expiration date: " + dnie3Dg13Identity.getExpirationDate()); //$NON-NLS-1$
		System.out.println("Support number: "  + dnie3Dg13Identity.getSupportNumber());  //$NON-NLS-1$
		System.out.println("Sex: "             + dnie3Dg13Identity.getSex());            //$NON-NLS-1$
		System.out.println("Birth city: "      + dnie3Dg13Identity.getBirthCity());      //$NON-NLS-1$
		System.out.println("Birth country: "   + dnie3Dg13Identity.getBirthCountry());   //$NON-NLS-1$
		System.out.println("Parent's names: "  + dnie3Dg13Identity.getParentsNames());   //$NON-NLS-1$
		System.out.println("Address: "         + dnie3Dg13Identity.getAddress());        //$NON-NLS-1$
		System.out.println("City: "            + dnie3Dg13Identity.getCity());           //$NON-NLS-1$
		System.out.println("Province: "        + dnie3Dg13Identity.getProvince());       //$NON-NLS-1$
		System.out.println("Country: "         + dnie3Dg13Identity.getCountry());        //$NON-NLS-1$
	}

	/** Prueba de <code>CallbackHandler</code> con distintas clases para <code>TextInputCallback</code>.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Probar solo en sistemas con entornos no estandar, como Android")
	void testFlexHandler() throws Exception {
		final CallbackHandler cbh = new TestingDnieCallbackHandler(CAN, PIN);
		final CustomTextInputCallback custom = new CustomTextInputCallback("customprompt"); //$NON-NLS-1$
		final TextInputCallback java = new TextInputCallback("javaprompt"); //$NON-NLS-1$
		cbh.handle(new Callback[] { custom, java });
		Assertions.assertEquals("texto", custom.getText()); //$NON-NLS-1$
		Assertions.assertEquals("texto", java.getText()); //$NON-NLS-1$
	}

	/** Prueba de lectura de DG en Pasaporte.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita pasaporte")
	void testPassportWithBacReadDgs() throws Exception {
		final ApduConnection conn = ProviderUtil.getDefaultConnection();
		System.out.println(HexUtils.hexify(conn.reset(), true));
		System.out.println();
		final IcaoMrtdWithBac passport = new IcaoMrtdWithBac(conn, new BcCryptoHelper());
		Assertions.assertNotNull(passport);

		System.out.println();
		System.out.println(passport);
		System.out.println();

		final Com com = passport.getCom();
		System.out.println(com);
		System.out.println();

		final Mrz dg1 = passport.getDg1();
		System.out.println(dg1);
		System.out.println();

		final AdditionalPersonalDetails dg11 = passport.getDg11();
		System.out.println(dg11);
		System.out.println();
	}

	/** Prueba de carga de certificados.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testReadCerts() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null, // PasswordCallback
			new BcCryptoHelper(),
			new TestingDnieCallbackHandler(CAN, (char[])null), // CallbackHandler con PIN nulo
			false
		);
		Assertions.assertNotNull(dnie);
		final String[] aliases = dnie.getAliases();
		for (final String alias : aliases) {
			System.out.println(alias + ": " + dnie.getCertificate(alias).getSubjectX500Principal()); //$NON-NLS-1$
		}
		System.out.println(CERT_ALIAS_SIGN + ": " + dnie.getCertificate(CERT_ALIAS_SIGN)); //$NON-NLS-1$
		System.out.println(CERT_ALIAS_INTERMEDIATE_CA + ": " + dnie.getCertificate(CERT_ALIAS_INTERMEDIATE_CA).getSubjectX500Principal()); //$NON-NLS-1$
	}
}
