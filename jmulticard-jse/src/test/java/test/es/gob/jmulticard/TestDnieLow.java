package test.es.gob.jmulticard;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.imageio.ImageIO;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.TextInputCallback;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.WindowConstants;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.BcCryptoHelper;
import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneV1Connection;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.icao.Com;
import es.gob.jmulticard.asn1.icao.OptionalDetails;
import es.gob.jmulticard.asn1.icao.Sod;
import es.gob.jmulticard.callback.CustomTextInputCallback;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.card.dnie.Dnie3Cwa14890Constants;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.card.dnie.DnieSubjectPrincipalParser;
import es.gob.jmulticard.card.dnie.OptionalDetailsDnie3;
import es.gob.jmulticard.card.icao.Mrz;
import es.gob.jmulticard.card.icao.bac.IcaoMrtdWithBac;
import es.gob.jmulticard.jse.provider.ProviderUtil;

/** Pruebas de operaciones en DNIe sin PIN.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestDnieLow {

//	private static final String MRZ = ""; //$NON-NLS-1$
	private static final String CAN = "can"; //$NON-NLS-1$

	private static final String PIN = "pin"; //$NON-NLS-1$

	private static final CryptoHelper CH = new BcCryptoHelper();

	/** Prueba de lectura sin PIN de los datos del titular.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
 	public void testDnieReadSubject() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			CH,
			null,
			false
		);
		final Cdf cdf = dnie.getCdf();
		System.out.println(cdf);
		System.out.println();
		System.out.println(new DnieSubjectPrincipalParser(cdf.getCertificateSubjectPrincipal(0)));
		System.out.println("IDESP: " + dnie.getIdesp()); //$NON-NLS-1$
	}

	/** Prueba la obtenci&oacute;n y verificaci&oacute;n del SOD.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDnieSod() throws Exception {
		final Dnie3 dnie = (Dnie3) DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			CH,
			new TestingDnieCallbackHandler(CAN, PIN),
			true
		);
		System.out.println(dnie);
		dnie.openSecureChannelIfNotAlreadyOpened(false);
		final Sod sod = dnie.getSod();
		System.out.println(sod);
		System.out.println();
		final X509Certificate[] certChain = dnie.checkSecurityObjects();
		System.out.println(certChain[0].getSubjectX500Principal());
	}

	/** Prueba directa de firma.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDnieSign() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			CH,
			new TestingDnieCallbackHandler(CAN, PIN),
			//new SmartcardCallbackHandler(),
			true
		);
		System.out.println();
		System.out.println(dnie);
		System.out.println();
		if (!(dnie instanceof Dnie3)) {
			System.out.println("No es un DNIe v3.0"); //$NON-NLS-1$
			return;
		}
		final String[] aliases = dnie.getAliases();
		for (final String a : aliases) {
			System.out.println(a);
		}

		final PrivateKeyReference pkr = dnie.getPrivateKey(Dnie.CERT_ALIAS_SIGN);

		System.out.println();
		System.out.println(pkr);

		final byte[] sign = dnie.sign(
			"Hola mundo".getBytes(), //$NON-NLS-1$
			"SHA256withRSA", //$NON-NLS-1$
			pkr
		);

		System.out.println();
		System.out.println("Firma generada: " + HexUtils.hexify(sign, true)); //$NON-NLS-1$
	}

	/** Prueba una autenticaci&oacute; de DNIe sin PIN.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testAuthNoPin() throws Exception {

		final CryptoHelper cryptoHelper = new BcCryptoHelper();

		final Dnie3 dnie = (Dnie3) DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			cryptoHelper,
			new TestingDnieCallbackHandler(CAN, (String)null), // No usamos el PIN
			false // No cargamos certificados ni nada
		);
		final X509Certificate iccCert = dnie.getIccCert();
//		try (
//			final OutputStream fos = new FileOutputStream(File.createTempFile("CERT_COMPO_DNI_", ".cer")) //$NON-NLS-1$ //$NON-NLS-2$
//		) {
//			fos.write(iccCert.getEncoded());
//		}
//		System.out.println(
//			"Certificado de componente: " + iccCert.getSubjectX500Principal() //$NON-NLS-1$
//		);

        final byte[] randomIfd = cryptoHelper.generateRandomBytes(8);

        final Dnie3Cwa14890Constants constants = DnieFactory.getDnie3UsrCwa14890Constants(dnie.getIdesp());

        // Nos validamos contra la tarjeta como controlador
        dnie.verifyIfdCertificateChain(constants);

		// Ahora hacemos una autenticación interna con un aleatorio generado externamente
		final byte[] sigMinCiphered = Cwa14890OneV1Connection.internalAuthGetInternalAuthenticateMessage(
			dnie,
			constants,
			randomIfd
		);

		System.out.println("SigMin cifrado: " + HexUtils.hexify(sigMinCiphered, false)); //$NON-NLS-1$

		// Validamos esa autenticación interna
		Cwa14890OneV1Connection.internalAuthValidateInternalAuthenticateMessage(
			constants.getChrCCvIfd(),              // CHR de la clave publica del certificado de terminal
			sigMinCiphered,                        // Mensaje de autenticacion generado por la tarjeta.
			randomIfd,                             // Aleatorio del desafio del terminal.
			constants.getIfdPrivateKey(),          // Clave privada del certificado de terminal.
			constants.getIfdKeyLength(),           // Longitud en octetos de las claves RSA del certificado de componente del terminal.
			constants,                             // Constantes privadas para la apertura de canal CWA-14890.
			constants,                             // Constantes publicas para la apertura de canal CWA-14890.
			(RSAPublicKey) iccCert.getPublicKey(), // Clave publica del certificado de componente.
			cryptoHelper                           // Utilidad para la ejecucion de funciones criptograficas.
		);

		System.out.println("Autenticacion interna correcta"); //$NON-NLS-1$

		// Abrimos canal de usuario (sin PIN), lo que reinicia la autenticacion interna
		dnie.openSecureChannelIfNotAlreadyOpened(false);

		// Obtenemos el SOD
		final Sod sod = dnie.getSod();
//		System.out.println(sod);

		// Obtenemos los datos del DNI

		final Com com = dnie.getCom();
		System.out.println(com);
		System.out.println();

		final Mrz dg1 = dnie.getDg1();
		System.out.println("DG1: " + dg1); //$NON-NLS-1$
		System.out.println();

		final byte[] dg2 = dnie.getDg2().getBytes(); // Foto del rostro

		//final ResponseApdu res = dnie.sendArbitraryApdu(null);

		// 3 no hay permisos
		// 4, 5, 6 no presentes en el DNI
		final byte[] dg7 = dnie.getDg7().getBytes(); // Imagen de la firma manuscrita
		// 8, 9 y 10 no presente en el DNI
		final byte[] dg11 = dnie.getDg11(); // Detalles personales adicionales
		System.out.println("DG11: " + HexUtils.hexify(dg11, false)); //$NON-NLS-1$
		System.out.println();
		// 12 no presente en el DNI

		final OptionalDetails dg13 = dnie.getDg13(); // Detalles opcionales
		System.out.println(dg13);
		System.out.println();

		final byte[] dg14 = dnie.getDg14(); // Opciones de seguridad
		System.out.println("DG14: " + HexUtils.hexify(dg14, false)); //$NON-NLS-1$
	}

	/** Prueba de lectura de DG en DNIe 3.0.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDnieReadDgs() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			new BcCryptoHelper(),
			new TestingDnieCallbackHandler(CAN, (String)null), // No usamos el PIN
			false
		);
		System.out.println();
		System.out.println(dnie);
		System.out.println();
		if (!(dnie instanceof Dnie3)) {
			System.out.println("No es un DNIe v3.0"); //$NON-NLS-1$
			return;
		}

		final Dnie3 dnie3 = (Dnie3) dnie;

		final byte[] atrInfo = dnie3.getAtrInfo();
		System.out.println("ATR/INFO:"); //$NON-NLS-1$
		System.out.println(HexUtils.hexify(atrInfo, true));
		System.out.println();

		final byte[] cardAccess = dnie3.getCardAccess();
		System.out.println("CardAccess:"); //$NON-NLS-1$
		System.out.println(HexUtils.hexify(cardAccess, true));
		System.out.println();

		// Abrimos canal seguro sin verificar el PIN
		dnie.openSecureChannelIfNotAlreadyOpened(false);

		final Sod sod = dnie3.getSod();
		System.out.println("SOD:"); //$NON-NLS-1$
		System.out.println(sod);
		System.out.println();

		// COM
		final Com com = dnie3.getCom();
		System.out.println("COM:"); //$NON-NLS-1$
		System.out.println(com);
		System.out.println();

		// DG01
		final Mrz dg1 = dnie3.getDg1();
		System.out.println("MRZ del DNIe: " + dg1); //$NON-NLS-1$
		System.out.println();

		// DG11
		final byte[] dg11 = dnie3.getDg11();
		System.out.println("DG11"); //$NON-NLS-1$
		System.out.println(HexUtils.hexify(dg11, true));
		System.out.println(new String(dg11));
		System.out.println();

		// DG02
		final byte[] photo = dnie3.getDg2().getSubjectPhotoAsJpeg2k();
		final JFrame framePhoto = new JFrame();
		framePhoto.add(new JLabel(new ImageIcon(ImageIO.read(new ByteArrayInputStream(photo))))); // width = 307 height = 378
		framePhoto.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		framePhoto.pack();
		framePhoto.setVisible(true);

		// DG07
		final byte[] rubric = dnie3.getDg7().getSubjectSignaturePhotoAsJpeg2k();
		final JFrame frameRubric = new JFrame();
		frameRubric.add(new JLabel(new ImageIcon(ImageIO.read(new ByteArrayInputStream(rubric)))));
		frameRubric.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		frameRubric.pack();
		frameRubric.setVisible(true);

		System.out.println("Certificados del DNIe:"); //$NON-NLS-1$
		for (final String alias : dnie3.getAliases()) {
			System.out.println("   " + dnie3.getCertificate(alias).getSubjectX500Principal()); //$NON-NLS-1$
		}

		for (;;) {
			// Vacio, para mantener las imagenes abiertas y visibles
		}

	}

	/** Prueba de lectura del DG13.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDnie3Dg13Parser() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			ProviderUtil.getDefaultConnection(),
			null,
			new BcCryptoHelper(),
			null,
			false
		);
		if (!(dnie instanceof Dnie3)) {
			System.out.println("No es un DNIe v3.0"); //$NON-NLS-1$
			return;
		}
		dnie.openSecureChannelIfNotAlreadyOpened();

		final Dnie3 dnie3 = (Dnie3) dnie;

		final OptionalDetailsDnie3 dnie3Dg13Identity = (OptionalDetailsDnie3) dnie3.getDg13();

		System.out.println("Name: "            + dnie3Dg13Identity.getName());           //$NON-NLS-1$
		System.out.println("Second surname: "  + dnie3Dg13Identity.getSecondSurname());  //$NON-NLS-1$
		System.out.println("First surname: "   + dnie3Dg13Identity.getFirstSurname());   //$NON-NLS-1$
		System.out.println("DNI number: "      + dnie3Dg13Identity.getDniNumber());      //$NON-NLS-1$
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
	@Ignore
	public void testFlexHandler() throws Exception {
		final CallbackHandler cbh = new TestingDnieCallbackHandler(CAN, PIN);
		//final CallbackHandler cbh = new SmartcardCallbackHandler();

		final CustomTextInputCallback custom = new CustomTextInputCallback("customprompt"); //$NON-NLS-1$
		final TextInputCallback java = new TextInputCallback("javaprompt"); //$NON-NLS-1$
		cbh.handle(
			new Callback[] {
				custom,
				java
			}
		);

		Assert.assertEquals("texto", custom.getText()); //$NON-NLS-1$
		Assert.assertEquals("texto", java.getText()); //$NON-NLS-1$
	}

	/** Prueba de lectura de DG en Pasaporte.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testPassportWithBacReadDgs() throws Exception {
		final ApduConnection conn = ProviderUtil.getDefaultConnection();
		System.out.println(HexUtils.hexify(conn.reset(), true));
		System.out.println();
		final IcaoMrtdWithBac passport = new IcaoMrtdWithBac(
			conn,
			new BcCryptoHelper()
		);

		System.out.println();
		System.out.println(passport);
		System.out.println();

		final Com com = passport.getCom();
		System.out.println(com);
		System.out.println();

		final Mrz dg1 = passport.getDg1();
		System.out.println(dg1);
		System.out.println();

		final byte[] dg11 = passport.getDg11();
		System.out.println(new String(dg11));
		System.out.println();
	}

}
