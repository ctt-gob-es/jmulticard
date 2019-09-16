package es.gob.jmulticard;

import java.io.ByteArrayInputStream;

import javax.imageio.ImageIO;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.TextInputCallback;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.callback.CustomTextInputCallback;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.card.dnie.Dnie3Dg01Mrz;
import es.gob.jmulticard.card.dnie.Dnie3Dg13Identity;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.card.dnie.DnieSubjectPrincipalParser;
import es.gob.jmulticard.card.dnie.SpanishPassportWithBac;
import es.gob.jmulticard.card.dnie.SpanishPassportWithPace;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de operaciones en DNIe sin PIN.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestDnieLow {

//	private static final String MRZ = ""; //$NON-NLS-1$
	private static final String CAN = ""; //$NON-NLS-1$

	private static final String PIN = ""; //$NON-NLS-1$

	/** Prueba de lectura sin PIN de los datos del titular.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDnieReadSubject() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			new SmartcardIoConnection(),
			null,
			new JseCryptoHelper(),
			null,
			false
		);
		final Cdf cdf = dnie.getCdf();
		System.out.println(cdf);
		System.out.println();
		System.out.println(new DnieSubjectPrincipalParser(cdf.getCertificateSubjectPrincipal(0)));
	}

	/** Prueba directa de firma.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDnieSign() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			new SmartcardIoConnection(),
			null,
			new JseCryptoHelper(),
			new TestingDnieCallbackHandler(CAN, PIN),
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

	/** Prueba de lectura de DG en DNIe 3.0.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDnieReadDgs() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			new SmartcardIoConnection(),
			null,
			new JseCryptoHelper(),
			new TestingDnieCallbackHandler(CAN, PIN),
			false
		);
		System.out.println();
		System.out.println(dnie);
		System.out.println();
		if (!(dnie instanceof Dnie3)) {
			System.out.println("No es un DNIe v3.0"); //$NON-NLS-1$
			return;
		}

		// Abrimos canal seguro sin vertificar el PIN
		dnie.openSecureChannelIfNotAlreadyOpened(false);

		final Dnie3 dnie3 = (Dnie3) dnie;

		// DG01
		final Dnie3Dg01Mrz dg1 = dnie3.getMrz();
		System.out.println("MRZ del DNIe: " + dg1); //$NON-NLS-1$
		System.out.println();

		// DG11
		final byte[] dg11 = dnie3.getDg11();
		System.out.println(new String(dg11));
		System.out.println();

		// DG02
		final byte[] photo = dnie3.getSubjectPhotoAsJpeg2k();
		final JFrame framePhoto = new JFrame();
		framePhoto.add(new JLabel(new ImageIcon(ImageIO.read(new ByteArrayInputStream(photo))))); // width = 307 height = 378
		framePhoto.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		framePhoto.pack();
		framePhoto.setVisible(true);

		// DG07
		final byte[] rubric = dnie3.getSubjectSignatureImageAsJpeg2k();
		final JFrame frameRubric = new JFrame();
		frameRubric.add(new JLabel(new ImageIcon(ImageIO.read(new ByteArrayInputStream(rubric)))));
		frameRubric.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frameRubric.pack();
		frameRubric.setVisible(true);

		System.out.println("Certificados del DNIe:"); //$NON-NLS-1$
		for (final String alias : dnie3.getAliases()) {
			System.out.println("   " + AOUtil.getCN(dnie3.getCertificate(alias))); //$NON-NLS-1$
		}

		for (;;) {
			// Vacio, para mantener las imagenes abiertas y visibles
		}

	}

	/** Prueba de lectura del DG13.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	//@Ignore
	public void testDnie3Dg13Parser() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
				new SmartcardIoConnection(),
				null,
				new JseCryptoHelper(),
				null,
				false
		);
		if (!(dnie instanceof Dnie3)) {
			System.out.println("No es un DNIe v3.0"); //$NON-NLS-1$
			return;
		}
		dnie.openSecureChannelIfNotAlreadyOpened();

		final Dnie3 dnie3 = (Dnie3) dnie;

		final Dnie3Dg13Identity dnie3Dg13Identity = dnie3.getIdentity();

		System.out.println("Name: " + dnie3Dg13Identity.getName()); //$NON-NLS-1$
		System.out.println("Second surname: " + dnie3Dg13Identity.getSecondSurname()); //$NON-NLS-1$
		System.out.println("First surname: " + dnie3Dg13Identity.getFirstSurname()); //$NON-NLS-1$
		System.out.println("DNI number: " + dnie3Dg13Identity.getDniNumber()); //$NON-NLS-1$
		System.out.println("Birth date: " + dnie3Dg13Identity.getBirthDate()); //$NON-NLS-1$
		System.out.println("Nationality: " + dnie3Dg13Identity.getNationality()); //$NON-NLS-1$
		System.out.println("Expiration date: " + dnie3Dg13Identity.getExpirationDate()); //$NON-NLS-1$
		System.out.println("Support number: " + dnie3Dg13Identity.getSupportNumber()); //$NON-NLS-1$
		System.out.println("Sex: " + dnie3Dg13Identity.getSex()); //$NON-NLS-1$
		System.out.println("Birth city: " + dnie3Dg13Identity.getBirthCity()); //$NON-NLS-1$
		System.out.println("Birth country: " + dnie3Dg13Identity.getBirthCountry()); //$NON-NLS-1$
		System.out.println("Parent's names: " + dnie3Dg13Identity.getParentsNames()); //$NON-NLS-1$
		System.out.println("Address: " + dnie3Dg13Identity.getAddress()); //$NON-NLS-1$
		System.out.println("City: " + dnie3Dg13Identity.getCity()); //$NON-NLS-1$
		System.out.println("Province: " + dnie3Dg13Identity.getProvince()); //$NON-NLS-1$
		System.out.println("Country: " + dnie3Dg13Identity.getCountry()); //$NON-NLS-1$
	}

	/** Prueba de <code>CallbackHandler</code> con distintas clases para <code>TextInputCallback</code>.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testFlexHandler() throws Exception {
		final CallbackHandler cbh = new TestingDnieCallbackHandler(CAN, PIN);

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
	public void testPassportReadDgs() throws Exception {
		final ApduConnection conn = new SmartcardIoConnection();
		System.out.println(HexUtils.hexify(conn.reset(), true));
		System.out.println();
		final SpanishPassportWithBac passport = new SpanishPassportWithBac(
			conn,
			new JseCryptoHelper()
		);

		System.out.println();
		System.out.println(passport);
		System.out.println();

		final byte[] com = passport.getCOM();
		System.out.println(new String(com));
		System.out.println();

		final Dnie3Dg01Mrz dg1 = passport.getMrz();
		System.out.println(dg1);
		System.out.println();

		final byte[] dg11 = passport.getDg11();
		System.out.println(new String(dg11));
		System.out.println();

	}

	/** Prueba de lectura de DG en Pasaporte con PACE.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testPassportWithPaceReadDgs() throws Exception {

		// ATR = 3B-88-80-01-E1-F3-5E-11-77-83-D7-00-77

		final ApduConnection conn = new SmartcardIoConnection();
		System.out.println(HexUtils.hexify(conn.reset(), true));
		System.out.println();
		final SpanishPassportWithPace passport = new SpanishPassportWithPace(
			conn,
			new JseCryptoHelper(),
			new TestingDnieCallbackHandler(CAN, PIN)
		);

		System.out.println();
		System.out.println(passport);
		System.out.println();

		final byte[] com = passport.getCOM();
		System.out.println(new String(com));
		System.out.println();

		final Dnie3Dg01Mrz dg1 = passport.getMrz();
		System.out.println(dg1);
		System.out.println();

		final byte[] dg11 = passport.getDg11();
		System.out.println(new String(dg11));
		System.out.println();

	}
}
