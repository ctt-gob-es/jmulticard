package test.es.gob.jmulticard;

import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.asn1.icao.Com;
import es.gob.jmulticard.asn1.icao.Sod;
import es.gob.jmulticard.card.icao.Mrz;
import es.gob.jmulticard.card.icao.pace.IcaoMrtdWithPace;
import es.gob.jmulticard.jse.provider.ProviderUtil;

/** Pruebas de operaciones en MRTD ICAO.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestIcao {

//	private static final String MRZ =
//			"P<ESPORTEGA<SANCHEZ<<MARIA<ESTHER<<<<<<<<<<<" + //$NON-NLS-1$
//			"XDB4260931ESP7310043F2411129RE20110005121752";  //$NON-NLS-1$

	private static final String MRZ =
			"P<ESPGARCIA<MERAS<CAPOTE<<TOMAS<<<<<<<<<<<<<" + //$NON-NLS-1$
			"PAK1670410ESP7501045M2909233A1183096000<<<02"; //$NON-NLS-1$


	/** Prueba de lectura de DG en Pasaporte con PACE.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testPassportWithPaceReadDgs() throws Exception {

		// ATR = 3B-88-80-01-E1-F3-5E-11-77-83-D7-00-77

		final ApduConnection conn = ProviderUtil.getDefaultConnection();
		System.out.println(HexUtils.hexify(conn.reset(), true));
		System.out.println();
		final IcaoMrtdWithPace passport = new IcaoMrtdWithPace(
			conn,
			new JseCryptoHelper(),
			new TestingDnieCallbackHandler(MRZ, (String)null)
		);

		System.out.println();
		System.out.println(passport);
		System.out.println();

		final Sod sod = passport.getSod();
		System.out.println("SOD:"); //$NON-NLS-1$
		System.out.println(sod);
		System.out.println();

		final Com com = passport.getCom();
		System.out.println("COM:"); //$NON-NLS-1$
		System.out.println(com);
		System.out.println();

		final Mrz dg1 = passport.getDg1();
		System.out.println("MRZ:"); //$NON-NLS-1$
		System.out.println(dg1);
		System.out.println();

		try {
			final byte[] dg = passport.getDg2();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG2: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg3();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG3: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg4();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG4: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg5();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG5: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg6();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG6: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg7();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG7: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg8();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG8: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg9();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG9: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg10();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG10: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg11();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG11: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg12();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG12: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg13();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG13: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg14();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG14: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg15();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG15: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] dg = passport.getDg16();
			System.out.println(new String(dg));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene DG16: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] ca = passport.getCardAccess();
			System.out.println("CardAccess:"); //$NON-NLS-1$
			System.out.println(new String(ca));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene CardAccess: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] cs = passport.getCardSecurity();
			System.out.println("CardSecurity:"); //$NON-NLS-1$
			System.out.println(new String(cs));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene CardSecurity: " + e); //$NON-NLS-1$
		}

		try {
			final byte[] ai = passport.getAtrInfo();
			System.out.println("ATR/INFO:"); //$NON-NLS-1$
			System.out.println(new String(ai));
			System.out.println();
		}
		catch(final Exception e) {
			System.out.println("Este MRTD no tiene ATR/INFO: " + e); //$NON-NLS-1$
		}


	}
}
