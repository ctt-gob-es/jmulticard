package es.gob.jmulticard;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.imageio.ImageIO;

import org.junit.Test;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.card.dnie.Dnie3Dg01Mrz;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.jse.provider.JseCryptoHelper;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de la obtenci&oacute;n de los objetos dentro del DNIe 3.0.
 * @author Sergio Mart&iacute;nez Rico. */
public final class TestDnieObjects {

    private static final Location FILE_DG01_LOCATION_MRZ   = new Location("3F010101"); //$NON-NLS-1$
    private static final Location FILE_DG02_LOCATION_PHOTO = new Location("3F010102"); //$NON-NLS-1$
    private static final Location FILE_DG07_LOCATION_SIGN  = new Location("3F010107"); //$NON-NLS-1$

    /** No vamos a leer este fichero, todo lo que da esta en el MRZ. */
    private static final Location FILE_DG11_LOCATION_DATA  = new Location("3F01010B"); //$NON-NLS-1$

    private static final String JPEG2K_HEADER = "0000000C6A502020"; //$NON-NLS-1$

    private static final BufferedImage extractImage(final byte[] photo) throws IOException {
    	if (photo == null) {
    		throw new IllegalArgumentException("Los datos de entrada no pueden ser nulos"); //$NON-NLS-1$
    	}
    	final int headerSize = (HexUtils.hexify(photo, false).indexOf(JPEG2K_HEADER) / 2);
    	final byte[] pj2kPhoto = new byte[photo.length - headerSize];
        System.arraycopy(photo, headerSize, pj2kPhoto, 0, pj2kPhoto.length);
        return ImageIO.read(new ByteArrayInputStream(pj2kPhoto));
    }

    public static void main(final String args[]) throws Exception {
    	new TestDnieObjects().testReadDnieObjects();
    }

	/** Prueba la obtenci&oacute;n de los objetos del DNIe
	 * @throws Exception En cualquier error. */
    @SuppressWarnings("static-method")
	@Test
	public void testReadDnieObjects() throws Exception {
		ApduConnection conn = new SmartcardIoConnection();

		final Dnie3 dni = (Dnie3) DnieFactory.getDnie(
				conn,
				null,
				new JseCryptoHelper(),
				null
		);
		conn = dni.openUserChannel();

		final byte[] mrz = dni.selectFileByLocationAndRead(FILE_DG01_LOCATION_MRZ);

        System.out.println(new Dnie3Dg01Mrz(mrz).getNationality());
        System.out.println(new Dnie3Dg01Mrz(mrz).getSex());

        final byte[] photo = dni.selectFileByLocationAndRead(FILE_DG02_LOCATION_PHOTO);
        System.out.println(extractImage(photo));

        final byte[] sign = dni.selectFileByLocationAndRead(FILE_DG07_LOCATION_SIGN);
        System.out.println(extractImage(sign));

        final byte[] data = dni.selectFileByLocationAndRead(FILE_DG11_LOCATION_DATA);
        final Tlv tlv = new Tlv(data);
        System.out.println("TLV: " + HexUtils.hexify(tlv.getValue(), false));
        final Tlv tlv2 = new Tlv(tlv.getValue());
        System.out.println("TAG: " + tlv2.getTag());
        System.out.println("VAL: " + HexUtils.hexify(tlv2.getValue(), false));

    }
}
