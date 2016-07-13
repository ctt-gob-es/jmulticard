package es.gob.jmulticard;

import org.junit.Test;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.card.dnie.Dnie3Dg01Mrz;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.jse.provider.JseCryptoHelper;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de la obtenci&oacute;n de los objetos dentro del DNIe 3.0.
 * @author Sergio Mart&iacute;nez Rico. */
public final class TestDnieObjects {

    private static final byte[] ID_FILE_3F01 = new byte[] { (byte) 0x3f, (byte) 0x1 };
    private static final byte[] ID_FILE_DG02 = new byte[] { (byte) 0x01, (byte) 0x2 };
    private static final byte[] ID_FILE_DG07 = new byte[] { (byte) 0x01, (byte) 0x7 };
    private static final byte[] ID_FILE_DG11 = new byte[] { (byte) 0x01, (byte) 0x0 };

    private static final Location FILE_DG01_LOCATION_MRZ = new Location("3F010101"); //$NON-NLS-1$

    public static void main(final String args[]) throws Exception {
    	new TestDnieObjects().testReadDnieObjects();
    }

	/** Prueba la obtenci&oacute;n de los objetos del DNIe */
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

//		//Lectura de la imagen del propietario del DNIe
//		file = getDnieFileBytes(ID_FILE_DG2, 117, conn);
//
//        try {
//        	//Se debe modificar la clase DG2 para quitar los caracteres de encapsulacion y dejarlo en formato jp2
//			final InputStream in = new ByteArrayInputStream(new DG2(file.toByteArray()).getImageBytes());
//			final BufferedImage bImageFromConvert = ImageIO.read(in);
//			System.out.println(bImageFromConvert);
//        }
//		catch(final Exception e) {
//	    	System.out.println("Error al obtener la imagen del propietario del DNIe"); //$NON-NLS-1$
//	    }
//
//        //Para el DG3 se obtiene 69-82, no tenemos permisos suficientes
//
//        //Lectura de la imagen de firma
//        file = getDnieFileBytes(ID_FILE_DG7, 101, conn);
//        try {
//        	//Se debe modificar la clase DG7 para quitar los caracteres de encapsulacion y dejarlo en formato jp2
//        	final InputStream in = new ByteArrayInputStream(file.toByteArray());
//        	final BufferedImage bImageFromConvert = ImageIO.read(in);
//        	System.out.println(bImageFromConvert);
//        }
//        catch(final Exception e) {
//        	System.out.println("Error al obtener la imagen de firma"); //$NON-NLS-1$
//        }
//
//		//Lectura de datos adicionales
//        file = getDnieFileBytes(ID_FILE_DG11, 107, conn);
//
//        try {
//        	//Necesaria mejora de la clase DG11 para obtener los campos
//        	System.out.println(new DG11(file.toByteArray()).getAddress(3));
//	        System.out.println(new DG11(file.toByteArray()).getCustodyInfo());
//	        System.out.println(new DG11(file.toByteArray()).getPersonalNumber());
//	        System.out.println(new DG11(file.toByteArray()).getPhone());
//	        System.out.println(new DG11(file.toByteArray()).getProfession());
//        }
//        catch(final Exception e) {
//        	System.out.println("Error al obtener los datos adicionales"); //$NON-NLS-1$
//        }
    }
}
