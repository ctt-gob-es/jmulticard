package test.es.gob.jmulticard.ui.passwordcallback;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;

import org.junit.Test;

import de.tsenger.androsmex.mrtd.DG11;
import de.tsenger.androsmex.mrtd.DG1_Dnie;
import de.tsenger.androsmex.mrtd.DG2;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.iso7816four.ReadBinaryApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectDfByNameApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectFileApduResponse;
import es.gob.jmulticard.apdu.iso7816four.SelectFileByIdApduCommand;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.jse.provider.JseCryptoHelper;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;
import es.gob.jmulticard.ui.passwordcallback.gui.DnieCallbackHandler;

/** Pruebas de la obtenci&oacute;n de los objetos dentro del DNIe 3.0.
 * @author Sergio Mart&iacute;nez Rico. */
public final class TestDnieObjects {

    private static final byte[] ID_FILE_3F01;
    private static final byte[] ID_FILE_DG1;
    private static final byte[] ID_FILE_DG2;
    private static final byte[] ID_FILE_DG7;
    private static final byte[] ID_FILE_DG11;
    static {
        ID_FILE_3F01 = new byte[]{63, 1};
        ID_FILE_DG1 = new byte[]{1, 1};
        ID_FILE_DG2 = new byte[]{1, 2};
        ID_FILE_DG7 = new byte[]{1, 7};
        ID_FILE_DG11 = new byte[]{1, 11};
    }
	/** Prueba la obtenci&oacute;n de los objetos del DNIe */
    @SuppressWarnings("static-method")
	@Test
	public void testDnieObjects() throws Exception {
		ApduConnection conn = new SmartcardIoConnection();
		Dnie3 dni = null;

		try {
			dni = (Dnie3) DnieFactory.getDnie(
					conn,
					null,
					new JseCryptoHelper(),
					new DnieCallbackHandler()
				);
		} catch (final Exception e) {
			throw new Exception(e.getMessage());
		}
		conn = dni.openUserChannel();

		//Lectura de MRZ
		ByteArrayOutputStream file = getDnieFileBytes(ID_FILE_DG1, 97, conn);
		try {
	        System.out.println(new DG1_Dnie(file.toByteArray()).getDateOfBirth());
	        System.out.println(new DG1_Dnie(file.toByteArray()).getSex());
		}
		catch(final Exception e) {
        	System.out.println("Error al obtener la informacion del MRZ"); //$NON-NLS-1$
        }

		//Lectura de la imagen del propietario del DNIe
		file = getDnieFileBytes(ID_FILE_DG2, 117, conn);

        try {
        	//Se debe modificar la clase DG2 para quitar los caracteres de encapsulacion y dejarlo en formato jp2
			final InputStream in = new ByteArrayInputStream(new DG2(file.toByteArray()).getImageBytes());
			final BufferedImage bImageFromConvert = ImageIO.read(in);
			System.out.println(bImageFromConvert);
        }
		catch(final Exception e) {
	    	System.out.println("Error al obtener la imagen del propietario del DNIe"); //$NON-NLS-1$
	    }

        //Para el DG3 se obtiene 69-82, no tenemos permisos suficientes

        //Lectura de la imagen de firma
        file = getDnieFileBytes(ID_FILE_DG7, 101, conn);
        try {
        	//Se debe modificar la clase DG7 para quitar los caracteres de encapsulacion y dejarlo en formato jp2
        	final InputStream in = new ByteArrayInputStream(file.toByteArray());
        	final BufferedImage bImageFromConvert = ImageIO.read(in);
        	System.out.println(bImageFromConvert);
        }
        catch(final Exception e) {
        	System.out.println("Error al obtener la imagen de firma"); //$NON-NLS-1$
        }

		//Lectura de datos adicionales
        file = getDnieFileBytes(ID_FILE_DG11, 107, conn);

        try {
        	//Necesaria mejora de la clase DG11 para obtener los campos
        	System.out.println(new DG11(file.toByteArray()).getAddress(3));
	        System.out.println(new DG11(file.toByteArray()).getCustodyInfo());
	        System.out.println(new DG11(file.toByteArray()).getPersonalNumber());
	        System.out.println(new DG11(file.toByteArray()).getPhone());
	        System.out.println(new DG11(file.toByteArray()).getProfession());
        }
        catch(final Exception e) {
        	System.out.println("Error al obtener los datos adicionales"); //$NON-NLS-1$
        }
    }

	private static ByteArrayOutputStream getDnieFileBytes(final byte[] fileId, final int fileTag, final ApduConnection conn) throws IOException {
		try {
            final SelectDfByNameApduCommand selectDFName = new SelectDfByNameApduCommand((byte)0, "Master.File".getBytes()); //$NON-NLS-1$
            ResponseApdu myResponse = conn.transmit(selectDFName);
            final SelectFileByIdApduCommand selectPassport = new SelectFileByIdApduCommand((byte)0, ID_FILE_3F01);
            myResponse = conn.transmit(selectPassport);
            final SelectFileByIdApduCommand selectEFCOM = new SelectFileByIdApduCommand((byte)0, fileId);
            myResponse = conn.transmit(selectEFCOM);
            final SelectFileApduResponse SelectResponse = new SelectFileApduResponse(myResponse);
            final int fileLen = SelectResponse.getFileLength();
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            int off = 0;
            byte msbOffset = 0;
            byte lsbOffset = 0;
            try {
                ByteArrayInputStream inStr = null;
                ResponseApdu readResponse;
                byte tag = 0;
                while (off < fileLen && ((tag = (byte)(inStr = new ByteArrayInputStream((readResponse = readBinary(msbOffset, lsbOffset, (byte)4, conn)).getData())).read()) == fileTag || tag == 103)) {
                    boolean indefinite;
                    int tlvTotalLen = 2;
                    int size = inStr.read() & 255;
                    indefinite = size == 128;
                    if (indefinite) {
                        if ((tag & 32) == 0) {
                            throw new IOException("Longitud del TLV invalida"); //$NON-NLS-1$
                        }
                    } else if (size >= 128) {
                        int sizeLen = size - 128;
                        if (sizeLen > 3) {
                            throw new IOException("TLV demasiado largo"); //$NON-NLS-1$
                        }
                        size = 0;
                        while (sizeLen > 0) {
                            size = (size << 8) + (inStr.read() & 255);
                            --sizeLen;
                            ++tlvTotalLen;
                        }
                    }
                    int dataRead = 0;
                    while (dataRead < size + tlvTotalLen) {
                        final int left = size + tlvTotalLen - dataRead;
                        if (left < 239) {
                            readResponse = readBinary(msbOffset, lsbOffset, (byte)left, conn);
                            dataRead += left;
                            off += left;
                        } else {
                            readResponse = readBinary(msbOffset, lsbOffset, (byte)-17, conn);
                            dataRead += 239;
                            off += 239;
                        }
                        out.write(readResponse.getData());
                        msbOffset = (byte)(off >> 8);
                        lsbOffset = (byte)(off & 255);
                    }
                }
            }
            catch (final Exception e) {
                e.printStackTrace();
                throw new IOException("Error durante lectura del fichero."); //$NON-NLS-1$
            }
            return out;

        }
        catch (final Exception e) {
            e.printStackTrace();
            throw new IOException("Operaci\u00f3n err\u00f3nea durante lectura EF_COM."); //$NON-NLS-1$
        }
	}

	private static ResponseApdu readBinary(final byte msbOffset, final byte lsbOffset, final byte readLength, final ApduConnection conn) throws ApduConnectionException {
        final ResponseApdu res = conn.transmit(new ReadBinaryApduCommand((byte)0, msbOffset, lsbOffset, readLength));
        return res;
    }
}
