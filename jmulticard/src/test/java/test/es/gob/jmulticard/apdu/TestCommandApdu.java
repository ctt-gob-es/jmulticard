package test.es.gob.jmulticard.apdu;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.dnie.GetChipInfoApduCommand;

/** Prueba de {@linkplain es.gob.jmulticard.apdu.CommandApdu#setLe(int)} de
 * la clase {@linkplain es.gob.jmulticard.apdu.CommandApdu}
 * @author Alberto Mart&iacute;nez. */
class TestCommandApdu {

    /** {@linkplain es.gob.jmulticard.apdu.CommandApdu#setLe(int)} */
	@SuppressWarnings("static-method")
	@Test
    final void testSetLe() {
        final CommandApdu command = new GetChipInfoApduCommand();
        command.setLe(0);
        Assertions.assertNotNull(command);
    }
}