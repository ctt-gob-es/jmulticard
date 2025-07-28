/*
 * Controlador Java de la Secretaria de Estado de Administraciones Publicas
 * para el DNI electronico.
 *
 * El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
 * que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
 * para la realizacion de procesos de autenticacion, firma electronica y validacion
 * de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
 * el acceso a los certificados y claves del DNI electronico, asi como la realizacion
 * de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
 * sido disenado para su funcionamiento independiente del sistema operativo final.
 *
 * Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
 * e Impulso de la Administracion Electronica
 *
 * Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
 * o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
 * licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
 * en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
 * su compatibilidad con otros componentes.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * Lesser GNU General Public License publicada por la Free Software Foundation,
 * tanto en la version 2.1 de la Licencia, o en una version posterior.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * European Union Public License publicada por la Comision Europea,
 * tanto en la version 1.1 de la Licencia, o en una version posterior.
 *
 * Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
 *
 * Deberia recibir una copia de la European Union Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
 *
 * Este programa es distribuido con la esperanza de que sea util, pero
 * SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
 * o idoneidad para un proposito particular.
 */
package es.gob.jmulticard.jse.smartcardio;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.dnie.VerifyApduCommand;
import es.gob.jmulticard.connection.AbstractApduConnectionIso7816;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.ApduConnectionProtocol;
import es.gob.jmulticard.connection.CardNotPresentException;
import es.gob.jmulticard.connection.LostChannelException;
import es.gob.jmulticard.connection.NoReadersFoundException;

/** Conexi&oacute;n con lector de tarjetas inteligentes implementado sobre
 * JSR-268 SmartCard I/O.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SmartcardIoConnection extends AbstractApduConnectionIso7816 {

	private static final boolean DEBUG = false;

	/**
	 * Tama&ntilde;o m&aacute;ximo de las APDU.
	 * Por encima de este tama&ntilde;o, se hace autom&aacute;ticamente
	 * una envoltura en varias APDU.
	 */
	private static final int MAX_APDU_SIZE = 0xFF;

    /**
     * Constante para la indicaci&oacute;n de que se ha detectado un
     * reinicio del canal con la tarjeta.
     */
    private static final String SCARD_W_RESET_CARD = "SCARD_W_RESET_CARD"; //$NON-NLS-1$

    /**
     * Propiedad del sistema con la que configurar que se ignoren los lectores de
     * tarjeta que se reconozcan como lectores virtuales.
     */
    private static final String SYSTEM_PROPERTY_IGNORE_VIRTUAL_READERS = "ignoreVirtualReaders"; //$NON-NLS-1$

    private static final Logger LOGGER = Logger.getLogger(SmartcardIoConnection.class.getName());

    private int terminalNumber = -1;

	private CardChannel cardChannel = null;

    private Card card = null;

    private boolean exclusive = false;

    private ApduConnectionProtocol protocol = ApduConnectionProtocol.ANY;

    List<CardTerminal> terminales = null;

    static {

		// Aplicamos un parche para el error de PCSCLite de Debian:
		// https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=529339
    	try {
    		LibJ2PCSCGNULinuxFix.fixNativeLibrary();
    	}
    	catch(final Exception | Error e) {
    		LOGGER.warning(
				"No se han podido aplicar las correcciones al error 529339 de Debian: " + e //$NON-NLS-1$
			);
    	}

    	// Aplicamos un parche para el error JDK-8255877 de Java: https://bugs.openjdk.java.net/browse/JDK-8255877
    	final String osName = System.getProperty("os.name"); //$NON-NLS-1$
		if (
			osName != null &&
			osName.startsWith("Mac OS X") && //$NON-NLS-1$
			new File("/System/Library/Frameworks/PCSC.framework/Versions/Current").isDirectory() //$NON-NLS-1$
		) {
			System.setProperty(
				"sun.security.smartcardio.library", //$NON-NLS-1$
				"/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC" //$NON-NLS-1$
			);
		}
    }

    /** Constructor por defecto. */
    public SmartcardIoConnection() {
    	// Vacio
    }

    @Override
	  public String toString() {
    	return "Conexion de bajo nivel JSR-268 " + //$NON-NLS-1$
			(isOpen()
				? "abierta en modo " + (this.exclusive ? "" : "no") + " exclusivo" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
					: "cerrada"); //$NON-NLS-1$
    }

    @Override
    public void close() throws ApduConnectionException {
    	if (this.card != null) {
	        try {
	            this.card.disconnect(false);
	        }
	        catch (final Exception e) {
	            throw new ApduConnectionException(
	                "Error intentando cerrar el objeto de tarjeta inteligente, la conexion puede quedar abierta pero inutil", e //$NON-NLS-1$
	            );
	        }
	        this.card = null;
    	}
        this.cardChannel = null;
    }

    /** {@inheritDoc} */
    @Override
    public String getTerminalInfo(final int terminal) throws ApduConnectionException {
        try {
            final List<CardTerminal> terminalList = getTerminals();
            if (terminal < terminalList.size()) {
                final CardTerminal cardTerminal = terminalList.get(terminal);
                if (cardTerminal != null) {
                    return cardTerminal.getName();
                }
            }

            return null;
        }
        catch (final Exception ex) {
            throw new ApduConnectionException(
        		"Error recuperando la lista de lectores de tarjetas del sistema", ex //$NON-NLS-1$
    		);
        }
    }

    private List<CardTerminal> getTerminals() {

    	if (this.terminales != null) {
    		return this.terminales;
    	}

    	try {
    		this.terminales = TerminalFactory.getDefault().terminals().list();
    	}
    	catch(final CardException e) {
    		LOGGER.log(
				Level.WARNING,
				"No se ha podido recuperar la lista de lectores del sistema", //$NON-NLS-1$
				e
			);
    		return Collections.emptyList();
    	}

    	final boolean ignoreVirtualReaders = Boolean.getBoolean(SYSTEM_PROPERTY_IGNORE_VIRTUAL_READERS);
    	if (ignoreVirtualReaders) {
    		final List<CardTerminal> filteredList = new ArrayList<>();
    		for (final CardTerminal terminal : this.terminales) {
    			if (!isVirtual(terminal)) {
    				filteredList.add(terminal);
    			}
    		}
    		this.terminales = filteredList;
    	}

    	return this.terminales;
    }

    /**
     * Identifica si se trata de un lector de tarjetas virtual.
     * @param terminal Lector de tarjetas.
     * @return {@code true} si se trata de un lector virtual,
     * {@code false} en caso contrario.
     */
    private static boolean isVirtual(final CardTerminal terminal) {

    	final String name = terminal.getName();

    	// Ignoramos Windows Hello, el sistema de inicio de sesion de Microsoft (C)
    	return name != null && name.startsWith("Windows Hello"); //$NON-NLS-1$
	}

	@Override
    public long[] getTerminals(final boolean onlyWithCardPresent) throws ApduConnectionException {

		final List<CardTerminal> terminalList = getTerminals();
        try {
        	// Listamos los indices de los lectores que correspondan segun si tienen o no tarjeta insertada
        	final ArrayList<Long> idsTerminales = new ArrayList<>(terminalList.size());
        	for (int idx = 0; idx < terminalList.size(); idx++) {
        		if (onlyWithCardPresent) {
        			if (terminalList.get(idx).isCardPresent()) {
        				idsTerminales.add(Long.valueOf(idx));
        			}
        		}
        		else {
        			idsTerminales.add(Long.valueOf(idx));
        		}
        	}

        	final long[] ids = new long[idsTerminales.size()];
        	for (int i = 0; i < ids.length; i++) {
        		ids[i] = idsTerminales.get(i).longValue();
        	}
        	return ids;
        }
        catch (final Exception ex) {
            throw new ApduConnectionException(
        		"Error recuperando la lista de lectores de tarjetas del sistema", ex //$NON-NLS-1$
    		);
        }
    }

    @Override
    public boolean isOpen() {
        return this.card != null;
    }

    @Override
    public void open() throws ApduConnectionException {

    	if (isOpen()) {
    		return;
    	}

        // Desactivamos las respuestas automaticas para evitar los problemas con el canal seguro
        System.setProperty("sun.security.smartcardio.t0GetResponse", "false"); //$NON-NLS-1$ //$NON-NLS-2$
        System.setProperty("sun.security.smartcardio.t1GetResponse", "false"); //$NON-NLS-1$ //$NON-NLS-2$

        final List<CardTerminal> terminalList = getTerminals();
        try {
            if (terminalList.isEmpty()) {
                throw new NoReadersFoundException();
            }
            if (this.terminalNumber == -1) {
            	final long[] cadsWithCard = getTerminals(true);
            	if (cadsWithCard.length <= 0) {
            		throw new ApduConnectionException(
        				"En el sistema no hay ningun terminal con tarjeta insertada" //$NON-NLS-1$
    				);
            	}
				this.terminalNumber = (int) cadsWithCard[0];
            }
            if (terminalList.size() <= this.terminalNumber) {
                throw new ApduConnectionException(
            		"No se detecto el lector de tarjetas numero " + this.terminalNumber //$NON-NLS-1$
        		);
            }
            this.card = terminalList.get(this.terminalNumber).connect(this.protocol.toString());
        }
        catch(final javax.smartcardio.CardNotPresentException e) {
            throw new CardNotPresentException(e);
        }
        catch (final CardException e) {
            throw new ApduConnectionException(
                "No se ha podido abrir la conexion con el lector de tarjetas numero " + this.terminalNumber, e  //$NON-NLS-1$
    		);
        }

        if (this.exclusive) {
            try {
                this.card.beginExclusive();
            }
            catch (final CardException e) {
                throw new ApduConnectionException(
                    "No se ha podido abrir la conexion exclusiva con el lector de tarjetas numero " + Integer.toString(this.terminalNumber), e //$NON-NLS-1$
                );
            }
        }
        this.cardChannel = this.card.getBasicChannel();
        this.protocol = ApduConnectionProtocol.getApduConnectionProtocol(this.card.getProtocol());
    }

    @Override
    public byte[] reset() throws ApduConnectionException {
    	if (this.card != null) {
	    	try {
				this.card.disconnect(true);
			}
	    	catch (final CardException e) {
				LOGGER.warning("Error reiniciando la tarjeta: " + e); //$NON-NLS-1$
			}
    	}
    	this.card = null;
        open();
        if (this.card != null) {
            return this.card.getATR().getBytes();
        }
        throw new ApduConnectionException("Error indefinido reiniciando la conexion con la tarjeta"); //$NON-NLS-1$
    }

    /** Establece si la conexi&oacute;n se debe abrir en modo exclusivo.
     * Solo puede establecerse si la conexi&oacute;n aun no ha sido abierta.
     * @param ex <code>true</code> para abrir la conexi&oacute;n en modo
     *           exclusivo, <code>false</code> para abrirla en modo no
     *           exclusivo. */
    public void setExclusiveUse(final boolean ex) {
        if (this.card == null) {
            this.exclusive = ex;
        }
        else {
            LOGGER.warning(
                "No se puede cambiar el modo de acceso a la tarjeta con la conexion abierta, se mantendra el modo EXCLUSIVE=" + Boolean.toString(this.exclusive) //$NON-NLS-1$
            );
        }
    }

    /** Establece el protocolo de conexi&oacute;n con la tarjeta.
     * Por defecto, si no se establece ninguno, se indica <i>*</i> para que sea el API subyancente el
     * que detecte el apropiado.
     * @param p Protocolo de conexi&oacute;n con la tarjeta. */
    @Override
	public void setProtocol(final ApduConnectionProtocol p) {
        if (p == null) {
            LOGGER.warning(
                "El protocolo de conexion no puede ser nulo, se usara T=0" //$NON-NLS-1$
            );
            this.protocol = ApduConnectionProtocol.T0;
            return;
        }
        this.protocol = p;
    }

    @Override
    public void setTerminal(final int terminalN) {
        if (this.terminalNumber == terminalN) {
            return;
        }

        final boolean wasOpened = isOpen();

        this.terminalNumber = terminalN;

        if (wasOpened) {
            try {
            	// El cierre no mira el terminalNumber, no pasa nada por cambiarlo antes de llamar a close()
                close();
            }
            catch (final ApduConnectionException e) {
                LOGGER.warning(
                    "Error intentando cerrar la conexion con el lector: " + e //$NON-NLS-1$
        		);
            }
            try {
            	open();
            }
            catch (final Exception e) {
            	LOGGER.warning("Error intentando abrir la conexion con el lector: " + e); //$NON-NLS-1$
            }
        }
    }

    @Override
    public ResponseApdu internalTransmit(final byte[] command) throws ApduConnectionException {

        if (this.cardChannel == null) {
            throw new ApduConnectionException(
                "No se puede transmitir sobre una conexion cerrada" //$NON-NLS-1$
            );
        }

    	final CommandAPDU commandApdu = new CommandAPDU(command);
    	// Miramos si es un CHV para que nunca aparezca el PIN en ningun log
    	final boolean isChv = commandApdu.getINS() == VerifyApduCommand.INS_VERIFY;

        if (DEBUG) {
        	LOGGER.info(
    			"Se va a enviar la APDU" + //$NON-NLS-1$
					(isChv ? " de verificacion de PIN" : //$NON-NLS-1$
						":\n" + HexUtils.hexify(command, command.length > 32)) // En APDU mayores de 32 octetos separamos lineas y octetos //$NON-NLS-1$
			);
        }

        try {
        	final ResponseApdu response = new ResponseApdu(
				this.cardChannel.transmit(commandApdu).getBytes()
			);
            if (DEBUG) {
            	LOGGER.info(
        			"Respuesta:\n" + //$NON-NLS-1$
						HexUtils.hexify(response.getBytes(), command.length > 32) // En APDU mayores de 32 octetos separamos lineas y octetos
				);
            }
            return response;
        }
        catch (final CardException e) {
            final Throwable t = e.getCause();
            if (t != null && SCARD_W_RESET_CARD.equals(t.getMessage())) {
                throw new LostChannelException(t.getMessage(), t);
            }
            throw new ApduConnectionException(
                "Error de comunicacion con la tarjeta tratando de transmitir la APDU" +  //$NON-NLS-1$
                	(isChv ? " de verificacion de PIN" : //$NON-NLS-1$
            		"\n" + HexUtils.hexify(command, command.length > 32) + //$NON-NLS-1$
            			"\nAl lector " + Integer.toString(this.terminalNumber) + //$NON-NLS-1$
            				" en modo EXCLUSIVE=" + //$NON-NLS-1$
            					Boolean.toString(this.exclusive) +
            						" con el protocolo " + getProtocol()), e //$NON-NLS-1$
            );
        }
        catch (final Exception e) {
            throw new ApduConnectionException(
                    "Error de comunicacion con la tarjeta tratando de transmitir la APDU" +  //$NON-NLS-1$
                        	(isChv ? " de verificacion de PIN" : //$NON-NLS-1$
                    		"\n" + HexUtils.hexify(command, command.length > 32) + //$NON-NLS-1$
                    			"\nAl lector " + Integer.toString(this.terminalNumber) + //$NON-NLS-1$
                    				" en modo EXCLUSIVE=" + //$NON-NLS-1$
                    					Boolean.toString(this.exclusive) +
                    						" con el protocolo " + getProtocol()), e //$NON-NLS-1$
            );
        }
    }

    /** Devuelve el protocolo de conexi&oacute;n con la tarjeta usado actualmente.
     * @return Un objeto de tipo enumerado <code>ConnectionProtocol</code>. */
    public ApduConnectionProtocol getProtocol() {
        return this.protocol;
    }

    /** Indica si la conexi&oacute;n con la tarjeta se ha establecido en modo exclusivo o no.
     * @return <code>true</code> si la conexi&oacute;n est&aacute; establecida en modo exclusivo. */
    public boolean isExclusiveUse() {
        return this.exclusive;
    }

	@Override
	public ApduConnection getSubConnection() {
		// Esta conexion es siempre la de mas bajo nivel
		return null;
	}

	@Override
	public int getMaxApduSize() {
		return MAX_APDU_SIZE;
	}
}