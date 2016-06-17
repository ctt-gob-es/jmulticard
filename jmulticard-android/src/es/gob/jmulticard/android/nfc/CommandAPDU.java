package es.gob.jmulticard.android.nfc;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.Arrays;

public final class CommandAPDU
implements Serializable {
    private static final long serialVersionUID = 398698301286670877L;
    private static final int MAX_APDU_SIZE = 65544;
    private byte[] apdu;
    private transient int nc;
    private transient int ne;
    private transient int dataOffset;

    public CommandAPDU(final byte[] apdu) {
        this.apdu = apdu.clone();
        this.parse();
    }

    public CommandAPDU(final byte[] apdu, final int apduOffset, final int apduLength) {
        this.checkArrayBounds(apdu, apduOffset, apduLength);
        this.apdu = new byte[apduLength];
        System.arraycopy(apdu, apduOffset, this.apdu, 0, apduLength);
        this.parse();
    }

    private void checkArrayBounds(final byte[] b, final int ofs, final int len) {
        if (ofs < 0 || len < 0) {
            throw new IllegalArgumentException("Offset and length must not be negative");
        }
        if (b == null) {
            if (ofs != 0 && len != 0) {
                throw new IllegalArgumentException("offset and length must be 0 if array is null");
            }
        } else if (ofs > b.length - len) {
            throw new IllegalArgumentException("Offset plus length exceed array size");
        }
    }

    public CommandAPDU(final ByteBuffer apdu) {
        this.apdu = new byte[apdu.remaining()];
        apdu.get(this.apdu);
        this.parse();
    }

    public CommandAPDU(final int cla, final int ins, final int p1, final int p2) {
        this(cla, ins, p1, p2, null, 0, 0, 0);
    }

    public CommandAPDU(final int cla, final int ins, final int p1, final int p2, final int ne) {
        this(cla, ins, p1, p2, null, 0, 0, ne);
    }

    public CommandAPDU(final int cla, final int ins, final int p1, final int p2, final byte[] data) {
        this(cla, ins, p1, p2, data, 0, CommandAPDU.arrayLength(data), 0);
    }

    public CommandAPDU(final int cla, final int ins, final int p1, final int p2, final byte[] data, final int dataOffset, final int dataLength) {
        this(cla, ins, p1, p2, data, dataOffset, dataLength, 0);
    }

    public CommandAPDU(final int cla, final int ins, final int p1, final int p2, final byte[] data, final int ne) {
        this(cla, ins, p1, p2, data, 0, CommandAPDU.arrayLength(data), ne);
    }

    private static int arrayLength(final byte[] b) {
        return b != null ? b.length : 0;
    }

    private void parse() {
        if (this.apdu.length < 4) {
            throw new IllegalArgumentException("apdu must be at least 4 bytes long");
        }
        if (this.apdu.length == 4) {
            return;
        }
        final int l1 = this.apdu[4] & 255;
        if (this.apdu.length == 5) {
            this.ne = l1 == 0 ? 256 : l1;
            return;
        }
        if (l1 != 0) {
            if (this.apdu.length == 5 + l1) {
                this.nc = l1;
                this.dataOffset = 5;
                return;
            }
            if (this.apdu.length == 6 + l1) {
                this.nc = l1;
                this.dataOffset = 5;
                final int l2 = this.apdu[this.apdu.length - 1] & 255;
                this.ne = l2 == 0 ? 256 : l2;
                return;
            }
            throw new IllegalArgumentException("Invalid APDU: length=" + this.apdu.length + ", b1=" + l1);
        }
        if (this.apdu.length < 7) {
            throw new IllegalArgumentException("Invalid APDU: length=" + this.apdu.length + ", b1=" + l1);
        }
        final int l2 = (this.apdu[5] & 255) << 8 | this.apdu[6] & 255;
        if (this.apdu.length == 7) {
            this.ne = l2 == 0 ? 65536 : l2;
            return;
        }
        if (l2 == 0) {
            throw new IllegalArgumentException("Invalid APDU: length=" + this.apdu.length + ", b1=" + l1 + ", b2||b3=" + l2);
        }
        if (this.apdu.length == 7 + l2) {
            this.nc = l2;
            this.dataOffset = 7;
            return;
        }
        if (this.apdu.length != 9 + l2) {
            throw new IllegalArgumentException("Invalid APDU: length=" + this.apdu.length + ", b1=" + l1 + ", b2||b3=" + l2);
        }
        this.nc = l2;
        this.dataOffset = 7;
        final int leOfs = this.apdu.length - 2;
        final int l3 = (this.apdu[leOfs] & 255) << 8 | this.apdu[leOfs + 1] & 255;
        this.ne = l3 == 0 ? 65536 : l3;
    }

    public CommandAPDU(final int cla, final int ins, final int p1, final int p2, final byte[] data, final int dataOffset, final int dataLength, final int ne) {
        this.checkArrayBounds(data, dataOffset, dataLength);
        if (dataLength > 65535) {
            throw new IllegalArgumentException("dataLength is too large");
        }
        if (ne < 0) {
            throw new IllegalArgumentException("ne must not be negative");
        }
        if (ne > 65536) {
            throw new IllegalArgumentException("ne is too large");
        }
        this.ne = ne;
        this.nc = dataLength;
        if (dataLength == 0) {
            if (ne == 0) {
                this.apdu = new byte[4];
                this.setHeader(cla, ins, p1, p2);
            } else if (ne <= 256) {
                final byte len = ne != 256 ? (byte)ne : 0;
                this.apdu = new byte[5];
                this.setHeader(cla, ins, p1, p2);
                this.apdu[4] = len;
            } else {
                byte l2;
                byte l1;
                if (ne == 65536) {
                    l1 = 0;
                    l2 = 0;
                } else {
                    l1 = (byte)(ne >> 8);
                    l2 = (byte)ne;
                }
                this.apdu = new byte[7];
                this.setHeader(cla, ins, p1, p2);
                this.apdu[5] = l1;
                this.apdu[6] = l2;
            }
        } else if (ne == 0) {
            if (dataLength <= 255) {
                this.apdu = new byte[5 + dataLength];
                this.setHeader(cla, ins, p1, p2);
                this.apdu[4] = (byte)dataLength;
                this.dataOffset = 5;
                System.arraycopy(data, dataOffset, this.apdu, 5, dataLength);
            } else {
                this.apdu = new byte[7 + dataLength];
                this.setHeader(cla, ins, p1, p2);
                this.apdu[4] = 0;
                this.apdu[5] = (byte)(dataLength >> 8);
                this.apdu[6] = (byte)dataLength;
                this.dataOffset = 7;
                System.arraycopy(data, dataOffset, this.apdu, 7, dataLength);
            }
        } else if (dataLength <= 255 && ne <= 256) {
            this.apdu = new byte[6 + dataLength];
            this.setHeader(cla, ins, p1, p2);
            this.apdu[4] = (byte)dataLength;
            this.dataOffset = 5;
            System.arraycopy(data, dataOffset, this.apdu, 5, dataLength);
            this.apdu[this.apdu.length - 1] = ne != 256 ? (byte)ne : 0;
        } else {
            this.apdu = new byte[9 + dataLength];
            this.setHeader(cla, ins, p1, p2);
            this.apdu[4] = 0;
            this.apdu[5] = (byte)(dataLength >> 8);
            this.apdu[6] = (byte)dataLength;
            this.dataOffset = 7;
            System.arraycopy(data, dataOffset, this.apdu, 7, dataLength);
            if (ne != 65536) {
                final int leOfs = this.apdu.length - 2;
                this.apdu[leOfs] = (byte)(ne >> 8);
                this.apdu[leOfs + 1] = (byte)ne;
            }
        }
    }

    private void setHeader(final int cla, final int ins, final int p1, final int p2) {
        this.apdu[0] = (byte)cla;
        this.apdu[1] = (byte)ins;
        this.apdu[2] = (byte)p1;
        this.apdu[3] = (byte)p2;
    }

    public int getCLA() {
        return this.apdu[0] & 255;
    }

    public int getINS() {
        return this.apdu[1] & 255;
    }

    public int getP1() {
        return this.apdu[2] & 255;
    }

    public int getP2() {
        return this.apdu[3] & 255;
    }

    public int getNc() {
        return this.nc;
    }

    public byte[] getData() {
        final byte[] data = new byte[this.nc];
        System.arraycopy(this.apdu, this.dataOffset, data, 0, this.nc);
        return data;
    }

    public int getNe() {
        return this.ne;
    }

    public byte[] getBytes() {
        return this.apdu.clone();
    }

    @Override
	public String toString() {
        return "CommmandAPDU: " + this.apdu.length + " bytes, nc=" + this.nc + ", ne=" + this.ne;
    }

    @Override
	public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CommandAPDU)) {
            return false;
        }
        final CommandAPDU other = (CommandAPDU)obj;
        return Arrays.equals(this.apdu, other.apdu);
    }

    @Override
	public int hashCode() {
        return Arrays.hashCode(this.apdu);
    }

    private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.apdu = (byte[])in.readUnshared();
        this.parse();
    }
}


