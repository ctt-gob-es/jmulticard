package es.gob.jmulticard.card.dnie;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Pattern;

public final class Dnie3Dg13Identity {

  /** This regEx matches on every pair (word) of control character (0x00-0x1F and 0x7F-0x9F) */
  private static final Pattern CONTROL_CHARACTER_WORD = Pattern.compile("\\p{Cc}{2}");

  private final SimpleDateFormat dateFormat = new SimpleDateFormat("dd MM yyyy");
  private final String[] parsedValues;

  Dnie3Dg13Identity(final byte[] dg13RawData) {
    parsedValues = new String(dg13RawData).split(CONTROL_CHARACTER_WORD.pattern());
  }

  public String getName() {
    return parsedValues[1];
  }

  public String getSecondName() {
    return parsedValues[2];
  }

  public String getFirstName() {
    return parsedValues[3];
  }

  public String getDniNumber() {
    return parsedValues[4];
  }

  public Date getBirthDate() throws ParseException {
    return dateFormat.parse(parsedValues[5]);
  }

  public String getNationality() {
    return parsedValues[6];
  }

  public Date getExpirationDate() throws ParseException {
    return dateFormat.parse(parsedValues[7]);
  }

  public String getSupportNumber() {
    return parsedValues[8];
  }

  public Dnie3Dg01Mrz.Gender getSex() {
    return Dnie3Dg01Mrz.Gender.getGender(parsedValues[9]);
  }

  public String getBirthCity() {
    return parsedValues[10];
  }

  public String getBirthCountry() {
    return parsedValues[11];
  }

  public String getParentsNames() {
    return parsedValues[12];
  }

  public String getAddress() {
    return parsedValues[13];
  }

  public String getCity() {
    return parsedValues[14];
  }

  public String getCountry() {
    return parsedValues[16];
  }
}
