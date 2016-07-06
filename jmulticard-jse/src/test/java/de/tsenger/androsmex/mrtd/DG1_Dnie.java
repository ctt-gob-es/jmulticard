/*
 * Decompiled with CFR 0_110.
 */
package de.tsenger.androsmex.mrtd;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

public class DG1_Dnie {
    private byte[] rawData;
    private String name;
    private String surname;
    private String dateOfBirth;
    private String nationality;
    private String sex;
    private String dateOfExpiry;
    private String docNumber;
    private String docType;
    private String issuer;
    private String optData;
    private SimpleDateFormat sdFormat = new SimpleDateFormat("yyMMdd");
    private Date date = null;
    private HashMap<String, String> countryNames = new HashMap();

    private void fillHashMap() {
        this.countryNames.put("ABW", "Aruba");
        this.countryNames.put("AFG", "Afghanistan");
        this.countryNames.put("AGO", "Angola");
        this.countryNames.put("AIA", "Anguilla");
        this.countryNames.put("ALA", "\u00c5land Islands");
        this.countryNames.put("ALB", "Albania");
        this.countryNames.put("AND", "Andorra");
        this.countryNames.put("ANT", "Netherlands Antilles");
        this.countryNames.put("ARE", "United Arab Emirates");
        this.countryNames.put("ARG", "Argentina");
        this.countryNames.put("ARM", "Armenia");
        this.countryNames.put("ASM", "American Samoa");
        this.countryNames.put("ATA", "Antarctica");
        this.countryNames.put("ATF", "French Southern Territories");
        this.countryNames.put("ATG", "Antigua and Barbuda");
        this.countryNames.put("AUS", "Australia");
        this.countryNames.put("AUT", "Austria");
        this.countryNames.put("AZE", "Azerbaijan");
        this.countryNames.put("BDI", "Burundi");
        this.countryNames.put("BDR", "Bundesdruckerei");
        this.countryNames.put("BEL", "Belgium");
        this.countryNames.put("BEN", "Benin");
        this.countryNames.put("BFA", "Burkina Faso");
        this.countryNames.put("BGD", "Bangladesh");
        this.countryNames.put("BGR", "Bulgaria");
        this.countryNames.put("BHR", "Bahrain");
        this.countryNames.put("BHS", "Bahamas");
        this.countryNames.put("BIH", "Bosnia and Herzegovina");
        this.countryNames.put("BLR", "Belarus");
        this.countryNames.put("BLZ", "Belize");
        this.countryNames.put("BMU", "Bermuda");
        this.countryNames.put("BOL", "Bolivia");
        this.countryNames.put("BRA", "Brazil");
        this.countryNames.put("BRB", "Barbados");
        this.countryNames.put("BRN", "Brunei Darussalam");
        this.countryNames.put("BTN", "Bhutan");
        this.countryNames.put("BVT", "Bouvet Island");
        this.countryNames.put("BWA", "Botswana");
        this.countryNames.put("CAF", "Central African Republic");
        this.countryNames.put("CAN", "Canada");
        this.countryNames.put("CCK", "Cocos (Keeling) Islands");
        this.countryNames.put("CHE", "Switzerland");
        this.countryNames.put("CHL", "Chile");
        this.countryNames.put("CHN", "China");
        this.countryNames.put("CIV", "C\u00f4te d'Ivoire");
        this.countryNames.put("CMR", "Cameroon");
        this.countryNames.put("COD", "Congo, the Democratic Republic of the");
        this.countryNames.put("COG", "Congo");
        this.countryNames.put("COK", "Cook Islands");
        this.countryNames.put("COL", "Colombia");
        this.countryNames.put("COM", "Comoros");
        this.countryNames.put("CPV", "Cape Verde");
        this.countryNames.put("CRI", "Costa Rica");
        this.countryNames.put("CUB", "Cuba");
        this.countryNames.put("CXR", "Christmas Island");
        this.countryNames.put("CYM", "Cayman Islands");
        this.countryNames.put("CYP", "Cyprus");
        this.countryNames.put("CZE", "Czech Republic");
        this.countryNames.put("D", "Germany");
        this.countryNames.put("DJI", "Djibouti");
        this.countryNames.put("DMA", "Dominica");
        this.countryNames.put("DNK", "Denmark");
        this.countryNames.put("DOM", "Dominican Republic");
        this.countryNames.put("DZA", "Algeria");
        this.countryNames.put("ECU", "Ecuador");
        this.countryNames.put("EGY", "Egypt");
        this.countryNames.put("ERI", "Eritrea");
        this.countryNames.put("ESH", "Western Sahara");
        this.countryNames.put("ESP", "Espa\u00f1a");
        this.countryNames.put("EST", "Estonia");
        this.countryNames.put("ETH", "Ethiopia");
        this.countryNames.put("FIN", "Finland");
        this.countryNames.put("FJI", "Fiji");
        this.countryNames.put("FLK", "Falkland Islands (Malvinas)");
        this.countryNames.put("FRA", "France");
        this.countryNames.put("FRO", "Faroe Islands");
        this.countryNames.put("FSM", "Micronesia, Federated States of");
        this.countryNames.put("GAB", "Gabon");
        this.countryNames.put("GBR", "United Kingdom");
        this.countryNames.put("GEO", "Georgia");
        this.countryNames.put("GGY", "Guernsey");
        this.countryNames.put("GHA", "Ghana");
        this.countryNames.put("GIB", "Gibraltar");
        this.countryNames.put("GIN", "Guinea");
        this.countryNames.put("GLP", "Guadeloupe");
        this.countryNames.put("GMB", "Gambia");
        this.countryNames.put("GNB", "Guinea-Bissau");
        this.countryNames.put("GNQ", "Equatorial Guinea");
        this.countryNames.put("GRC", "Greece");
        this.countryNames.put("GRD", "Grenada");
        this.countryNames.put("GRL", "Greenland");
        this.countryNames.put("GTM", "Guatemala");
        this.countryNames.put("GUF", "French Guiana");
        this.countryNames.put("GUM", "Guam");
        this.countryNames.put("GUY", "Guyana");
        this.countryNames.put("HKG", "Hong Kong");
        this.countryNames.put("HMD", "Heard Island and McDonald Islands");
        this.countryNames.put("HND", "Honduras");
        this.countryNames.put("HRV", "Croatia");
        this.countryNames.put("HTI", "Haiti");
        this.countryNames.put("HUN", "Hungary");
        this.countryNames.put("IDN", "Indonesia");
        this.countryNames.put("IMN", "Isle of Man");
        this.countryNames.put("IND", "India");
        this.countryNames.put("IOT", "British Indian Ocean Territory");
        this.countryNames.put("IRL", "Ireland");
        this.countryNames.put("IRN", "Iran, Islamic Republic of");
        this.countryNames.put("IRQ", "Iraq");
        this.countryNames.put("ISL", "Iceland");
        this.countryNames.put("ISR", "Israel");
        this.countryNames.put("ITA", "Italy");
        this.countryNames.put("JAM", "Jamaica");
        this.countryNames.put("JEY", "Jersey");
        this.countryNames.put("JOR", "Jordan");
        this.countryNames.put("JPN", "Japan");
        this.countryNames.put("KAZ", "Kazakhstan");
        this.countryNames.put("KEN", "Kenya");
        this.countryNames.put("KGZ", "Kyrgyzstan");
        this.countryNames.put("KHM", "Cambodia");
        this.countryNames.put("KIR", "Kiribati");
        this.countryNames.put("KNA", "Saint Kitts and Nevis");
        this.countryNames.put("KOR", "Korea, Republic of");
        this.countryNames.put("KWT", "Kuwait");
        this.countryNames.put("LAO", "Lao People's Democratic Republic");
        this.countryNames.put("LBN", "Lebanon");
        this.countryNames.put("LBR", "Liberia");
        this.countryNames.put("LBY", "Libyan Arab Jamahiriya");
        this.countryNames.put("LCA", "Saint Lucia");
        this.countryNames.put("LIE", "Liechtenstein");
        this.countryNames.put("LKA", "Sri Lanka");
        this.countryNames.put("LSO", "Lesotho");
        this.countryNames.put("LTU", "Lithuania");
        this.countryNames.put("LUX", "Luxembourg");
        this.countryNames.put("LVA", "Latvia");
        this.countryNames.put("MAC", "Macao");
        this.countryNames.put("MAR", "Morocco");
        this.countryNames.put("MCO", "Monaco");
        this.countryNames.put("MDA", "Moldova, Republic of");
        this.countryNames.put("MDG", "Madagascar");
        this.countryNames.put("MDV", "Maldives");
        this.countryNames.put("MEX", "Mexico");
        this.countryNames.put("MHL", "Marshall Islands");
        this.countryNames.put("MKD", "Macedonia, the former Yugoslav Republic of");
        this.countryNames.put("MLI", "Mali");
        this.countryNames.put("MLT", "Malta");
        this.countryNames.put("MMR", "Myanmar");
        this.countryNames.put("MNE", "Montenegro");
        this.countryNames.put("MNG", "Mongolia");
        this.countryNames.put("MNP", "Northern Mariana Islands");
        this.countryNames.put("MOZ", "Mozambique");
        this.countryNames.put("MRT", "Mauritania");
        this.countryNames.put("MSR", "Montserrat");
        this.countryNames.put("MTQ", "Martinique");
        this.countryNames.put("MUS", "Mauritius");
        this.countryNames.put("MWI", "Malawi");
        this.countryNames.put("MYS", "Malaysia");
        this.countryNames.put("MYT", "Mayotte");
        this.countryNames.put("NAM", "Namibia");
        this.countryNames.put("NCL", "New Caledonia");
        this.countryNames.put("NER", "Niger");
        this.countryNames.put("NFK", "Norfolk Island");
        this.countryNames.put("NGA", "Nigeria");
        this.countryNames.put("NIC", "Nicaragua");
        this.countryNames.put("NIU", "Niue");
        this.countryNames.put("NLD", "Netherlands");
        this.countryNames.put("NOR", "Norway");
        this.countryNames.put("NPL", "Nepal");
        this.countryNames.put("NRU", "Nauru");
        this.countryNames.put("NZL", "New Zealand");
        this.countryNames.put("OMN", "Oman");
        this.countryNames.put("PAK", "Pakistan");
        this.countryNames.put("PAN", "Panama");
        this.countryNames.put("PCN", "Pitcairn");
        this.countryNames.put("PER", "Peru");
        this.countryNames.put("PHL", "Philippines");
        this.countryNames.put("PLW", "Palau");
        this.countryNames.put("PNG", "Papua New Guinea");
        this.countryNames.put("POL", "Poland");
        this.countryNames.put("PRI", "Puerto Rico");
        this.countryNames.put("PRK", "Korea, Democratic People's Republic of");
        this.countryNames.put("PRT", "Portugal");
        this.countryNames.put("PRY", "Paraguay");
        this.countryNames.put("PSE", "Palestinian Territory, Occupied");
        this.countryNames.put("PYF", "French Polynesia");
        this.countryNames.put("QAT", "Qatar");
        this.countryNames.put("REU", "R\u00e9union");
        this.countryNames.put("ROU", "Romania");
        this.countryNames.put("RUS", "Russian Federation");
        this.countryNames.put("RWA", "Rwanda");
        this.countryNames.put("SAU", "Saudi Arabia");
        this.countryNames.put("SDN", "Sudan");
        this.countryNames.put("SEN", "Senegal");
        this.countryNames.put("SGP", "Singapore");
        this.countryNames.put("SGS", "South Georgia and the South Sandwich Islands");
        this.countryNames.put("SHN", "Saint Helena");
        this.countryNames.put("SJM", "Svalbard and Jan Mayen");
        this.countryNames.put("SLB", "Solomon Islands");
        this.countryNames.put("SLE", "Sierra Leone");
        this.countryNames.put("SLV", "El Salvador");
        this.countryNames.put("SMR", "San Marino");
        this.countryNames.put("SOM", "Somalia");
        this.countryNames.put("SPM", "Saint Pierre and Miquelon");
        this.countryNames.put("SRB", "Serbia");
        this.countryNames.put("STP", "Sao Tome and Principe");
        this.countryNames.put("SUR", "Suriname");
        this.countryNames.put("SVK", "Slovakia");
        this.countryNames.put("SVN", "Slovenia");
        this.countryNames.put("SWE", "Sweden");
        this.countryNames.put("SWZ", "Swaziland");
        this.countryNames.put("SYC", "Seychelles");
        this.countryNames.put("SYR", "Syrian Arab Republic");
        this.countryNames.put("TCA", "Turks and Caicos Islands");
        this.countryNames.put("TCD", "Chad");
        this.countryNames.put("TGO", "Togo");
        this.countryNames.put("THA", "Thailand");
        this.countryNames.put("TJK", "Tajikistan");
        this.countryNames.put("TKL", "Tokelau");
        this.countryNames.put("TKM", "Turkmenistan");
        this.countryNames.put("TLS", "Timor-Leste");
        this.countryNames.put("TON", "Tonga");
        this.countryNames.put("TTO", "Trinidad and Tobago");
        this.countryNames.put("TUN", "Tunisia");
        this.countryNames.put("TUR", "Turkey");
        this.countryNames.put("TUV", "Tuvalu");
        this.countryNames.put("TWN", "Taiwan, Province of China");
        this.countryNames.put("TZA", "Tanzania, United Republic of");
        this.countryNames.put("UGA", "Uganda");
        this.countryNames.put("UKR", "Ukraine");
        this.countryNames.put("UMI", "United States Minor Outlying Islands");
        this.countryNames.put("URY", "Uruguay");
        this.countryNames.put("USA", "United States");
        this.countryNames.put("UTO", "Utopia");
        this.countryNames.put("UZB", "Uzbekistan");
        this.countryNames.put("VAT", "Holy See (Vatican City State)");
        this.countryNames.put("VCT", "Saint Vincent and the Grenadines");
        this.countryNames.put("VEN", "Venezuela");
        this.countryNames.put("VGB", "Virgin Islands, British");
        this.countryNames.put("VIR", "Virgin Islands, U.S.");
        this.countryNames.put("VNM", "Viet Nam");
        this.countryNames.put("VUT", "Vanuatu");
        this.countryNames.put("WLF", "Wallis and Futuna");
        this.countryNames.put("WSM", "Samoa");
        this.countryNames.put("YEM", "Yemen");
        this.countryNames.put("ZAF", "South Africa");
        this.countryNames.put("ZMB", "Zambia");
        this.countryNames.put("ZWE", "Zimbabwe");
    }

    public DG1_Dnie(byte[] rawBytes) {
        this.rawData = (byte[])rawBytes.clone();
        byte[] mrzBytes = new byte[this.rawData[4]];
        System.arraycopy(this.rawData, 5, mrzBytes, 0, mrzBytes.length);
        String mrzString = new String(mrzBytes);
        if (this.rawData[4] == 88) {
            String mrz1 = mrzString.substring(0, 44);
            String mrz2 = mrzString.substring(44, 88);
            this.fillHashMap();
            this.docType = mrz1.substring(0, 2).replace('<', ' ').trim();
            this.issuer = mrz1.substring(2, 5).replace('<', ' ').trim();
            String helpName = mrz1.substring(5, 44);
            for (int i = 0; i < helpName.length(); ++i) {
                if (helpName.charAt(i) != '<' || helpName.charAt(i + 1) != '<') continue;
                this.surname = helpName.substring(0, i).replace('<', ' ').trim();
                this.name = helpName.substring(i + 2).replace('<', ' ').trim();
                break;
            }
            this.docNumber = mrz2.substring(0, 9).replace('<', ' ').trim();
            this.nationality = mrz2.substring(10, 13).replace('<', ' ').trim();
            this.dateOfBirth = mrz2.substring(13, 19);
            this.sex = mrz2.substring(20, 21);
            this.dateOfExpiry = mrz2.substring(21, 27);
            this.optData = mrz2.substring(28, 42).replace('<', ' ').trim();
        } else {
            String mrz1 = mrzString.substring(0, 30);
            String mrz2 = mrzString.substring(30, 60);
            String mrz3 = mrzString.substring(60, 90);
            this.fillHashMap();
            this.docType = mrz1.substring(0, 2).replace('<', ' ').trim();
            this.issuer = mrz1.substring(2, 5).replace('<', ' ').trim();
            this.docNumber = mrz1.substring(5, 14).replace('<', ' ').trim();
            this.optData = mrz1.substring(15, 30).replace('<', ' ').trim();
            this.dateOfBirth = mrz2.substring(0, 6);
            this.sex = mrz2.substring(7, 8);
            this.dateOfExpiry = mrz2.substring(8, 14);
            this.nationality = mrz2.substring(15, 18).replace('<', ' ').trim();
            for (int i = 0; i < mrz3.length(); ++i) {
                if (mrz3.charAt(i) != '<' || mrz3.charAt(i + 1) != '<') continue;
                this.surname = mrz3.substring(0, i).replace('<', ' ').trim();
                this.name = mrz3.substring(i + 2).replace('<', ' ').trim();
                break;
            }
        }
    }

    public byte[] getBytes() {
        return this.rawData;
    }

    public String getName() {
        return this.name;
    }

    public String getSurname() {
        return this.surname;
    }

    public String getDateOfBirth() {
        try {
            this.date = this.sdFormat.parse(this.dateOfBirth);
        }
        catch (ParseException e) {
            e.printStackTrace();
        }
        return DateFormat.getDateInstance(2).format(this.date);
    }

    public String getNationality() {
        return this.countryNames.get(this.nationality);
    }

    public String getSex() {
        if (this.sex.equals("F")) {
            return "female";
        }
        if (this.sex.equals("M")) {
            return "male";
        }
        return this.sex;
    }

    public String getDateOfExpiry() {
        try {
            this.date = this.sdFormat.parse(this.dateOfExpiry);
        }
        catch (ParseException e) {
            e.printStackTrace();
        }
        return DateFormat.getDateInstance(2).format(this.date);
    }

    public String getDocNumber() {
        return this.docNumber;
    }

    public String getIssuer() {
        return this.countryNames.get(this.issuer);
    }

    public String getOptData() {
        return this.optData;
    }

    public String getDocType() {
        return this.docType;
    }
}

