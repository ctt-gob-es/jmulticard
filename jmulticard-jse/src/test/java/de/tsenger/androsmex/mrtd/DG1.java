/*
 * DG1DataContainer.java
 *
 * Created on 26. September 2007
 *
 *  This file is part of JSmex.
 *
 *  JSmex is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  JSmex is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Foobar; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package de.tsenger.androsmex.mrtd;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

/**
 *
 * @author Tobias Senger
 */
public class DG1 {
    
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
    
    private SimpleDateFormat sdFormat = new SimpleDateFormat( "yyMMdd" );
    private Date date = null;
    
    private HashMap<String,String> countryNames = new HashMap<String,String>();
    
    private void fillHashMap() {
        countryNames.put("ABW","Aruba");
        countryNames.put("AFG","Afghanistan");
        countryNames.put("AGO","Angola");
        countryNames.put("AIA","Anguilla");
        countryNames.put("ALA","Åland Islands");
        countryNames.put("ALB","Albania");
        countryNames.put("AND","Andorra");
        countryNames.put("ANT","Netherlands Antilles");
        countryNames.put("ARE","United Arab Emirates");
        countryNames.put("ARG","Argentina");
        countryNames.put("ARM","Armenia");
        countryNames.put("ASM","American Samoa");
        countryNames.put("ATA","Antarctica");
        countryNames.put("ATF","French Southern Territories");
        countryNames.put("ATG","Antigua and Barbuda");
        countryNames.put("AUS","Australia");
        countryNames.put("AUT","Austria");
        countryNames.put("AZE","Azerbaijan");
        countryNames.put("BDI","Burundi");
        countryNames.put("BDR","Bundesdruckerei");
        countryNames.put("BEL","Belgium");
        countryNames.put("BEN","Benin");
        countryNames.put("BFA","Burkina Faso");
        countryNames.put("BGD","Bangladesh");
        countryNames.put("BGR","Bulgaria");
        countryNames.put("BHR","Bahrain");
        countryNames.put("BHS","Bahamas");
        countryNames.put("BIH","Bosnia and Herzegovina");
        countryNames.put("BLR","Belarus");
        countryNames.put("BLZ","Belize");
        countryNames.put("BMU","Bermuda");
        countryNames.put("BOL","Bolivia");
        countryNames.put("BRA","Brazil");
        countryNames.put("BRB","Barbados");
        countryNames.put("BRN","Brunei Darussalam");
        countryNames.put("BTN","Bhutan");
        countryNames.put("BVT","Bouvet Island");
        countryNames.put("BWA","Botswana");
        countryNames.put("CAF","Central African Republic");
        countryNames.put("CAN","Canada");
        countryNames.put("CCK","Cocos (Keeling) Islands");
        countryNames.put("CHE","Switzerland");
        countryNames.put("CHL","Chile");
        countryNames.put("CHN","China");
        countryNames.put("CIV","Côte d'Ivoire");
        countryNames.put("CMR","Cameroon");
        countryNames.put("COD","Congo, the Democratic Republic of the");
        countryNames.put("COG","Congo");
        countryNames.put("COK","Cook Islands");
        countryNames.put("COL","Colombia");
        countryNames.put("COM","Comoros");
        countryNames.put("CPV","Cape Verde");
        countryNames.put("CRI","Costa Rica");
        countryNames.put("CUB","Cuba");
        countryNames.put("CXR","Christmas Island");
        countryNames.put("CYM","Cayman Islands");
        countryNames.put("CYP","Cyprus");
        countryNames.put("CZE","Czech Republic");
        countryNames.put("D"  ,"Germany");
        countryNames.put("DJI","Djibouti");
        countryNames.put("DMA","Dominica");
        countryNames.put("DNK","Denmark");
        countryNames.put("DOM","Dominican Republic");
        countryNames.put("DZA","Algeria");
        countryNames.put("ECU","Ecuador");
        countryNames.put("EGY","Egypt");
        countryNames.put("ERI","Eritrea");
        countryNames.put("ESH","Western Sahara");
        countryNames.put("ESP","Spain");
        countryNames.put("EST","Estonia");
        countryNames.put("ETH","Ethiopia");
        countryNames.put("FIN","Finland");
        countryNames.put("FJI","Fiji");
        countryNames.put("FLK","Falkland Islands (Malvinas)");
        countryNames.put("FRA","France");
        countryNames.put("FRO","Faroe Islands");
        countryNames.put("FSM","Micronesia, Federated States of");
        countryNames.put("GAB","Gabon");
        countryNames.put("GBR","United Kingdom");
        countryNames.put("GEO","Georgia");
        countryNames.put("GGY","Guernsey");
        countryNames.put("GHA","Ghana");
        countryNames.put("GIB","Gibraltar");
        countryNames.put("GIN","Guinea");
        countryNames.put("GLP","Guadeloupe");
        countryNames.put("GMB","Gambia");
        countryNames.put("GNB","Guinea-Bissau");
        countryNames.put("GNQ","Equatorial Guinea");
        countryNames.put("GRC","Greece");
        countryNames.put("GRD","Grenada");
        countryNames.put("GRL","Greenland");
        countryNames.put("GTM","Guatemala");
        countryNames.put("GUF","French Guiana");
        countryNames.put("GUM","Guam");
        countryNames.put("GUY","Guyana");
        countryNames.put("HKG","Hong Kong");
        countryNames.put("HMD","Heard Island and McDonald Islands");
        countryNames.put("HND","Honduras");
        countryNames.put("HRV","Croatia");
        countryNames.put("HTI","Haiti");
        countryNames.put("HUN","Hungary");
        countryNames.put("IDN","Indonesia");
        countryNames.put("IMN","Isle of Man");
        countryNames.put("IND","India");
        countryNames.put("IOT","British Indian Ocean Territory");
        countryNames.put("IRL","Ireland");
        countryNames.put("IRN","Iran, Islamic Republic of");
        countryNames.put("IRQ","Iraq");
        countryNames.put("ISL","Iceland");
        countryNames.put("ISR","Israel");
        countryNames.put("ITA","Italy");
        countryNames.put("JAM","Jamaica");
        countryNames.put("JEY","Jersey");
        countryNames.put("JOR","Jordan");
        countryNames.put("JPN","Japan");
        countryNames.put("KAZ","Kazakhstan");
        countryNames.put("KEN","Kenya");
        countryNames.put("KGZ","Kyrgyzstan");
        countryNames.put("KHM","Cambodia");
        countryNames.put("KIR","Kiribati");
        countryNames.put("KNA","Saint Kitts and Nevis");
        countryNames.put("KOR","Korea, Republic of");
        countryNames.put("KWT","Kuwait");
        countryNames.put("LAO","Lao People's Democratic Republic");
        countryNames.put("LBN","Lebanon");
        countryNames.put("LBR","Liberia");
        countryNames.put("LBY","Libyan Arab Jamahiriya");
        countryNames.put("LCA","Saint Lucia");
        countryNames.put("LIE","Liechtenstein");
        countryNames.put("LKA","Sri Lanka");
        countryNames.put("LSO","Lesotho");
        countryNames.put("LTU","Lithuania");
        countryNames.put("LUX","Luxembourg");
        countryNames.put("LVA","Latvia");
        countryNames.put("MAC","Macao");
        countryNames.put("MAR","Morocco");
        countryNames.put("MCO","Monaco");
        countryNames.put("MDA","Moldova, Republic of");
        countryNames.put("MDG","Madagascar");
        countryNames.put("MDV","Maldives");
        countryNames.put("MEX","Mexico");
        countryNames.put("MHL","Marshall Islands");
        countryNames.put("MKD","Macedonia, the former Yugoslav Republic of");
        countryNames.put("MLI","Mali");
        countryNames.put("MLT","Malta");
        countryNames.put("MMR","Myanmar");
        countryNames.put("MNE","Montenegro");
        countryNames.put("MNG","Mongolia");
        countryNames.put("MNP","Northern Mariana Islands");
        countryNames.put("MOZ","Mozambique");
        countryNames.put("MRT","Mauritania");
        countryNames.put("MSR","Montserrat");
        countryNames.put("MTQ","Martinique");
        countryNames.put("MUS","Mauritius");
        countryNames.put("MWI","Malawi");
        countryNames.put("MYS","Malaysia");
        countryNames.put("MYT","Mayotte");
        countryNames.put("NAM","Namibia");
        countryNames.put("NCL","New Caledonia");
        countryNames.put("NER","Niger");
        countryNames.put("NFK","Norfolk Island");
        countryNames.put("NGA","Nigeria");
        countryNames.put("NIC","Nicaragua");
        countryNames.put("NIU","Niue");
        countryNames.put("NLD","Netherlands");
        countryNames.put("NOR","Norway");
        countryNames.put("NPL","Nepal");
        countryNames.put("NRU","Nauru");
        countryNames.put("NZL","New Zealand");
        countryNames.put("OMN","Oman");
        countryNames.put("PAK","Pakistan");
        countryNames.put("PAN","Panama");
        countryNames.put("PCN","Pitcairn");
        countryNames.put("PER","Peru");
        countryNames.put("PHL","Philippines");
        countryNames.put("PLW","Palau");
        countryNames.put("PNG","Papua New Guinea");
        countryNames.put("POL","Poland");
        countryNames.put("PRI","Puerto Rico");
        countryNames.put("PRK","Korea, Democratic People's Republic of");
        countryNames.put("PRT","Portugal");
        countryNames.put("PRY","Paraguay");
        countryNames.put("PSE","Palestinian Territory, Occupied");
        countryNames.put("PYF","French Polynesia");
        countryNames.put("QAT","Qatar");
        countryNames.put("REU","Réunion");
        countryNames.put("ROU","Romania");
        countryNames.put("RUS","Russian Federation");
        countryNames.put("RWA","Rwanda");
        countryNames.put("SAU","Saudi Arabia");
        countryNames.put("SDN","Sudan");
        countryNames.put("SEN","Senegal");
        countryNames.put("SGP","Singapore");
        countryNames.put("SGS","South Georgia and the South Sandwich Islands");
        countryNames.put("SHN","Saint Helena");
        countryNames.put("SJM","Svalbard and Jan Mayen");
        countryNames.put("SLB","Solomon Islands");
        countryNames.put("SLE","Sierra Leone");
        countryNames.put("SLV","El Salvador");
        countryNames.put("SMR","San Marino");
        countryNames.put("SOM","Somalia");
        countryNames.put("SPM","Saint Pierre and Miquelon");
        countryNames.put("SRB","Serbia");
        countryNames.put("STP","Sao Tome and Principe");
        countryNames.put("SUR","Suriname");
        countryNames.put("SVK","Slovakia");
        countryNames.put("SVN","Slovenia");
        countryNames.put("SWE","Sweden");
        countryNames.put("SWZ","Swaziland");
        countryNames.put("SYC","Seychelles");
        countryNames.put("SYR","Syrian Arab Republic");
        countryNames.put("TCA","Turks and Caicos Islands");
        countryNames.put("TCD","Chad");
        countryNames.put("TGO","Togo");
        countryNames.put("THA","Thailand");
        countryNames.put("TJK","Tajikistan");
        countryNames.put("TKL","Tokelau");
        countryNames.put("TKM","Turkmenistan");
        countryNames.put("TLS","Timor-Leste");
        countryNames.put("TON","Tonga");
        countryNames.put("TTO","Trinidad and Tobago");
        countryNames.put("TUN","Tunisia");
        countryNames.put("TUR","Turkey");
        countryNames.put("TUV","Tuvalu");
        countryNames.put("TWN","Taiwan, Province of China");
        countryNames.put("TZA","Tanzania, United Republic of");
        countryNames.put("UGA","Uganda");
        countryNames.put("UKR","Ukraine");
        countryNames.put("UMI","United States Minor Outlying Islands");
        countryNames.put("URY","Uruguay");
        countryNames.put("USA","United States");
        countryNames.put("UTO","Utopia");
        countryNames.put("UZB","Uzbekistan");
        countryNames.put("VAT","Holy See (Vatican City State)");
        countryNames.put("VCT","Saint Vincent and the Grenadines");
        countryNames.put("VEN","Venezuela");
        countryNames.put("VGB","Virgin Islands, British");
        countryNames.put("VIR","Virgin Islands, U.S.");
        countryNames.put("VNM","Viet Nam");
        countryNames.put("VUT","Vanuatu");
        countryNames.put("WLF","Wallis and Futuna");
        countryNames.put("WSM","Samoa");
        countryNames.put("YEM","Yemen");
        countryNames.put("ZAF","South Africa");
        countryNames.put("ZMB","Zambia");
        countryNames.put("ZWE","Zimbabwe");
    }
        
    
    /**
     * Creates a new instance of DG1DataContainer
     */
    public DG1(byte[] rawBytes) {
        
        this.rawData = rawBytes.clone();
        
        byte [] mrzBytes = new byte[rawData[4]];
        System.arraycopy(rawData,5,mrzBytes,0,mrzBytes.length);
        
        String mrzString = new String(mrzBytes);
        
        String mrz1 = mrzString.substring(0,44);
        String mrz2 = mrzString.substring(44,88);
        
        fillHashMap();
        
        this.docType = mrz1.substring(0,2).replace('<', ' ').trim();
        this.issuer = mrz1.substring(2,5).replace('<', ' ').trim();
        
        String helpName =mrz1.substring(5,44);
        for (int i = 0;i<helpName.length();i++) {
            if (helpName.charAt(i)=='<' && helpName.charAt(i+1)=='<') {
                this.surname = helpName.substring(0,i).replace('<', ' ').trim();
                this.name = helpName.substring(i+2).replace('<', ' ').trim();
                break;
            }
        }
        
        
        this.docNumber = mrz2.substring(0,9).replace('<', ' ').trim(); 
        this.nationality = mrz2.substring(10,13).replace('<', ' ').trim();
        this.dateOfBirth = mrz2.substring(13,19);
        this.sex = mrz2.substring(20,21);
        this.dateOfExpiry = mrz2.substring(21,27);
        this.optData = mrz2.substring(28,42).replace('<', ' ').trim();
        
    }
    
    public byte[] getBytes() {
        return rawData;
    }
    
    public String getName() {
        return name;
    }
    
    public String getSurname() {
        return surname;
    }
    
    public String getDateOfBirth() {
        try {
            date = sdFormat.parse( dateOfBirth );
        } catch ( ParseException e ) {
            e.printStackTrace(); 
        }
        return DateFormat.getDateInstance(DateFormat.MEDIUM).format(date);
    }
    
    public String getNationality() {
        return countryNames.get(nationality);
    }
    
    public String getSex() {
        if (sex.equals("F")) return "female";
        if (sex.equals("M")) return "male";
        return sex;
    }
    
    public String getDateOfExpiry() {
        try {
            date = sdFormat.parse( dateOfExpiry );
        } catch ( ParseException e ) {
            e.printStackTrace(); 
        }
        return DateFormat.getDateInstance(DateFormat.MEDIUM).format(date);     
    }
    
    public String getDocNumber() {
        return docNumber;
    }
    
    public String getIssuer() {
        return countryNames.get(issuer);
    }
    
    public String getOptData() {
        return optData;
    }
    
    public String getDocType() {
        return docType;
    }
}
