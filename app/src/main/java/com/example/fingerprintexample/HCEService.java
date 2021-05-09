package com.example.fingerprintexample;

import android.content.Context;
import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.widget.HeterogeneousExpandableList;

import com.herumi.mcl.G2;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Objects;
import java.util.Random;

public class HCEService extends HostApduService {

    //Shared Preferences for data exchange
    SharedPreferences sharedPreferences;
    //Holder for received data
    String receivedData = "";
    //Sequence number for Proof of Knowledge "PI"
    int SN_PI = 1;
    //IndexHolder for Proof Of Knowledge
    int indexHolderPI = 0;
    //Sequence number for cryptographic credential "creds"
    int SN_creds = 1;
    //IndexHolder for ryptographic credential "creds"
    int indexHolderCreds = 0;
    //Current day variable
    private String currentDate;
    //Sequence number for GET_USER_ATTRIBUTES_DISCLOSED
    int SN_DISCLOSED = 1;
    //Index holder for INS_GET_ATTRIBUTES_DISCLOSES
    int indexHolder_DISCLOSED = 0;
    //EMPTY value
    String EMPTY = "";
    long startTime = 0;
    long stopTime = 0;


    /* APDU command
    ______________________________________
   |       Header        |       DATA     |
   |_____________________|________________|
   | CLA | INS | P1 | P2 | LC | DATA | LE |
    ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
    CLA.......Class byte (1B)
    INS.......Instruction byte (1B)
    P1........First parameter for instruction (1B)
    P2........Second parameter for instruction (1B)
    LC........Data length (1B)
    DATA......Data
    LE........Length of response (1B)
     */


    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle bundle) {
        Calendar calendar = Calendar.getInstance();
        currentDate = DateFormat.getDateInstance(DateFormat.FULL).format(calendar.getTime());
        if (commandApdu == null) {
            ApduResponseObject apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
            return Utils.hexStringToByteArray(apduResponse.toString());
        }
        //Received APDU command as a hexadecimal representation
        String hexCommandApdu = Utils.byteArrayToHexString(commandApdu).toUpperCase();

        //Checking the minimum APDU length 4 bytes (8 chars)
        if (hexCommandApdu.length() < ApduValues.APDU_constants.MIN_APDU_LENGTH) {
            ApduResponseObject apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
            return Utils.hexStringToByteArray(apduResponse.toString());
        }

        //Checking the correctness of the Select Application AID command
        if (hexCommandApdu.equals(ApduValues.APDU_constants.APDU_SCARD_SELECT_APPLICATION)) {
            ApduResponseObject apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_SUCCESS);
            return Utils.hexStringToByteArray(apduResponse.toString());
        }

        //APDU response variable declaration
        ApduResponseObject apduResponse;

        //Instruction recognition
        String apduInstruction = hexCommandApdu.substring(2, 4);
        switch (apduInstruction) {
            case ApduValues.APDU_instructions.INS_SET_USER_IDENTIFIER:
                try {
                    //---------Card personalization--------------------------------------------------//
                    //Checking that APDU command consists 8 bytes long Identifier
                    if (hexCommandApdu.substring(8, 10).equals(Constants.SystemParameters.BYTES_8)) {
                        //Getting an identifier for card personalization
                        String ID = hexCommandApdu.substring(10, 26);
                        //Using shared preferences for Activity data exchange (UserData shared preference)
                        sharedPreferences = getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
                        SharedPreferences.Editor editor = sharedPreferences.edit();
                        editor.putString(Constants.SystemParameters.ID, ID);
                        editor.commit();
                        //Log creation
                        createLog(Constants.SystemParameters.CARD_PERSONALIZATION, currentDate, editor);
                        //Successful response
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    } else {
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.INS_SET_USER_IDENTIFIER, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            case ApduValues.APDU_instructions.INS_GET_USER_IDENTIFIER:
                try {
                    //---------Issuance of a revocation parameter------------------------------------//
                    //---------User sends their ID to Revocation Authority---------------------------//
                    //Checking that APDU command consists requested response length equals to 8 bytes
                    if (hexCommandApdu.substring(8, 10).equals(Constants.SystemParameters.BYTES_8)) {
                        //Load UserData sharedPreference
                        sharedPreferences = getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
                        //Set ID from UserData sharedPreference
                        String ID = sharedPreferences.getString(Constants.SystemParameters.ID, "");
                        //Checking, that Saved ID is 8 Bytes long (16 chars)
                        if (ID.length() == 16) {
                            //If so, than response with ID data
                            apduResponse = new ApduResponseObject(ID, ApduValues.SW1_SW2.STATUS_SUCCESS);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        } else {
                            //Failed -> Saved ID is not 8 Bytes long
                            apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                    } else {
                        //Required ID length is not 8 bytes (16 chars) --> Fail
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.INS_GET_USER_IDENTIFIER, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            case ApduValues.APDU_instructions.INS_SET_REVOCATION_AUTHORITY_DATA:
                try {
                    //---------Issuance of a revocation parameters------------------------------------//
                    //---------User receives (m_r, sigma_RA, k, j, a1...aj, h1....hj, e1...ek, sigma_e1......sigma_ek)---//
                    //Getting total number of Apdu commands from P2 parameter
                    int totalNumberOfApduCommands_SET_RA_DATA = Integer.parseInt(hexCommandApdu.substring(6, 8), 16);
                    //Getting sequence number of Apdu command from P1 parameter
                    int sequenceNumberOfApduCommand_SET_RA_DATA = Integer.parseInt(hexCommandApdu.substring(4, 6), 16);
                    //Checking, that sequence number is lower than the total number
                    if (sequenceNumberOfApduCommand_SET_RA_DATA < totalNumberOfApduCommands_SET_RA_DATA) {
                        String data;
                        //Setting data length (2* because LC is the number of bytes and not chars, 2 chars = 1 byte)
                        int dataLength = 2 * (Integer.parseInt(hexCommandApdu.substring(8, 10), 16));
                        //Getting the data (10 + dataLength means the starting index of the data, which are followed after header, which is 10 chars (5 bytes) long)
                        data = hexCommandApdu.substring(10, 10 + dataLength);
                        //Setting the global variable, which will be saved after receiving the last Apdu command
                        receivedData += data;
                        //Need more data (Its because sequence number is lower than total number of requested Apdu commands
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.MORE_DATA);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    } else {
                        //Last message -> Sequence number is equal to totalNumber
                        String data;
                        //Setting data length (2* because LC is the number of bytes and not chars, 2 chars = 1 byte)
                        int dataLength = 2 * (Integer.parseInt(hexCommandApdu.substring(8, 10), 16));
                        //Getting the data (10 + dataLength means the starting index of the data, which are followed after header, which is 10 chars (5 bytes) long)
                        data = hexCommandApdu.substring(10, 10 + dataLength);
                        //Setting the global variable, which will be saved after receiving the last Apdu command
                        receivedData += data;
                        //Parsing and Saving received data a into the sharedPreferences storage
                        sharedPreferences = getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
                        SharedPreferences.Editor editor = sharedPreferences.edit();
                        editor.putString(Constants.SystemParameters.M_R, receivedData.substring(0, 64));//Length is 32 bytes, that is 64 chars
                        editor.putString(Constants.SystemParameters.SIGMA_RA, receivedData.substring(64, 194));//Length is 65 bytes, that is 130 chars. 64+130=194
                        editor.putString(Constants.SystemParameters.K, receivedData.substring(194, 196));//Length is 1 byte, that is 2 chars
                        editor.putString(Constants.SystemParameters.J, receivedData.substring(196, 198));//Length is 1 byte, that is 2 chars
                        //Getting decimal value from j
                        int j = Integer.parseInt(receivedData.substring(196, 198), 16);
                        //Getting decimal value from k
                        int k = Integer.parseInt(receivedData.substring(194, 196), 16);
                        //198 is the starting index for Alfas
                        int indexHolder = 198;
                        //a_1......a_j (Number)
                        for (int i = 1; i <= j; i++) {
                            //length is 32 bytes, that is 64 chars
                            editor.putString(Constants.SystemParameters.A_ + i, receivedData.substring(indexHolder, indexHolder + 64));
                            indexHolder += 64;
                        }
                        //h_1......h_j (Curve point)
                        for (int i = 1; i <= j; i++) {
                            //length is 65 bytes, that is 130 chars. indexHolder starts at the last index of Alfa, which is the first index for h
                            editor.putString(Constants.SystemParameters.H_ + i, receivedData.substring(indexHolder, indexHolder + 130));
                            indexHolder += 130;
                        }
                        //e_1.......e_k (Number)
                        for (int i = 1; i <= k; i++) {
                            //length is 32 bytes, that is 64 chars. indexHolder starts at the last index of h, which is the first index for e
                            //+2 is because of compatibility with MultiOS card, each received e value starts with "00"
                            editor.putString(Constants.SystemParameters.E_ + i, receivedData.substring(indexHolder + 2, indexHolder + 64 + 2));
                            indexHolder += 64 + 2;
                        }
                        //sigma_e1.......sigma_ek (Curve point)
                        for (int i = 1; i <= k; i++) {
                            //length is 65 bytes, that is 130 chars. indexHolder starts at the last index of e, which is the first index for sigma_e
                            editor.putString(Constants.SystemParameters.SIGMA_E + i, receivedData.substring(indexHolder, indexHolder + 130));
                            indexHolder += 130;
                        }
                        editor.commit();
                        //Setting the global variable to an empty string (For the future usage)
                        receivedData = EMPTY;
                        //Log creation
                        createLog(Constants.SystemParameters.REVOCATION_HANDLER_ISSUE, currentDate, editor);
                        //Response 9000 -> The last message was received
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.INS_SET_REVOCATION_AUTHORITY_DATA, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            case ApduValues.APDU_instructions.INS_GET_USER_IDENTIFIER_ATTRIBUTES:
                try {
                    //---------Issuance of user's attributes---------//
                    //---------Issuer asks for ID, m_r, sigma_RA, n--------//
                    //Getting requested values
                    sharedPreferences = getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
                    String id_GET_USER_ID_ATTR = sharedPreferences.getString(Constants.SystemParameters.ID, EMPTY);
                    String m_r_GET_USER_ID_ATTR = sharedPreferences.getString(Constants.SystemParameters.M_R, EMPTY);
                    String sigma_RA_GET_USER_ID_ATTR = sharedPreferences.getString(Constants.SystemParameters.SIGMA_RA, EMPTY);
                    String n_GET_USER_ID_ATTR = sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, Constants.SystemParameters.BYTE_0);
                    //Checking, that requested values are set -> Fail if one of them are not set. "n" can be 00 = 0
                    if (!id_GET_USER_ID_ATTR.equals(EMPTY) && !m_r_GET_USER_ID_ATTR.equals(EMPTY) && !sigma_RA_GET_USER_ID_ATTR.equals(EMPTY)) {
                        //ID + m_r + sigma_RA + n (106 Bytes)
                        String data_GET_USER_ID_ATTR = id_GET_USER_ID_ATTR + m_r_GET_USER_ID_ATTR + sigma_RA_GET_USER_ID_ATTR + n_GET_USER_ID_ATTR;
                        apduResponse = new ApduResponseObject(data_GET_USER_ID_ATTR, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    } else {
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.INS_GET_USER_IDENTIFIER_ATTRIBUTES, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            case ApduValues.APDU_instructions.INS_SET_USER_ATTRIBUTES:
                try {
                    //---------Issuance of user's attributes---------//
                    //---------Issuer issues the attributes to User (m_1.....m_9), 9 Attributes is maximum--------//
                    //User receives "n", m_1.....m_9
                    //Initializing attributes
                    sharedPreferences = getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
                    SharedPreferences.Editor editor_INS_SET_USER_ATTR = sharedPreferences.edit();
                    for (int i = 1; i < 10; i++) {
                        if (Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i, EMPTY), EMPTY)) {
                            editor_INS_SET_USER_ATTR.putString(Constants.SystemParameters.M_ + i, EMPTY);
                        }
                    }
                    //Getting total number of Apdu commands from P2 parameter
                    int totalNumberOfApduCommands_SET_USER_ATTRIBUTES = Integer.parseInt(hexCommandApdu.substring(6, 8), 16);
                    //Getting sequence number of Apdu command from P1 parameter
                    int sequenceNumberOfApduCommand_SET_USER_ATTRIBUTES = Integer.parseInt(hexCommandApdu.substring(4, 6), 16);
                    if (sequenceNumberOfApduCommand_SET_USER_ATTRIBUTES < totalNumberOfApduCommands_SET_USER_ATTRIBUTES) {
                        String data;
                        //Setting data length (2* because LC is the number of bytes and not chars, 2 chars = 1 byte)
                        int dataLength = 2 * (Integer.parseInt(hexCommandApdu.substring(8, 10), 16));
                        //Getting the data (10 + dataLength means the starting index of the data, which are followed after header, which is 10 chars (5 bytes) long)
                        data = hexCommandApdu.substring(10, 10 + dataLength);
                        //Setting the global variable, which will be saved after receiving the last Apdu command
                        receivedData += data;
                        //Need more data (Its because sequence number is lower than total number of requested Apdu commands
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.MORE_DATA);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    } else {
                        //Last message -> Sequence number is equal to totalNumber
                        String data;
                        //Setting data length (2* because LC is the number of bytes and not chars, 2 chars = 1 byte)
                        int dataLength = 2 * (Integer.parseInt(hexCommandApdu.substring(8, 10), 16));
                        //Getting the data (10 + dataLength means the starting index of the data, which are followed after header, which is 10 chars (5 bytes) long)
                        data = hexCommandApdu.substring(10, 10 + dataLength);
                        //Setting the global variable, which will be saved after receiving the last Apdu command
                        receivedData += data;
                        //Getting the total number of saved Attributes. (10, 12) Is the first byte of data "n", which describes the number of attributes
                        int totalNumberOfAlreadySavedAttributes = Integer.parseInt(Objects.requireNonNull(sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, Constants.SystemParameters.BYTE_0)), 16);
                        if (Integer.parseInt(hexCommandApdu.substring(10, 12), 16) + totalNumberOfAlreadySavedAttributes > 9) {
                            //Setting the global variable to an empty string (For the future usage)
                            receivedData = EMPTY;
                            //Its not possible to save more than 9 attributes
                            apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                        //Getting the total length of Received data (Chars)
                        int totalLengthOfReceivedData = receivedData.length();
                        //Checking that the totalLengthOfReceivedData is divisible by 64, because one attribute is 64 chars long (32 bytes).
                        //-2 is because of "n" which is 2 chars long (1 byte) and "n" is not an attribute
                        if ((totalLengthOfReceivedData - 2) % 64 != 0) {
                            //Setting the global variable to an empty string (For the future usage)
                            receivedData = "";
                            apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        } else {
                            //Parsing and Saving received data a into the sharedPreferences storage
                            //Division by 64 means, that one attribute is 32 bytes long, that is 64 chars
                            //-2 is because of "n" which is 2 chars long and "n" is not an attribute
                            int numberOfReceivedAttributes = (totalLengthOfReceivedData - 2) / 64;
                            //IndexHolder for setting attributes. The starting index is 2, because first byte is "n"
                            int indexHolder = 2;
                            for (int i = 0; i < numberOfReceivedAttributes; i++) {
                                for (int j = 1; j <= 9; j++) {
                                    if (Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + j, EMPTY), EMPTY)) {
                                        editor_INS_SET_USER_ATTR.putString(Constants.SystemParameters.M_ + j, receivedData.substring(indexHolder, indexHolder + 64));
                                        editor_INS_SET_USER_ATTR.commit();
                                        indexHolder += 64;
                                        break;
                                    }
                                }
                            }
                            editor_INS_SET_USER_ATTR.putString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, Utils.decimalToHex(totalNumberOfAlreadySavedAttributes + numberOfReceivedAttributes, "0"));
                            editor_INS_SET_USER_ATTR.commit();
                            //Setting the global variable to an empty string (For the future usage)
                            receivedData = "";
                            //Response 9000 -> The last message was received
                            apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_SUCCESS);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                    }
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.INS_SET_USER_ATTRIBUTES, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            case ApduValues.APDU_instructions.INS_SET_ISSUER_SIGNATURES:
                try {
                    //---------Issuance of a cryptographic credential------------------------------------//
                    //---------User receives (sigma, sigma_xr, sigma_x1......sigma_xn)-------------------//
                    //Getting total number of Apdu commands from P2 parameter
                    int totalNumberOfApduCommands_SET_ISSUER_SIGN = Integer.parseInt(hexCommandApdu.substring(6, 8), 16);
                    //Getting sequence number of Apdu command from P1 parameter
                    int sequenceNumberOfApduCommand_SET_ISSUER_SIGN = Integer.parseInt(hexCommandApdu.substring(4, 6), 16);
                    if (sequenceNumberOfApduCommand_SET_ISSUER_SIGN < totalNumberOfApduCommands_SET_ISSUER_SIGN) {
                        String data;
                        //Setting data length (2* because LC is the number of bytes and not chars, 2 chars = 1 byte)
                        int dataLength = 2 * (Integer.parseInt(hexCommandApdu.substring(8, 10), 16));
                        //Getting the data (10 + dataLength means the starting index of the data, which are followed after header, which is 10 chars (5 bytes) long)
                        data = hexCommandApdu.substring(10, 10 + dataLength);
                        //Setting the global variable, which will be saved after receiving the last Apdu command
                        receivedData += data;
                        //Need more data (Its because sequence number is lower than total number of requested Apdu commands
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.MORE_DATA);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    } else {
                        //Last message -> Sequence number is equal to totalNumber
                        String data;
                        //Setting data length (2* because LC is the number of bytes and not chars, 2 chars = 1 byte)
                        int dataLength = 2 * (Integer.parseInt(hexCommandApdu.substring(8, 10), 16));
                        //Getting the data (10 + dataLength means the starting index of the data, which are followed after header, which is 10 chars (5 bytes) long)
                        data = hexCommandApdu.substring(10, 10 + dataLength);
                        //Setting the global variable, which will be saved after receiving the last Apdu command
                        receivedData += data;
                        //Checking, that received data consists of 65 bytes long blocks (65 bytes = 130 chars)
                        if (receivedData.length() % 130 != 0) {
                            //Setting the global variable to an empty string (For the future usage)
                            receivedData = EMPTY;
                            apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        } else {
                            sharedPreferences = getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
                            SharedPreferences.Editor editor_SET_ISSUER_SIGN = sharedPreferences.edit();
                            //Creation of cryptographic credential value (sigma)
                            editor_SET_ISSUER_SIGN.putString(Constants.SystemParameters.SIGMA, receivedData.substring(0, 130));
                            //Setting sigma_xr, checking, that User has m_r
                            if (!Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_R, EMPTY), EMPTY) && Objects.equals(sharedPreferences.getString(Constants.SystemParameters.SIGMA_XR, EMPTY), EMPTY)) {
                                editor_SET_ISSUER_SIGN.putString(Constants.SystemParameters.SIGMA_XR, receivedData.substring(130, 260));
                            } else {
                                //Setting the global variable to an empty string (For the future usage)
                                receivedData = EMPTY;
                                //Its not possible to save sigma_xr, if the user does not have m_r
                                apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                                return Utils.hexStringToByteArray(apduResponse.toString());
                            }
                            //260 is the starting index of sigma_x1.....sigma_xn
                            int indexHolder = 260;
                            for (int i = 1; i < 10; i++) {
                                //Checking, which attributes are issued but do not have sigma_x1...sigma_xn
                                if (!Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i, EMPTY), EMPTY) && Objects.equals(sharedPreferences.getString(Constants.SystemParameters.SIGMA_X + i, EMPTY), EMPTY)) {
                                    //Setting sigma_x1...sigma_xn. Length is 65 bytes, that is 130 chars
                                    editor_SET_ISSUER_SIGN.putString(Constants.SystemParameters.SIGMA_X + i, receivedData.substring(indexHolder, indexHolder + 130));
                                    indexHolder += 130;
                                }
                            }
                            editor_SET_ISSUER_SIGN.commit();
                            receivedData = EMPTY;
                            //Log creation
                            createLog(Constants.SystemParameters.ATTRIBUTE_ISSUE, currentDate, editor_SET_ISSUER_SIGN);
                            //Response 9000 -> The last message was received
                            apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_SUCCESS);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                    }
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.INS_SET_ISSUER_SIGNATURES, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            case ApduValues.APDU_instructions.CMD_TEST_BIT_CHECKER:
                try {
                /*
                    ______________________________________________
                   |       P1      |           P2                |
                   |_______________|_____________________________|
                   |1|2|3|4|5|6|7|8|9|X|X|X|no. Hidden attributes|
                   ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
                   |0|1|0|0|0|1|0|0|0|0|0|0|  0    0    1    0   |
                   ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
             */
                    //---------Verification of attribute holding---------//
                    //---------User receives an information, that describes which attribute need to be disclosed and which hidden---------//
                    //Saving Byte P1 and P2 byte, which describe position of disclosed and hidden attributes
                    String P1_P2_CMD_TEST_BIT_CHECKER = Utils.toBinaryString(hexCommandApdu.substring(4, 6)) + Utils.toBinaryString(hexCommandApdu.substring(6, 8));
                    //Shared preferences initialization
                    sharedPreferences = getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
                    //Checking, that User has required attributes -> If not FAIL
                    for (int i = 1; i < 10; i++) {
                        if (Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i, EMPTY), EMPTY) && P1_P2_CMD_TEST_BIT_CHECKER.substring(i - 1, i).equals("1")) {
                            apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                    }
                    SharedPreferences.Editor editor_TEST_BIT_CHECKER = sharedPreferences.edit();
                    //Initialization of "num_of_hidden_attributes" value
                    editor_TEST_BIT_CHECKER.putString(Constants.SystemParameters.NUMBER_OF_HIDDEN_ATTRIBUTES, Utils.decimalToHex(Utils.binaryToDecimal(P1_P2_CMD_TEST_BIT_CHECKER.substring(12, 16)), "0"));
                    //Initialization of m_1_disclosed.......m_9_disclosed values to "0" = NO, "1" = YES
                    for (int i = 1; i < 10; i++) {
                        if (P1_P2_CMD_TEST_BIT_CHECKER.substring(i - 1, i).equals("1")) {
                            editor_TEST_BIT_CHECKER.putString(Constants.SystemParameters.M_ + i + "_disclosed", "1");
                        } else {
                            editor_TEST_BIT_CHECKER.putString(Constants.SystemParameters.M_ + i + "_disclosed", "0");
                        }
                    }
                    editor_TEST_BIT_CHECKER.commit();
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_SUCCESS);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.CMD_TEST_BIT_CHECKER, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            case ApduValues.APDU_instructions.INS_COMPUTE_PROOF_OF_KNOWLEDGE_SEQ_DISCLOSED:
                try {
                    //---------Verification of attribute holding---------//
                    //---------User receives an information, that describes which attribute need to be disclosed and which hidden---------//
                    //---------User receives nonce (32B) and epoch (4B)---------//
                    //---------Computation of Proof of Knowledge---------//
                    //Saving Byte P1 and P2 byte, which describe position of disclosed and hidden attributes
/*                String P1_P2_COMP_PROOF_OF_KNOWLEDGE_SEQ_DISCLOSED = Utils.toBinaryString(hexCommandApdu.substring(4, 6)) + Utils.toBinaryString(hexCommandApdu.substring(6, 8));
                //Shared preferences initialization
                sharedPreferences = getSharedPreferences("UserData", Context.MODE_PRIVATE);
                //Checking, that User has required attributes -> If not FAIL
                for (int i = 1; i < 10; i++) {
                    if (Objects.equals(sharedPreferences.getString("m_" + i, ""), "") && P1_P2_COMP_PROOF_OF_KNOWLEDGE_SEQ_DISCLOSED.substring(i - 1, i).equals("1")) {
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                }*/
                    //Checking, that received values are the same, that were received from CMD_TEST_BIT_CHECKER or INS_GET_USER_DISCLOSED_ATTRIBUTES
/*                for (int i = 1; i < 10; i++) {
                    if (P1_P2_COMP_PROOF_OF_KNOWLEDGE_SEQ_DISCLOSED.substring(i - 1, i).equals(sharedPreferences.getString("m_" + i + "_disclosed", ""))) {
                        continue;
                    } else {
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                }
                //Checking, that received number of hidden attributes, are the same, that were received from CMD_BIT_CHECKER or INS_GET_USER_DISCLOSED_ATTRIBUTES
                if (!Objects.equals(sharedPreferences.getString("num_of_hidden_attributes", ""), Utils.decimalToHex(Utils.binaryToDecimal(P1_P2_COMP_PROOF_OF_KNOWLEDGE_SEQ_DISCLOSED.substring(12, 16)), "0"))) {
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }*/
                    //Checking LC. The length of received data (32B + 4B = 36B)
                    if (Integer.parseInt(hexCommandApdu.substring(8, 10), 16) != 36) {
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    SharedPreferences.Editor editor_COMP_OF_KONWLEDGE_SEQ_DISCLOSED = sharedPreferences.edit();
                    //Setting "nonce", 10 means the starting index of data after header, which is 5 Bytes (10 chars) long
                    editor_COMP_OF_KONWLEDGE_SEQ_DISCLOSED.putString(Constants.SystemParameters.NONCE, hexCommandApdu.substring(10, 10 + 64));
                    //Setting "epoch", "10+64" means the starting index of epoch, which is after "nonce" and "8" means the length of epoch, that is 4 Bytes (8 chars) long
                    editor_COMP_OF_KONWLEDGE_SEQ_DISCLOSED.putString(Constants.SystemParameters.EPOCH, hexCommandApdu.substring(10 + 64, 10 + 64 + 8));
                    //Commit
                    editor_COMP_OF_KONWLEDGE_SEQ_DISCLOSED.commit();
                    //Compute Proof of knowledge. Sending HCEService context to CryptoCore, that is non-activity class
                    CryptoCore cryptoCore = new CryptoCore(this);
                    if (cryptoCore.computeProofOfKnowledge()) {
                        //Successful computation
                        //Response 9000
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    } else {
                        //Response FAIL
                        //Fail during Proof of Knowledge computation
                        apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.INS_COMPUTE_PROOF_OF_KNOWLEDGE_SEQ_DISCLOSED, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            case ApduValues.APDU_instructions.INS_GET_PROOF_OF_KNOWLEDGE:
                try {
                    //---------Verification of attribute holding---------//
                    //---------Reading Authentication data from the card (Application)---------//
                /*
                User sends:
                PI   (e, (s_m_1...s_m_9 ∉ D), s_v, s_m_r, s_i, s_eI, s_eII) - Proof of Knowledge [max 468 B]
                cred (sigma_roof, sigma_roof_eI, sigma_roof_eII, sigma_plane_eI, sigma_plane_eII, C) [390 B]
                1:  e.............................................[20 B]
                2:  s_v...........................................[32 + 1 B] first B is 00 (MultOS)
                3:  s_i...........................................[32 + 1 B] first B is 00 (MultOS)
                4:  s_eI..........................................[32 B]
                5:  s_eII.........................................[32 B]
                6:  s_m_r.........................................[32 B]
                7:  s_m_1...s_m_9 ∉ D.............................[32 B each]
                8:  sigma_roof....................................[65 B]
                9:  sigma_roof_eI.................................[65 B]
                10: sigma_roof_eII................................[65 B]
                11: sigma_plane_eI................................[65 B]
                12: sigma_plane_eII...............................[65 B]
                13: C.............................................[65 B]
                 */
                    //Setting P1 "PI" = 01 or "cred" = 02
                    String P1_GET_PROOF_OF_KNOWLEDGE = hexCommandApdu.substring(4, 6);
                    //Setting P2 "01" = One message, "02" = two messages
                    String P2_GET_PROOF_OF_KNOWLEDGE = hexCommandApdu.substring(6, 8);
                    //Initialization of SharedPreferences
                    sharedPreferences = getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
                    if (P1_GET_PROOF_OF_KNOWLEDGE.equals("01")) {
                        //Parameters "PI" initialization
                        String e = sharedPreferences.getString(Constants.SystemParameters.E, EMPTY);
                        String s_m_1 = sharedPreferences.getString(Constants.SystemParameters.S_M_1, EMPTY);
                        String s_m_2 = sharedPreferences.getString(Constants.SystemParameters.S_M_2, EMPTY);
                        String s_m_3 = sharedPreferences.getString(Constants.SystemParameters.S_M_3, EMPTY);
                        String s_m_4 = sharedPreferences.getString(Constants.SystemParameters.S_M_4, EMPTY);
                        String s_m_5 = sharedPreferences.getString(Constants.SystemParameters.S_M_5, EMPTY);
                        String s_m_6 = sharedPreferences.getString(Constants.SystemParameters.S_M_6, EMPTY);
                        String s_m_7 = sharedPreferences.getString(Constants.SystemParameters.S_M_7, EMPTY);
                        String s_m_8 = sharedPreferences.getString(Constants.SystemParameters.S_M_8, EMPTY);
                        String s_m_9 = sharedPreferences.getString(Constants.SystemParameters.S_M_9, EMPTY);
                        String s_v = sharedPreferences.getString(Constants.SystemParameters.S_V, EMPTY);
                        String s_m_r = sharedPreferences.getString(Constants.SystemParameters.S_M_R, EMPTY);
                        String s_i = sharedPreferences.getString(Constants.SystemParameters.S_I, EMPTY);
                        String s_eI = sharedPreferences.getString(Constants.SystemParameters.S_E_I, EMPTY);
                        String s_eII = sharedPreferences.getString(Constants.SystemParameters.S_E_II, EMPTY);
                        String allProofOfKnowledgeParams = e + s_v + s_i + s_eI + s_eII + s_m_r + s_m_1 + s_m_2 + s_m_3 + s_m_4 + s_m_5 + s_m_6 + s_m_7 + s_m_8 + s_m_9;
                        //Checking, if user can send all the data in one message
                        //2* means 2* size in bytes -> chars. (8, 10) stands for LE
                        if (P2_GET_PROOF_OF_KNOWLEDGE.equals("01") && allProofOfKnowledgeParams.length() == (2 * Integer.parseInt(hexCommandApdu.substring(8, 10), 16))) {
                            apduResponse = new ApduResponseObject(allProofOfKnowledgeParams, ApduValues.SW1_SW2.STATUS_SUCCESS);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                        //User has the send the data in two messages
                        else if (P2_GET_PROOF_OF_KNOWLEDGE.equals("02")) {
                            if (SN_PI == 1) {
                                //2* means 2* size in bytes -> chars. (8, 10) stands for LE. User indicates sending more data by "MORE_DATA" status bytes
                                apduResponse = new ApduResponseObject(allProofOfKnowledgeParams.substring(0, (2 * Integer.parseInt(hexCommandApdu.substring(8, 10), 16))), ApduValues.SW1_SW2.MORE_DATA);
                                //Setting sequence number for Proof of Knowledge +1. +1 Means, that this was the first message and user is going to send another one.
                                SN_PI++;
                                //Setting index holder for Proof of knowledge. Initial number is 0. (8, 10) stands for LE
                                indexHolderPI += (2 * Integer.parseInt(hexCommandApdu.substring(8, 10), 16));
                                return Utils.hexStringToByteArray(apduResponse.toString());
                            }
                            //Second message. Its necessary to decrement sequence number to 1 and set indexHolder to 0 for future usage.
                            else {
                                apduResponse = new ApduResponseObject(allProofOfKnowledgeParams.substring(indexHolderPI, indexHolderPI + (2 * Integer.parseInt(hexCommandApdu.substring(8, 10), 16))), ApduValues.SW1_SW2.STATUS_SUCCESS);
                                SN_PI--;
                                indexHolderPI = 0;
                                return Utils.hexStringToByteArray(apduResponse.toString());
                            }
                        }
                        //P2 is set to something else then "01" or "02" -> Not supported
                        else {
                            apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                    } else if (P1_GET_PROOF_OF_KNOWLEDGE.equals("02")) {
                        //Parameters "cred" initialization
                        String C = sharedPreferences.getString(Constants.SystemParameters.C, EMPTY);
                        String sigma_roof = sharedPreferences.getString(Constants.SystemParameters.SIGMA_ROOF, EMPTY);
                        String sigma_roof_eI = sharedPreferences.getString(Constants.SystemParameters.SIGMA_ROOF_E_I, EMPTY);
                        String sigma_roof_eII = sharedPreferences.getString(Constants.SystemParameters.SIGMA_ROOF_E_II, EMPTY);
                        String sigma_plane_eI = sharedPreferences.getString(Constants.SystemParameters.SIGMA_PLANE_E_I, EMPTY);
                        String sigma_plane_eII = sharedPreferences.getString(Constants.SystemParameters.SIGMA_PLANE_E_II, EMPTY);
                        String allCredsParams = sigma_roof + sigma_roof_eI + sigma_roof_eII + sigma_plane_eI + sigma_plane_eII + C;
                        if (SN_creds == 1) {
                            //Due to constant length of "creds", which is 390 B the first response will always have 250B long data, which is 500 chars
                            indexHolderCreds += 2 * Integer.parseInt(hexCommandApdu.substring(8, 10), 16);
                            apduResponse = new ApduResponseObject(allCredsParams.substring(0, indexHolderCreds), ApduValues.SW1_SW2.MORE_DATA);
                            //Setting SN_creds to 2 (next command will require the second part of "creds" data
                            SN_creds++;
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                        //Second message. Its necessary to decrement sequence number to 1 and set indexHolder to 0 for future usage.
                        else {
                            SharedPreferences.Editor editor = sharedPreferences.edit();
                            createLog(Constants.SystemParameters.PROOF_OF_KNOWLEDGE_SUBMIT, currentDate, editor);
                            apduResponse = new ApduResponseObject(allCredsParams.substring(indexHolderCreds, indexHolderCreds + 2 * Integer.parseInt(hexCommandApdu.substring(8, 10), 16)), ApduValues.SW1_SW2.STATUS_SUCCESS);
                            SN_creds--;
                            indexHolderCreds = 0;
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                    }
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.INS_GET_PROOF_OF_KNOWLEDGE, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            case ApduValues.APDU_instructions.INS_GET_USER_DISCLOSED_ATTRIBUTES:
                try {
                    //First message
                    if (SN_DISCLOSED == 1) {
                        //Saving Byte P1 and P2 byte, which describe position of disclosed and hidden attributes
                        String P1_P2_INS_GET_USER_DISCLOSED_ATTRIBUTES = Utils.toBinaryString(hexCommandApdu.substring(4, 6)) + Utils.toBinaryString(hexCommandApdu.substring(6, 8));
                        //Shared preferences initialization
                        sharedPreferences = getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
                        //Checking, that User has required attributes -> If not FAIL
                        for (int i = 1; i < 10; i++) {
                            if (Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i, EMPTY), EMPTY) && P1_P2_INS_GET_USER_DISCLOSED_ATTRIBUTES.substring(i - 1, i).equals("1")) {
                                apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                                return Utils.hexStringToByteArray(apduResponse.toString());
                            }
                        }
                        SharedPreferences.Editor editor_INS_GET_USER_DISCLOSED_ATTRIBUTES = sharedPreferences.edit();
                        //Initialization of m_1_disclosed.......m_9_disclosed values to "0" = NO, "1" = YES
                        int required_number_of_disclosed_attributes = 0;
                        for (int i = 1; i < 10; i++) {
                            if (P1_P2_INS_GET_USER_DISCLOSED_ATTRIBUTES.substring(i - 1, i).equals("1")) {
                                editor_INS_GET_USER_DISCLOSED_ATTRIBUTES.putString(Constants.SystemParameters.M_ + i + "_disclosed", "1");
                                required_number_of_disclosed_attributes++;
                            } else {
                                editor_INS_GET_USER_DISCLOSED_ATTRIBUTES.putString(Constants.SystemParameters.M_ + i + "_disclosed", "0");
                            }
                        }
                        //Initializing number of hidden attributes
                        int total_number_of_attributes = Integer.parseInt(Objects.requireNonNull(sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, Constants.SystemParameters.BYTE_0)), 16);
                        String num_of_hidden_attributes_string = Integer.toHexString((total_number_of_attributes - required_number_of_disclosed_attributes));
                        if (num_of_hidden_attributes_string.length() < 2) {
                            num_of_hidden_attributes_string = "0" + num_of_hidden_attributes_string;
                        }
                        editor_INS_GET_USER_DISCLOSED_ATTRIBUTES.putString(Constants.SystemParameters.NUMBER_OF_HIDDEN_ATTRIBUTES, num_of_hidden_attributes_string);
                        editor_INS_GET_USER_DISCLOSED_ATTRIBUTES.commit();
                        //Only one message needed
                        if (required_number_of_disclosed_attributes <= 7) {
                            String disclosed_attributes_data = sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, "00");
                            for (int i = 1; i < 10; i++) {
                                if (Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i + "_disclosed", "1"), "1") && !Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i, ""), "")) {
                                    disclosed_attributes_data += sharedPreferences.getString(Constants.SystemParameters.M_ + i, "");
                                }
                            }
                            SN_DISCLOSED = 1;
                            apduResponse = new ApduResponseObject(disclosed_attributes_data, ApduValues.SW1_SW2.STATUS_SUCCESS);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                        //Two messages needed
                        else {
                            //Incrementing sequence number
                            SN_DISCLOSED++;
                            //Getting all the data
                            String disclosed_attributes_data = sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, "00");
                            for (int i = 1; i < 10; i++) {
                                if (Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i + "_disclosed", "1"), "1") && !Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i, ""), "")) {
                                    disclosed_attributes_data += sharedPreferences.getString(Constants.SystemParameters.M_ + i, "");
                                }
                            }
                            //Initializing indexHolder, 0 to LE * 2, *2 because of number of chars
                            indexHolder_DISCLOSED = 2 * Integer.parseInt(hexCommandApdu.substring(8, 10), 16);
                            //First message sent
                            apduResponse = new ApduResponseObject(disclosed_attributes_data.substring(0, indexHolder_DISCLOSED), ApduValues.SW1_SW2.STATUS_SUCCESS);
                            return Utils.hexStringToByteArray(apduResponse.toString());
                        }
                    }
                    //Second message
                    else {
                        //Getting all the data
                        String disclosed_attributes_data = sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, "00");
                        for (int i = 1; i < 10; i++) {
                            if (Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i + "_disclosed", "1"), "1") && !Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i, ""), "")) {
                                disclosed_attributes_data += sharedPreferences.getString(Constants.SystemParameters.M_ + i, "");
                            }
                        }
                        apduResponse = new ApduResponseObject(disclosed_attributes_data.substring(indexHolder_DISCLOSED, 2 * Integer.parseInt(hexCommandApdu.substring(8, 10), 16)), ApduValues.SW1_SW2.STATUS_SUCCESS);
                        //Decrementing sequence number for future usage
                        SN_DISCLOSED--;
                        //Setting indexHolder to 0 for future usage
                        indexHolder_DISCLOSED = 0;
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.INS_GET_USER_DISCLOSED_ATTRIBUTES, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            case ApduValues.APDU_instructions.INS_GET_T:
                try {
                    //Saving Byte P1 byte, which describes Protocol parameter
                    String P1_INS_GET_T = hexCommandApdu.substring(4, 6);
                    //t_verify_debug
                    if (P1_INS_GET_T.equals("01")) {
                        String t_verify_debug = sharedPreferences.getString("t_verify_debug", "00");
                        apduResponse = new ApduResponseObject(t_verify_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //t_revoke_debug
                    else if (P1_INS_GET_T.equals("02")) {
                        String t_revoke_debug = sharedPreferences.getString("t_revoke_debug", "00");
                        apduResponse = new ApduResponseObject(t_revoke_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //t_sig_debug
                    else if (P1_INS_GET_T.equals("03")) {
                        String t_sig_debug = sharedPreferences.getString("t_sig_debug", "00");
                        apduResponse = new ApduResponseObject(t_sig_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //t_sig_debug
                    else if (P1_INS_GET_T.equals("04")) {
                        String t_sig1_debug = sharedPreferences.getString("t_sig1_debug", "00");
                        apduResponse = new ApduResponseObject(t_sig1_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //t_sig2_debug
                    else if (P1_INS_GET_T.equals("05")) {
                        String t_sig2_debug = sharedPreferences.getString("t_sig2_debug", "00");
                        apduResponse = new ApduResponseObject(t_sig2_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //sigma_hat_debug
                    else if (P1_INS_GET_T.equals("06")) {
                        String sigma_hat_debug = sharedPreferences.getString("sigma_hat_debug", "00");
                        apduResponse = new ApduResponseObject(sigma_hat_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //sigma_hat_e1_debug
                    else if (P1_INS_GET_T.equals("07")) {
                        String sigma_hat_e1_debug = sharedPreferences.getString("sigma_hat_e1_debug", "00");
                        apduResponse = new ApduResponseObject(sigma_hat_e1_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //sigma_hat_e2_debug
                    else if (P1_INS_GET_T.equals("08")) {
                        String sigma_hat_e2_debug = sharedPreferences.getString("sigma_hat_e2_debug", "00");
                        apduResponse = new ApduResponseObject(sigma_hat_e2_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //sigma_minus_e1_debug
                    else if (P1_INS_GET_T.equals("09")) {
                        String sigma_minus_e1_debug = sharedPreferences.getString("sigma_minus_e1_debug", "00");
                        apduResponse = new ApduResponseObject(sigma_minus_e1_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //sigma_minus_e2_debug
                    else if (P1_INS_GET_T.equals("0A")) {
                        String sigma_minus_e2_debug = sharedPreferences.getString("sigma_minus_e2_debug", "00");
                        apduResponse = new ApduResponseObject(sigma_minus_e2_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //pseudonym_debug
                    else if (P1_INS_GET_T.equals("0B")) {
                        String pseudonym_debug = sharedPreferences.getString("pseudonym_debug", "00");
                        apduResponse = new ApduResponseObject(pseudonym_debug, ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                    //Randomizers -> Different approach , so sending empty byte
                    else if (P1_INS_GET_T.equals("0C")) {
                        apduResponse = new ApduResponseObject("00000000", ApduValues.SW1_SW2.STATUS_SUCCESS);
                        return Utils.hexStringToByteArray(apduResponse.toString());
                    }
                } catch (Exception e) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    createLog(Constants.Errors.DEBUG_T, currentDate, editor);
                    apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.STATUS_FAILED);
                    return Utils.hexStringToByteArray(apduResponse.toString());
                }
            default:
                apduResponse = new ApduResponseObject(null, ApduValues.SW1_SW2.INS_NOT_SUPPORTED);
                return Utils.hexStringToByteArray(apduResponse.toString());
        }
    }

    private void createLog(String action, String currentDate, SharedPreferences.Editor editor) {
        int current_number_of_logs = sharedPreferences.getInt(Constants.SystemParameters.NUMBER_OF_LOGS, 0);
        editor.putInt(Constants.SystemParameters.NUMBER_OF_LOGS, current_number_of_logs + 1);
        editor.putString(Constants.SystemParameters.LOG_STATE + (current_number_of_logs + 1), action);
        editor.putString(Constants.SystemParameters.LOG_DATE + (current_number_of_logs + 1), currentDate);
        editor.commit();
    }

    @Override
    public void onDeactivated(int i) {
        System.out.println(".......");

    }
}