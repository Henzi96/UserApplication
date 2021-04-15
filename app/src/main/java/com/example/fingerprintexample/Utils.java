package com.example.fingerprintexample;

public class Utils {

    //ByteArray -> Hexadecimal String
    public static String byteArrayToHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }

    //Hexadecimal String -> ByteArray
    public static byte[] hexStringToByteArray(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

    public static String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    public static byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private static int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if (digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: " + hexChar);
        }
        return digit;
    }

    public static String dataLengthCounter(String data) {
        if (data.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }
        String hexadecimalLength = Integer.toHexString(data.length() / 2).toUpperCase();
        if (hexadecimalLength.length() == 1) {
            hexadecimalLength = "0" + hexadecimalLength;
            return hexadecimalLength;
        } else if (hexadecimalLength.length() == 3) {
            hexadecimalLength = "000" + hexadecimalLength;
            return hexadecimalLength;
        } else if (hexadecimalLength.length() == 4) {
            hexadecimalLength = "00" + hexadecimalLength;
            return hexadecimalLength;
        } else if (hexadecimalLength.length() >= 5) {
            throw new IllegalArgumentException(
                    "Out of supported range!");
        } else {
            return hexadecimalLength;
        }
    }

    public static String decimalToHex(int i, String zeros) {
        String result = "";
        result = Integer.toHexString(i);
        return zeros + result;
    }

    public static String toBinaryString(String hexNumber) {
        int decimalNumber = Integer.parseInt(hexNumber, 16);
        String binaryString = Integer.toBinaryString(decimalNumber);
        while (binaryString.length() < 8) {
            binaryString = "0" + binaryString;
        }
        return binaryString;
    }

    static int binaryToDecimal(String n) {
        String num = n;
        int dec_value = 0;
        // Initializing base value to 1,
        // i.e 2^0
        int base = 1;
        int len = num.length();
        for (int i = len - 1; i >= 0; i--) {
            if (num.charAt(i) == '1')
                dec_value += base;
            base = base * 2;
        }
        return dec_value;
    }
}
