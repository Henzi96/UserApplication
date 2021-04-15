package com.example.fingerprintexample;

public class ApduValues {
    class APDU_constants {
        //4 bytes = 8 string characters CLA|INS|P1|P2
        public static final int MIN_APDU_LENGTH = 8;
        //Select AID command from other entities
        public static final String APDU_SCARD_SELECT_APPLICATION = "00A40400077675743231303100";
    }

    class SW1_SW2 {
        public static final String STATUS_SUCCESS = "9000";
        public static final String STATUS_FAILED = "6F00";
        public static final String INS_NOT_SUPPORTED = "6D00";
        public static final String MORE_DATA = "91AF";
    }

    class APDU_instructions {
        public static final String INS_SET_USER_IDENTIFIER = "0B";
        public static final String INS_GET_USER_IDENTIFIER = "01";
        public static final String INS_SET_REVOCATION_AUTHORITY_DATA = "02";
        public static final String INS_GET_USER_IDENTIFIER_ATTRIBUTES = "04";
        public static final String INS_SET_USER_ATTRIBUTES = "03";
        public static final String INS_SET_ISSUER_SIGNATURES = "05";
        public static final String CMD_TEST_BIT_CHECKER = "09";
        public static final String INS_COMPUTE_PROOF_OF_KNOWLEDGE_SEQ_DISCLOSED = "0A";
        public static final String INS_GET_PROOF_OF_KNOWLEDGE = "07";
        public static final String INS_GET_USER_DISCLOSED_ATTRIBUTES = "0C";
    }

}
