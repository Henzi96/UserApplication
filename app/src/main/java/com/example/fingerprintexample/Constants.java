package com.example.fingerprintexample;


public class Constants {
    public class SystemParameters {
        public static final String NUMBER_OF_LOGS = "number_of_logs";
        public static final String LOG_STATE = "log_state_";
        public static final String LOG_DATE = "log_date_";
        public static final String CARD_PERSONALIZATION = "Card personalization";
        public static final String REVOCATION_HANDLER_ISSUE = "Issuance of a revocation handler";
        public static final String ATTRIBUTE_ISSUE = "Issuance of user's attributes";
        public static final String PROOF_OF_KNOWLEDGE_SUBMIT = "Proof Of Knowledge submitted";
        public static final String NUMBER_OF_ATTRIBUTES = "n";
        public static final String ID = "ID";
        public static final String BYTES_8 = "08";
        public static final String USER_DATA = "UserData";
        public static final String M_R = "m_r";
        public static final String SIGMA_RA = "sigma_RA";
        public static final String K = "k";
        public static final String J = "j";
        public static final String A_ = "a_";
        public static final String H_ = "h_";
        public static final String E_ = "e_";
        public static final String SIGMA_E = "sigma_e";
        public static final String BYTE_0 = "00";
        public static final String M_ = "m_";
        public static final String SIGMA = "sigma";
        public static final String SIGMA_XR = "sigma_xr";
        public static final String SIGMA_X = "sigma_x";
        public static final String NUMBER_OF_HIDDEN_ATTRIBUTES = "num_of_hidden_attributes";
        public static final String NONCE = "nonce";
        public static final String EPOCH = "epoch";
        public static final String E = "e";
        public static final String S_M_1 = "s_m_1";
        public static final String S_M_2 = "s_m_2";
        public static final String S_M_3 = "s_m_3";
        public static final String S_M_4 = "s_m_4";
        public static final String S_M_5 = "s_m_5";
        public static final String S_M_6 = "s_m_6";
        public static final String S_M_7 = "s_m_7";
        public static final String S_M_8 = "s_m_8";
        public static final String S_M_9 = "s_m_9";
        public static final String S_V = "s_v";
        public static final String S_M_R = "s_m_r";
        public static final String S_I = "s_i";
        public static final String S_E_I = "s_eI";
        public static final String S_E_II = "s_eII";
        public static final String C = "C";
        public static final String SIGMA_ROOF = "sigma_roof";
        public static final String SIGMA_ROOF_E_I = "sigma_roof_eI";
        public static final String SIGMA_ROOF_E_II = "sigma_roof_eII";
        public static final String SIGMA_PLANE_E_I = "sigma_plane_eI";
        public static final String SIGMA_PLANE_E_II = "sigma_plane_eII";
    }

    public class Errors {
        public static final String INS_SET_USER_IDENTIFIER = "Card personalization Error";
        public static final String INS_GET_USER_IDENTIFIER = "ID Request Error";
        public static final String INS_SET_REVOCATION_AUTHORITY_DATA = "Setting revocation Data Error";
        public static final String INS_GET_USER_IDENTIFIER_ATTRIBUTES = "ID and Attributes request Error";
        public static final String INS_SET_USER_ATTRIBUTES = "Attributes setting Error";
        public static final String INS_SET_ISSUER_SIGNATURES = "Issuer signatures setting Error";
        public static final String CMD_TEST_BIT_CHECKER = "Error setting Attributes disclosing";
        public static final String INS_COMPUTE_PROOF_OF_KNOWLEDGE_SEQ_DISCLOSED = "Proof of Knowledge computation Error";
        public static final String INS_GET_PROOF_OF_KNOWLEDGE = "Proof of Knowledge Data Request Error";
        public static final String INS_GET_USER_DISCLOSED_ATTRIBUTES = "Error setting Attributes disclosing";
        public static final String DEBUG_T = "Error during debug instruction";
    }
}
