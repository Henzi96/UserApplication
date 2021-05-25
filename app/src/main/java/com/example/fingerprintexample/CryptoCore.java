package com.example.fingerprintexample;

import android.content.Context;
import android.content.SharedPreferences;

import com.herumi.mcl.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class CryptoCore {

    CryptoCore(Context context) {
        this.context = context;
    }

    //Loads the native library specified by the library name
    static {
        String lib = "mcljava";
        System.loadLibrary(lib);
    }

    //Context reference
    private Context context;
    //Constant, which indicates exhausted or any other error state of (e_I, e_II, sigma_eI, sigma_eII) combination
    private final static String FAIL = "FAIL";
    //Constant, which indicates NOT_SET state of e1...ek
    private final static String NOT_SET = "NOT_SET";
    //Order of BN256 as a BigInteger
    BigInteger BN256_q = new BigInteger("2523648240000001ba344d8000000007ff9f800000000010a10000000000000d", 16);
    String BN256_g1_hex = "1 2523648240000001BA344D80000000086121000000000013A700000000000012 0000000000000000000000000000000000000000000000000000000000000001";
    private static final String SHA1_PADDING = "000000000000000000000000";
    String EMPTY = "";


    public boolean computeProofOfKnowledge() {
        //Initialization of MCL library. Curve type: BN254
        com.herumi.mcl.Mcl.SystemInit(MclConstants.BN254);
        //Removing old values
        removeOldValuesFromDatabase();
        /*
        Randomizers (e_I, e_II, sigma_eI, sigma_eII)
         1. e_I......... substring(0, 64).....[32 B]
         2. e_II........ substring(64, 128)...[32 B]
         3. sigma_eI.... substring(130, 198)..X substring(194, 258)..Y
         4. sigma_eII... substring(260, 324)..X substring(324, 388)..Y
         */
        String randomizersCombination = uniqueRandomizersCombinationFinder();
        if (randomizersCombination.equals(FAIL)) {
            return false;
        }
        //Initialization of "nonce"
        SharedPreferences sharedPreferences = context.getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
        String nonce = sharedPreferences.getString(Constants.SystemParameters.NONCE, Constants.SystemParameters.BYTE_0);
        //Initialization of g1
        G1 g1 = new G1();
        g1.setStr(BN256_g1_hex, 16);
        //Initialization of h_1 and h_2
        G1 h_1 = new G1();
        h_1.setStr(databaseCurvePointToMcl(Constants.SystemParameters.H_ + "1"), 16);
        G1 h_2 = new G1();
        h_2.setStr(databaseCurvePointToMcl(Constants.SystemParameters.H_ + "2"), 16);
        //"m_r" initialization
        Fr m_r = new Fr();
        m_r.setStr(sharedPreferences.getString(Constants.SystemParameters.M_R, EMPTY), 16);
        //"e_I" initialization
        Fr e_I = new Fr(randomizersCombination.substring(0, 64), 16);
        //"e_II" initialization
        Fr e_II = new Fr(randomizersCombination.substring(64, 128), 16);
        //"sigma_eI" initialization. 130 because the first byte is "04"
        G1 sigma_eI = new G1();
        sigma_eI.setStr("1 " + randomizersCombination.substring(130, 194) + " " + randomizersCombination.substring(194, 258), 16);
        //"sigma_eII initialization. 260 because the first byte is "04"
        G1 sigma_eII = new G1();
        sigma_eII.setStr("1 " + randomizersCombination.substring(260, 324) + " " + randomizersCombination.substring(324, 388), 16);
        //"i" computation
        Fr i = computeUnique_i(e_I, e_II);
        //"C" computation
        G1 C = computeUnique_C(i, g1);
        //Generating random numbers: ro, ro_v, ro_i, ro_m_r, (ro_m_1...ro_m_9) ∉ D, ro_eI, ro_eII
        //Each number is taken from Z_q group
        //ro initialization
        Fr ro = new Fr();
        ro.setByCSPRNG();
        //"ro_v" initialization
        Fr ro_v = new Fr();
        ro_v.setByCSPRNG();
        //"ro_i" initialization
        Fr ro_i = new Fr();
        ro_i.setByCSPRNG();
        //"ro_m_r" initialization
        Fr ro_m_r = new Fr();
        ro_m_r.setByCSPRNG();
        //"ro_eI" initialization
        Fr ro_eI = new Fr();
        ro_eI.setByCSPRNG();
        //"ro_eII" initialization
        Fr ro_eII = new Fr();
        ro_eII.setByCSPRNG();
        // (ro_m_1...ro_m_9) ∉ D initialization
        Fr[] ro_mz_container = computeRoMzValues();
        //"sigma_roof" computation
        G1 sigma_roof = computeSigma_roof(ro);
        //"sigma_roof_eI computation
        G1 sigma_roof_eI = computeSigma_roof_e(ro, sigma_eI);
        //"sigma_roof_eII computation
        G1 sigma_roof_eII = computeSigma_roof_e(ro, sigma_eII);
        //"sigma_plane_eI" computation
        G1 sigma_plane_eI = computeSigma_plane_e(e_I, sigma_roof_eI, g1, ro);
        //"sigma_plane_eII" computation
        G1 sigma_plane_eII = computeSigma_plane_e(e_II, sigma_roof_eII, g1, ro);
        //"sigma_xr" initialization
        G1 sigma_xr = new G1();
        sigma_xr.setStr(databaseCurvePointToMcl(Constants.SystemParameters.SIGMA_XR), 16);
        //"t_verify" computation
        G1 t_verify = computeTVerify(ro_v, ro_m_r, ro, sigma_xr, g1, ro_mz_container);
        //"t_revoke" computation
        G1 t_revoke = computeTRevoke(ro_m_r, ro_i, C);
        //"t_sig" computation
        G1 t_sig = computeTSig(ro_i, ro_eI, ro_eII, g1, h_1, h_2);
        //"t_sigI" computation
        G1 t_sig_I = computeTSig_I_II(ro_v, ro_eI, g1, sigma_roof_eI);
        //"t_sigII" computation
        G1 t_sig_II = computeTSig_I_II(ro_v, ro_eII, g1, sigma_roof_eII);
        //"e" computation
        Fr e = compute_e(t_verify, t_revoke, t_sig, t_sig_I, t_sig_II, sigma_roof, sigma_roof_eI, sigma_plane_eI, sigma_roof_eII, sigma_plane_eII, C, nonce);
        // "< s_mz > ∉ D computation
        Fr[] s_mz_container = computeSMzValues(ro_mz_container, e);
        //"s_v" computation
        Fr s_v = computeSv(ro_v, e, ro);
        //"s_m_r" computation
        Fr s_m_r = computeSMr(ro_m_r, e, m_r);
        //"s_i" computation
        Fr s_i = computeSi(ro_i, e, i);
        //"s_eI" computation
        Fr s_eI = computeSe_I_II(ro_eI, e, e_I);
        //"s_eI" computation
        Fr s_eII = computeSe_I_II(ro_eII, e, e_II);
        //Storing into Database (SharedPreferences)
        SharedPreferences.Editor editor = sharedPreferences.edit();
        //"e" storing
        editor.putString(Constants.SystemParameters.E, FrZeroFiller(e, 40));
        //"s_v" storing. "00" MultOS compatibility
        editor.putString(Constants.SystemParameters.S_V, Constants.SystemParameters.BYTE_0 + FrZeroFiller(s_v, 64));
        //"s_i" storing. "00" MultOS compatibility
        editor.putString(Constants.SystemParameters.S_I, Constants.SystemParameters.BYTE_0 + FrZeroFiller(s_i, 64));
        //"s_eI" storing
        editor.putString(Constants.SystemParameters.S_E_I, FrZeroFiller(s_eI, 64));
        //"s_eII" storing
        editor.putString(Constants.SystemParameters.S_E_II, FrZeroFiller(s_eII, 64));
        //"s_m_r" storing
        editor.putString(Constants.SystemParameters.S_M_R, FrZeroFiller(s_m_r, 64));
        //s_m_z storing
        store_s_m_z_container(s_mz_container);
        //"C" storing
        editor.putString(Constants.SystemParameters.C, mclCurvePointToDatabase(C));
        //"sigma_roof" storing
        editor.putString(Constants.SystemParameters.SIGMA_ROOF, mclCurvePointToDatabase(sigma_roof));
        //"sigma_roof_eI" storing
        editor.putString(Constants.SystemParameters.SIGMA_ROOF_E_I, mclCurvePointToDatabase(sigma_roof_eI));
        //"sigma_roof_eII storing
        editor.putString(Constants.SystemParameters.SIGMA_ROOF_E_II, mclCurvePointToDatabase(sigma_roof_eII));
        //"sigma_plane_eI" storing
        editor.putString(Constants.SystemParameters.SIGMA_PLANE_E_I, mclCurvePointToDatabase(sigma_plane_eI));
        //"sigma_plane_eII" storing
        editor.putString(Constants.SystemParameters.SIGMA_PLANE_E_II, mclCurvePointToDatabase(sigma_plane_eII));
        //debug-mode
        editor.putString("t_verify_debug", mclCurvePointToDatabase(t_verify));
        editor.putString("t_revoke_debug", mclCurvePointToDatabase(t_revoke));
        editor.putString("t_sig_debug", mclCurvePointToDatabase(t_sig));
        editor.putString("t_sig1_debug", mclCurvePointToDatabase(t_sig_I));
        editor.putString("t_sig2_debug", mclCurvePointToDatabase(t_sig_II));
        editor.putString("sigma_hat_debug", mclCurvePointToDatabase(sigma_roof));
        editor.putString("sigma_hat_e1_debug", mclCurvePointToDatabase(sigma_roof_eI));
        editor.putString("sigma_hat_e2_debug", mclCurvePointToDatabase(sigma_roof_eII));
        editor.putString("sigma_minus_e1_debug", mclCurvePointToDatabase(sigma_plane_eI));
        editor.putString("sigma_minus_e2_debug", mclCurvePointToDatabase(sigma_plane_eII));
        editor.putString("pseudonym_debug", mclCurvePointToDatabase(C));
        //SharedPreferences database Commit
        editor.commit();
        /*      *//*
        *
        *
        *
        ----------------VERIFIER PART:--------------------
        *
        *
        *
        */
        //VÝPOČET POVĚŘENÍ:
        //G1 povereni = VypoctiPovereni(g1);
        //G1 opravdove_povereni = new G1();
        //opravdove_povereni.setStr(databaseCurvePointToMcl("sigma"), 16);
        //Issuer/Verifier private keys
        //Fr[] x_keys = fill_xKeys();
        //Fr[] m_container = fill_m();
        //boolean t_verify_correctness = verify_t_verify(e, s_v, s_m_r, s_mz_container, sigma_roof, g1, x_keys, m_container, t_verify);
        //boolean t_revoke_correctness = verify_t_revoke(C, e, g1, s_m_r, s_i, t_revoke);
        //boolean t_sig_correctness = verify_t_sig(s_eI, s_eII, g1, h_1, h_2, s_i, t_sig);
        //boolean t_sigI_correctness = verify_t_sigI(s_v, s_eI, e, g1, sigma_roof_eI, sigma_plane_eI, t_sig_I);
        //boolean t_sigII_correctness = verify_t_sigII(s_v, s_eII, e, g1, sigma_roof_eII, sigma_plane_eII, t_sig_II);
        //boolean firstPairingCorectness = verify_Pairing(sigma_plane_eI, sigma_roof_eI);
        //boolean secondPairingCorectness = verify_Pairing(sigma_plane_eII, sigma_roof_eII);
        return true;
    }

    private void removeOldValuesFromDatabase() {
        SharedPreferences sharedPreferences = context.getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        for (int i = 1; i <= 9; i++) {
            editor.putString("s_m_" + i, "");
        }
        editor.commit();

    }

    private boolean verify_Pairing(G1 sigma_plane_e_I_II, G1 sigma_roof_e_I_II) {
        //g2 initialization
        G2 g2 = new G2();
        g2.setStr("1 12723517038133731887338407189719511622662176727675373276651903807414909099441 4168783608814932154536427934509895782246573715297911553964171371032945126671 13891744915211034074451795021214165905772212241412891944830863846330766296736 7937318970632701341203597196594272556916396164729705624521405069090520231616");
        //pk_RA initialization
        G2 pk_ra = new G2();
        pk_ra.setStr("1 11caba7ea42b9ab8084667c0de2a052d8797ed80deb988650cd0b286a4799e6f 93f5267e7cd73ef09381d78456555ee167ca7732ab2ffd752007674c15c7059 1bb987a2ac5a09ff0658c8d7dbdf9d533148bb92775d44357e2846d993978af7 1f05ef221f44468eefffa0cab0dcab931b7f36f438d491241912191a8d91bcb9", 16);
        // e(sigma_plane_eI, g2)
        GT e1 = new GT();
        GT e2 = new GT();
        com.herumi.mcl.Mcl.pairing(e1, sigma_plane_e_I_II, g2);
        com.herumi.mcl.Mcl.pairing(e2, sigma_roof_e_I_II, pk_ra);
        return e1.equals(e2);
    }


    private boolean verify_t_verify(Fr e, Fr s_v, Fr s_m_r, Fr[] s_mz_container, G1 sigma_roof, G1 g1, Fr[] x_keys, Fr[] m_container, G1 t_verify_user) {
        //Initialization of sharedPreferences
        SharedPreferences sharedPreferences = context.getSharedPreferences("UserData", Context.MODE_PRIVATE);
        //tmp1 = neg (e)
        Fr tmp1 = new Fr();
        com.herumi.mcl.Mcl.neg(tmp1, e);
        //x_0
        Fr x_0 = new Fr("12b45de28906d8ed87e757dcc612a02eec752e4ae68762a996a6a935c73bead8", 16);
        //tmp2 = neg_e * x_0
        Fr tmp2 = new Fr();
        com.herumi.mcl.Mcl.mul(tmp2, tmp1, x_0);
        //tmp3 = tmp2 * sigma_roof
        G1 tmp3 = new G1();
        com.herumi.mcl.Mcl.mul(tmp3, sigma_roof, tmp2);
        //tmp4 = s_v * g1
        G1 tmp4 = new G1();
        com.herumi.mcl.Mcl.mul(tmp4, g1, s_v);
        //x_r
        Fr x_r = new Fr("11d2d309e2d5b505dc824d452917780baa7e438e897c613d54989bbdea0cfa41", 16);
        //tmp5 = x_r * s_m_r
        Fr tmp5 = new Fr();
        com.herumi.mcl.Mcl.mul(tmp5, x_r, s_m_r);
        //tmp6 = tmp5 * sigma_roof
        G1 tmp6 = new G1();
        com.herumi.mcl.Mcl.mul(tmp6, sigma_roof, tmp5);
        //tmp7 = tmp3 + tmp4
        G1 tmp7 = new G1();
        com.herumi.mcl.Mcl.add(tmp7, tmp3, tmp4);
        //tmp8 = tmp7 + tmp6 (First part done)
        G1 tmp8 = new G1();
        com.herumi.mcl.Mcl.add(tmp8, tmp7, tmp6);
        //tmp9 = ∏ z ∉ D (s_m_z * x_z * sigma_roof). Second Part
        G1 tmp9 = new G1();
        tmp9.setStr("0");
        int total_number_of_attributes = Integer.parseInt(Objects.requireNonNull(sharedPreferences.getString("n", "00")), 16);
        int indexHolder_1 = 0;
        for (int i = 1; i <= total_number_of_attributes; i++) {
            if (Objects.equals(sharedPreferences.getString("m_" + i + "_disclosed", ""), "0") && !Objects.equals(sharedPreferences.getString("m_" + i, ""), "")) {
                Fr multiplier = new Fr();
                com.herumi.mcl.Mcl.mul(multiplier, x_keys[i], s_mz_container[indexHolder_1]);
                indexHolder_1++;
                G1 tmp = new G1();
                com.herumi.mcl.Mcl.mul(tmp, sigma_roof, multiplier);
                com.herumi.mcl.Mcl.add(tmp9, tmp9, tmp);
            }
        }
        //tmp10 = ∏ z ∈ D (-e * x_z * m_z). Third Part
        G1 tmp10 = new G1();
        tmp10.setStr("0");
        for (int i = 1; i <= total_number_of_attributes; i++) {
            if (Objects.equals(sharedPreferences.getString("m_" + i + "_disclosed", ""), "1") && !Objects.equals(sharedPreferences.getString("m_" + i, ""), "")) {
                Fr multiplier = new Fr();
                com.herumi.mcl.Mcl.mul(multiplier, tmp1, x_keys[i]);
                com.herumi.mcl.Mcl.mul(multiplier, multiplier, m_container[i - 1]);
                G1 tmp = new G1();
                com.herumi.mcl.Mcl.mul(tmp, sigma_roof, multiplier);
                com.herumi.mcl.Mcl.add(tmp10, tmp10, tmp);
            }
        }
        //tmp11 = tmp8 + tmp9
        G1 tmp11 = new G1();
        com.herumi.mcl.Mcl.add(tmp11, tmp8, tmp9);
        //t_verify = tmp11 + tmp10
        G1 t_verify = new G1();
        com.herumi.mcl.Mcl.add(t_verify, tmp11, tmp10);
        return t_verify.equals(t_verify_user);
    }

    private Fr[] fill_xKeys() {
        Fr[] x_keys = new Fr[11];
        //x_0
        x_keys[0] = new Fr("12b45de28906d8ed87e757dcc612a02eec752e4ae68762a996a6a935c73bead8", 16);
        //x_1
        x_keys[1] = new Fr("039961afcbe66b41b243401f4317e2eb0c7eb20aa7a185f21c2c53f8630a5f4b", 16);
        //x_2
        x_keys[2] = new Fr("0523a2dd0ca456bfd4361948701077011f72769a670a4fefc550a180245296e2", 16);
        //x_3
        x_keys[3] = new Fr("094b1477362c4f457c6f48b64776c7b21204cefd487689b0e8edd52a933c02af", 16);
        //x_4
        x_keys[4] = new Fr("05ef34e84bd80d767cb770456d6a1dcefb1eecb5c54d521b8620a1f1af34c2e7", 16);
        //x_5
        x_keys[5] = new Fr("1b7e825b700bba59abd6a96687e00fe87d089f872c38451d478827515aa47b3a", 16);
        //x_6
        x_keys[6] = new Fr("0f5d8bac94cc8ccc9fd097148df969a31ebabe1e1f0ecf7cab2c30f5c20609e5", 16);
        //x_7
        x_keys[7] = new Fr("16c414dc810acb3d2847337ce7a3d9939d6e70e6d08930889ef9ea310de42c3f", 16);
        //x_8
        x_keys[8] = new Fr("1a187d05038ee5507321059ed738094293a149267468cedc64cdb0fb72ca5e3b", 16);
        //x_9
        x_keys[9] = new Fr("0bacce740cce122ad0ea0a3d83da1ec99430b17e29de7eaaa6197f9cb876e70a", 16);
        //x_r
        x_keys[10] = new Fr("11d2d309e2d5b505dc824d452917780baa7e438e897c613d54989bbdea0cfa41", 16);
        return x_keys;

    }


    private Fr[] fill_m() {
        Fr[] m_container = new Fr[5];
        //m_1
        m_container[0] = new Fr("1b2aed725be94eaf356249331ed2ba2257bda9c3839dffdd97b6e6072ddef468", 16);
        //m_2
        m_container[1] = new Fr("08f8efe02fb337d7a679984a831940d4ace40a98c5c13b1da1f678ff3b60b859", 16);
        //m_3
        m_container[2] = new Fr("0a8c3d9811128ba743e931b4ad28cf0ab5301495ea1ab493f20b7e3aa23e468b", 16);
        //m_4
        m_container[3] = new Fr("1cee3bb1a9147c15b97f634893fa656ca33b1540e399dfbaeb51f646c5889fe5", 16);
        //m_5
        m_container[4] = new Fr("21738f24782061d4ec2ef4d3e626c85951e4c8717bfe15b39ba93d3e27c1f803", 16);
        return m_container;
    }

    private boolean verify_t_sigII(Fr s_v, Fr s_eII, Fr e, G1 g1, G1 sigma_roof_eII, G1 sigma_plane_eII, G1 t_sigII_user) {
        //tmp1 = s_v * g1
        G1 tmp1 = new G1();
        com.herumi.mcl.Mcl.mul(tmp1, g1, s_v);
        //tmp2 = s_eII * sigma_roof_eII
        G1 tmp2 = new G1();
        com.herumi.mcl.Mcl.mul(tmp2, sigma_roof_eII, s_eII);
        //tmp3 = neg (e)
        Fr neg_e = new Fr();
        com.herumi.mcl.Mcl.neg(neg_e, e);
        //tmp4 = neg_e * sigma_plane_eII
        G1 tmp4 = new G1();
        com.herumi.mcl.Mcl.mul(tmp4, sigma_plane_eII, neg_e);
        //tmp5 = tmp1 + tmp2
        G1 tmp5 = new G1();
        com.herumi.mcl.Mcl.add(tmp5, tmp1, tmp2);
        //t_sigII = tmp5 + tmp4
        G1 t_sigII = new G1();
        com.herumi.mcl.Mcl.add(t_sigII, tmp5, tmp4);
        String t_sigII_USER_side = t_sigII_user.toString();
        String t_sigII_VERIFIER_side = t_sigII.toString();
        return t_sigII_USER_side.equals(t_sigII_VERIFIER_side);
    }

    private boolean verify_t_sigI(Fr s_v, Fr s_eI, Fr e, G1 g1, G1 sigma_roof_eI, G1 sigma_plane_eI, G1 t_sigI_user) {
        //tmp1 = s_v * g1
        G1 tmp1 = new G1();
        com.herumi.mcl.Mcl.mul(tmp1, g1, s_v);
        //tmp2 = s_eI * sigma_roof_eI
        G1 tmp2 = new G1();
        com.herumi.mcl.Mcl.mul(tmp2, sigma_roof_eI, s_eI);
        //tmp3 = neg (e)
        Fr neg_e = new Fr();
        com.herumi.mcl.Mcl.neg(neg_e, e);
        //tmp4 = neg_e * sigma_plane_eI
        G1 tmp4 = new G1();
        com.herumi.mcl.Mcl.mul(tmp4, sigma_plane_eI, neg_e);
        //tmp5 = tmp1 + tmp2
        G1 tmp5 = new G1();
        com.herumi.mcl.Mcl.add(tmp5, tmp1, tmp2);
        //t_sigI = tmp5 + tmp4
        G1 t_sigI = new G1();
        com.herumi.mcl.Mcl.add(t_sigI, tmp5, tmp4);
        String t_sigI_USER_side = t_sigI_user.toString();
        String t_sigI_VERIFIER_side = t_sigI.toString();
        return t_sigI_USER_side.equals(t_sigI_VERIFIER_side);
    }

    private boolean verify_t_sig(Fr s_eI, Fr s_eII, G1 g1, G1 h_1, G1 h_2, Fr s_i, G1 t_sig_user) {
        //tmp1 = s_i * g1
        G1 tmp1 = new G1();
        com.herumi.mcl.Mcl.mul(tmp1, g1, s_i);
        //tmp2 = s_eI * h_1
        G1 tmp2 = new G1();
        com.herumi.mcl.Mcl.mul(tmp2, h_1, s_eI);
        //tmp3 = s_eII * h_2
        G1 tmp3 = new G1();
        com.herumi.mcl.Mcl.mul(tmp3, h_2, s_eII);
        //tmp4 = tmp1 + tmp2
        G1 tmp4 = new G1();
        com.herumi.mcl.Mcl.add(tmp4, tmp1, tmp2);
        //t_sig = tmp4 + tmp3
        G1 t_sig = new G1();
        com.herumi.mcl.Mcl.add(t_sig, tmp4, tmp3);
        String t_sig_USER_side = t_sig_user.toString();
        String t_sig_VERIFIER_side = t_sig.toString();
        return t_sig_USER_side.equals(t_sig_VERIFIER_side);
    }

    private boolean verify_t_revoke(G1 C, Fr e, G1 g1, Fr s_m_r, Fr s_i, G1 t_revoke_user) {
        //Initialization of SharedPreferences database
        SharedPreferences sharedPreferences = context.getSharedPreferences("UserData", Context.MODE_PRIVATE);
        //tmp1  = SHA1(epoch)
        //Conversion of Epoch into Fr using SHA-1
        String epoch_hash = new BigInteger(SHA1_PADDING + SHA1(sharedPreferences.getString("epoch", "00")), 16).mod(BN256_q).toString(16);
        Fr tmp1 = new Fr(epoch_hash, 16);
        //tmp2 = neg (tmp1)
        Fr tmp2 = new Fr();
        com.herumi.mcl.Mcl.neg(tmp2, tmp1);
        //tmp3 = tmp2 * C
        G1 tmp3 = new G1();
        com.herumi.mcl.Mcl.mul(tmp3, C, tmp2);
        //tmp4 = g1 + tmp3
        G1 tmp4 = new G1();
        com.herumi.mcl.Mcl.add(tmp4, g1, tmp3);
        //tmp5 = neg (e)
        Fr tmp5 = new Fr();
        com.herumi.mcl.Mcl.neg(tmp5, e);
        //tmp6 = tmp5 * tmp4
        G1 tmp6 = new G1();
        com.herumi.mcl.Mcl.mul(tmp6, tmp4, tmp5);
        //tmp7 = s_m_r * C
        G1 tmp7 = new G1();
        com.herumi.mcl.Mcl.mul(tmp7, C, s_m_r);
        //tmp8 = s_i * C
        G1 tmp8 = new G1();
        com.herumi.mcl.Mcl.mul(tmp8, C, s_i);
        //tmp9 = tmp6 + tmp7
        G1 tmp9 = new G1();
        com.herumi.mcl.Mcl.add(tmp9, tmp6, tmp7);
        //t_revoke = tmp9 + tmp8
        G1 t_revoke = new G1();
        com.herumi.mcl.Mcl.add(t_revoke, tmp9, tmp8);
        //Comparison
        String t_revoke_USER_side = t_revoke_user.toString();
        String t_revoke_VERIFIER_side = t_revoke.toString();
        return t_revoke_USER_side.equals(t_revoke_VERIFIER_side);
    }


    //This method produce the unique combination of (e_1.......e_k) and corresponding (sigma_e1.....sigma_ek)
    //if there is no unique pair or "k" is not set or "k" is 0, then the method returns "EXHAUSTED"
    private String uniqueRandomizersCombinationFinder() {
        //initialization of shared preferences
        SharedPreferences sharedPreferences = context.getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
        //Getting "k" value
        int k = Integer.parseInt(Objects.requireNonNull(sharedPreferences.getString(Constants.SystemParameters.K, "00")), 16);
        if (k == 0) {
            return FAIL;
        }
        //Searching "not_used" combination
        for (int i = 1; i <= k; i++) {
            for (int j = 1; j <= k; j++) {
                if (Objects.equals(sharedPreferences.getString(Constants.SystemParameters.E_ + i + Constants.SystemParameters.E_ + j, "not_used"), "not_used")) {
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    editor.putString(Constants.SystemParameters.E_ + i + Constants.SystemParameters.E_ + j, "used");
                    editor.commit();
                    String uniqueRandomizersCombination = sharedPreferences.getString("e_" + i, NOT_SET) + sharedPreferences.getString(Constants.SystemParameters.E_ + j, NOT_SET) + sharedPreferences.getString(Constants.SystemParameters.SIGMA_E + i, NOT_SET) + sharedPreferences.getString(Constants.SystemParameters.SIGMA_E + j, NOT_SET);
                    if (uniqueRandomizersCombination.contains(NOT_SET)) {
                        return FAIL;
                    }
                    return uniqueRandomizersCombination;
                }
            }

        }
        //Exhausted combinations
        return FAIL;
    }

    //This method computes "i" value. i = { (a_1 * e_I mod q) + (a_2 * e_II mod q) } mod q
    private Fr computeUnique_i(Fr e_I, Fr e_II) {
        //Initialization of shared preferences
        SharedPreferences sharedPreferences = context.getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
        //Initialization of a_1
        Fr a_1 = new Fr(sharedPreferences.getString(Constants.SystemParameters.A_ + "1", Constants.SystemParameters.BYTE_0), 16);
        //Initialization of a_2
        Fr a_2 = new Fr(sharedPreferences.getString(Constants.SystemParameters.A_ + "2", Constants.SystemParameters.BYTE_0), 16);
        //Returning "i"
        Fr tmp_1 = new Fr();
        Fr tmp_2 = new Fr();
        Fr i = new Fr();
        com.herumi.mcl.Mcl.mul(tmp_1, a_1, e_I);
        com.herumi.mcl.Mcl.mul(tmp_2, a_2, e_II);
        com.herumi.mcl.Mcl.add(i, tmp_1, tmp_2);
        return i;
    }


    //This method returns an array of random BigIntegers. Number of elements in array will be the same as the number of hidden attributes
    private Fr[] computeRoMzValues() {
        //Initialization of shared preferences
        SharedPreferences sharedPreferences = context.getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
        int number_of_hidden_attributes = Integer.parseInt(Objects.requireNonNull(sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_HIDDEN_ATTRIBUTES, Constants.SystemParameters.BYTE_0)), 16);
        if (number_of_hidden_attributes == 0) {
            //All attributes are disclosed (except revocation handler m_r)
            return new Fr[0];
        }
        Fr[] roMzContainer = new Fr[number_of_hidden_attributes];
        for (int i = 0; i < number_of_hidden_attributes; i++) {
            Fr tmp = new Fr();
            tmp.setByCSPRNG();
            roMzContainer[i] = tmp;
        }
        return roMzContainer;
    }


    private G1 computeUnique_C(Fr i, G1 g1) {
        //Initialization of Shared Preferences
        SharedPreferences sharedPreferences = context.getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
        //Fr initializations
        Fr multiplier = new Fr();
        Fr tmp_1 = new Fr();
        Fr tmp_2 = new Fr();
        Fr m_r = new Fr(sharedPreferences.getString(Constants.SystemParameters.M_R, Constants.SystemParameters.BYTE_0), 16);
        //"i" - "m_r"
        com.herumi.mcl.Mcl.sub(tmp_1, i, m_r);
        //Conversion of Epoch into Fr using SHA-1
        String epoch_hash = new BigInteger(SHA1_PADDING +
                SHA1(sharedPreferences.getString(Constants.SystemParameters.EPOCH, Constants.SystemParameters.BYTE_0)), 16)
                .mod(BN256_q).toString(16);
        Fr epoch_tmp = new Fr(epoch_hash, 16);
        //(i - m_r) + SHA1(epoch)
        com.herumi.mcl.Mcl.add(tmp_2, tmp_1, epoch_tmp);
        // denominator
        com.herumi.mcl.Mcl.div(multiplier, new Fr(1), tmp_2);
        //Initialization of C
        G1 C = new G1();
        //Computation of C --> C = multiplier * g1
        com.herumi.mcl.Mcl.mul(C, g1, multiplier);
        return C;
    }

    private G1 computeSigma_roof(Fr ro) {
        G1 sigma = new G1();
        sigma.setStr(databaseCurvePointToMcl(Constants.SystemParameters.SIGMA), 16);
        G1 sigma_roof = new G1();
        //sigma_roof = ro * sigma
        com.herumi.mcl.Mcl.mul(sigma_roof, sigma, ro);
        return sigma_roof;
    }

    private G1 computeSigma_roof_e(Fr ro, G1 sigma_e) {
        G1 sigma_roof_e = new G1();
        //sigma_roof_eI = ro * sigma_e(I OR II)
        com.herumi.mcl.Mcl.mul(sigma_roof_e, sigma_e, ro);
        return sigma_roof_e;
    }


    private G1 computeSigma_plane_e(Fr e_I, G1 sigma_roof_e, G1 g1, Fr ro) {
        //inversion of e_(I or II)
        Fr e_neg = new Fr();
        com.herumi.mcl.Mcl.neg(e_neg, e_I);
        //e_neg * sigma_roof_e(I or II)
        G1 tmp_1 = new G1();
        com.herumi.mcl.Mcl.mul(tmp_1, sigma_roof_e, e_neg);
        //ro * g1
        G1 tmp_2 = new G1();
        com.herumi.mcl.Mcl.mul(tmp_2, g1, ro);
        //results addition
        G1 sigma_plane_e = new G1();
        com.herumi.mcl.Mcl.add(sigma_plane_e, tmp_1, tmp_2);
        return sigma_plane_e;


    }

    private G1 computeTVerify(Fr ro_v, Fr ro_m_r, Fr ro, G1 sigma_xr, G1 g1, Fr[] ro_mz_container) {
        //Initialization of shared preferences
        SharedPreferences sharedPreferences = context.getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
        //tmp1 = ro_v * g1
        G1 tmp1 = new G1();
        com.herumi.mcl.Mcl.mul(tmp1, g1, ro_v);
        //ro_m_r * ro
        Fr multiplier_1 = new Fr();
        com.herumi.mcl.Mcl.mul(multiplier_1, ro_m_r, ro);
        //tmp2 = multiplier * sigma_xr
        G1 tmp2 = new G1();
        com.herumi.mcl.Mcl.mul(tmp2, sigma_xr, multiplier_1);
        //tmp3 = tmp1 + tmp2
        G1 tmp3 = new G1();
        com.herumi.mcl.Mcl.add(tmp3, tmp1, tmp2);
        // ∏ z ∉ D (ro_mz * ro * sigma_xz)
        //Computation of tmp4
        G1 tmp4 = new G1();
        tmp4.setStr("0");
        int total_number_of_attributes = Integer.parseInt(Objects.requireNonNull(sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, Constants.SystemParameters.BYTE_0)), 16);
        int indexHolder = 0;
        for (int i = 1; i <= total_number_of_attributes; i++) {
            if (!Objects.equals(sharedPreferences.getString(Constants.SystemParameters.SIGMA_X + i, EMPTY), EMPTY) && Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i + "_disclosed", EMPTY), "0") && !Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i, EMPTY), EMPTY)) {
                Fr multiplier_2 = new Fr();
                com.herumi.mcl.Mcl.mul(multiplier_2, ro_mz_container[indexHolder], ro);
                indexHolder++;
                G1 sigma_xz = new G1();
                sigma_xz.setStr(databaseCurvePointToMcl(Constants.SystemParameters.SIGMA_X + i), 16);
                G1 tmp = new G1();
                com.herumi.mcl.Mcl.mul(tmp, sigma_xz, multiplier_2);
                com.herumi.mcl.Mcl.add(tmp4, tmp4, tmp);
            }
        }
        G1 t_verify = new G1();
        com.herumi.mcl.Mcl.add(t_verify, tmp3, tmp4);
        return t_verify;
    }

    private G1 computeTRevoke(Fr ro_m_r, Fr ro_i, G1 C) {
        //tmp1 = ro_m_r * C
        G1 tmp1 = new G1();
        com.herumi.mcl.Mcl.mul(tmp1, C, ro_m_r);
        //tmp2 = ro_i * C
        G1 tmp2 = new G1();
        com.herumi.mcl.Mcl.mul(tmp2, C, ro_i);
        //t_revoke = tmp1 + tmp2
        G1 t_revoke = new G1();
        com.herumi.mcl.Mcl.add(t_revoke, tmp1, tmp2);
        return t_revoke;
    }

    private G1 computeTSig(Fr ro_i, Fr ro_eI, Fr ro_eII, G1 g1, G1 h_1, G1 h_2) {
        //tmp1 = ro_i * g1
        G1 tmp1 = new G1();
        com.herumi.mcl.Mcl.mul(tmp1, g1, ro_i);
        //tmp2 = ro_eI * h_1
        G1 tmp2 = new G1();
        com.herumi.mcl.Mcl.mul(tmp2, h_1, ro_eI);
        //tmp3 = ro_eII * h_2
        G1 tmp3 = new G1();
        com.herumi.mcl.Mcl.mul(tmp3, h_2, ro_eII);
        //tmp4 = tmp1 + tmp2
        G1 tmp4 = new G1();
        com.herumi.mcl.Mcl.add(tmp4, tmp1, tmp2);
        //t_sig = tmp4 + tmp3
        G1 t_sig = new G1();
        com.herumi.mcl.Mcl.add(t_sig, tmp4, tmp3);
        return t_sig;
    }

    private G1 computeTSig_I_II(Fr ro_v, Fr ro_e, G1 g1, G1 sigma_roof_e) {
        //tmp1 = ro_v * g1
        G1 tmp1 = new G1();
        com.herumi.mcl.Mcl.mul(tmp1, g1, ro_v);
        //tmp2 = ro_e * sigma_roof_e
        G1 tmp2 = new G1();
        com.herumi.mcl.Mcl.mul(tmp2, sigma_roof_e, ro_e);
        //t_sig_I_II = tmp1 + tmp2
        G1 t_sig_I_II = new G1();
        com.herumi.mcl.Mcl.add(t_sig_I_II, tmp1, tmp2);
        return t_sig_I_II;
    }

    private Fr compute_e(G1 t_verify, G1 t_revoke, G1 t_sig, G1 t_sig_I, G1 t_sig_II, G1 sigma_roof, G1 sigma_roof_eI, G1 sigma_plane_eI, G1 sigma_roof_eII, G1 sigma_plane_eII, G1 C, String nonce) {
        String t_verify_HEX = mclCurvePointToDatabase(t_verify);
        String t_revoke_HEX = mclCurvePointToDatabase(t_revoke);
        String t_sig_HEX = mclCurvePointToDatabase(t_sig);
        String t_sig_I_HEX = mclCurvePointToDatabase(t_sig_I);
        String t_sig_II_HEX = mclCurvePointToDatabase(t_sig_II);
        String sigma_roof_HEX = mclCurvePointToDatabase(sigma_roof);
        String sigma_roof_eI_HEX = mclCurvePointToDatabase(sigma_roof_eI);
        String sigma_plane_eI_HEX = mclCurvePointToDatabase(sigma_plane_eI);
        String sigma_roof_eII_HEX = mclCurvePointToDatabase(sigma_roof_eII);
        String sigma_plane_eII_HEX = mclCurvePointToDatabase(sigma_plane_eII);
        String C_HEX = mclCurvePointToDatabase(C);
        String hash = SHA1(t_verify_HEX + t_revoke_HEX + t_sig_HEX + t_sig_I_HEX + t_sig_II_HEX + sigma_roof_HEX + sigma_roof_eI_HEX + sigma_roof_eII_HEX + sigma_plane_eI_HEX + sigma_plane_eII_HEX + C_HEX + nonce);
        BigInteger hash_mod_q_BigInt = new BigInteger(SHA1_PADDING + hash, 16);
        hash_mod_q_BigInt.mod(BN256_q);
        hash = hash_mod_q_BigInt.toString(16);
        Fr e = new Fr();
        e.setStr(hash, 16);
        return e;
    }

    private String mclCurvePointToDatabase(G1 curvePoint) {
        String curvePointMcl = curvePoint.toString();
        String x_decimal_string = "";
        String y_decimal_string = "";
        int indexHolder = 2;
        for (int i = 2; i < curvePointMcl.length(); i++) {
            if (!curvePointMcl.substring(i, i + 1).equals(" ")) {
                x_decimal_string += curvePointMcl.substring(i, i + 1);
                indexHolder++;
            } else {
                indexHolder++;
                break;
            }
        }
        for (int i = indexHolder; i < curvePointMcl.length(); i++) {
            y_decimal_string += curvePointMcl.substring(i, i + 1);
        }
        BigInteger x_decimal = new BigInteger(x_decimal_string);
        BigInteger y_decimal = new BigInteger(y_decimal_string);
        String x_hex = x_decimal.toString(16);
        String y_hex = y_decimal.toString(16);
        if (x_hex.length() < 64) {
            String prefix_x = "";
            int number_of_zeros = 64 - x_hex.length();
            for (int i = 0; i < number_of_zeros; i++) {
                prefix_x += "0";
            }
            x_hex = prefix_x + x_hex;
        }
        if (y_hex.length() < 64) {
            String prefix_y = "";
            int number_of_zeros = 64 - y_hex.length();
            for (int i = 0; i < number_of_zeros; i++) {
                prefix_y += "0";
            }
            y_hex = prefix_y + y_hex;
        }
        return "04" + x_hex.toUpperCase() + y_hex.toUpperCase();
    }

    private String databaseCurvePointToMcl(String parameter_key) {
        //Initialization of Shared Preferences
        SharedPreferences sharedPreferences = context.getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
        String param = sharedPreferences.getString(parameter_key, "");
        if (param.length() != 130) {
            throw new NumberFormatException("Parameter is not set!");
        }
        //"04" is redundant
        return "1 " + param.substring(2, 66) + " " + param.substring(66, 130);
    }

    private Fr[] computeSMzValues(Fr[] ro_mz_container, Fr e) {
        //Initialization of sharedPreferences
        SharedPreferences sharedPreferences = context.getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
        //Initialization of s_mz container. Length is going to be the same as the length of ro_mz_container
        Fr[] s_mz_container = new Fr[ro_mz_container.length];
        //Getting the number of all issued attributes
        int number_of_all_attributes = Integer.parseInt(Objects.requireNonNull(sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, Constants.SystemParameters.BYTE_0)), 16);
        //Computing of s_mz
        //Indexholder for ro_mz_container
        int indexHolder = 0;
        for (int i = 1; i <= number_of_all_attributes; i++) {
            if (!Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i, EMPTY), EMPTY) && !Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i + "_disclosed", "0"), "1")) {
                //tmp1 = e * mz
                Fr tmp1 = new Fr();
                Fr m_z = new Fr();
                m_z.setStr(sharedPreferences.getString(Constants.SystemParameters.M_ + i, ""), 16);
                com.herumi.mcl.Mcl.mul(tmp1, e, m_z);
                //sm_z = ro_mz - tmp1
                Fr sm_z = new Fr();
                com.herumi.mcl.Mcl.sub(sm_z, ro_mz_container[indexHolder], tmp1);
                s_mz_container[indexHolder] = sm_z;
                indexHolder++;
            }
        }
        return s_mz_container;
    }

    private Fr computeSv(Fr ro_v, Fr e, Fr ro) {
        //tmp1 = e * ro
        Fr tmp1 = new Fr();
        com.herumi.mcl.Mcl.mul(tmp1, e, ro);
        //s_v = ro_v + tmp1
        Fr s_v = new Fr();
        com.herumi.mcl.Mcl.add(s_v, ro_v, tmp1);
        return s_v;
    }

    private Fr computeSMr(Fr ro_m_r, Fr e, Fr m_r) {
        //tmp1 = e * m_r
        Fr tmp1 = new Fr();
        com.herumi.mcl.Mcl.mul(tmp1, e, m_r);
        //s_m_r = ro_m_r - tmp1
        Fr s_m_r = new Fr();
        com.herumi.mcl.Mcl.sub(s_m_r, ro_m_r, tmp1);
        return s_m_r;
    }

    private Fr computeSi(Fr ro_i, Fr e, Fr i) {
        //tmp1 = e * i
        Fr tmp1 = new Fr();
        com.herumi.mcl.Mcl.mul(tmp1, e, i);
        //s_i = ro_i + tmp1
        Fr s_i = new Fr();
        com.herumi.mcl.Mcl.add(s_i, ro_i, tmp1);
        return s_i;
    }

    private Fr computeSe_I_II(Fr ro_e_i, Fr e, Fr e_I_II) {
        //tmp1 = e * e_I_II
        Fr tmp1 = new Fr();
        com.herumi.mcl.Mcl.mul(tmp1, e, e_I_II);
        //s_e_I_II = ro_e_i - tmp1
        Fr s_e_I_II = new Fr();
        com.herumi.mcl.Mcl.sub(s_e_I_II, ro_e_i, tmp1);
        return s_e_I_II;
    }

    private String FrZeroFiller(Fr number, int length) {
        String number_hex = number.toString(16);
        if (number_hex.length() < length) {
            String prefix = "";
            int number_of_zeros = length - number_hex.length();
            for (int i = 0; i < number_of_zeros; i++) {
                prefix += "0";
            }
            number_hex = prefix + number_hex;
        }
        return number_hex.toUpperCase();
    }

    //This method is storing s_m_z into SharedPreferences database
    private void store_s_m_z_container(Fr[] s_mz_container) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(Constants.SystemParameters.USER_DATA, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        int number_of_all_attributes = Integer.parseInt(Objects.requireNonNull(sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, Constants.SystemParameters.BYTE_0)), 16);
        int indexHolder = 0;
        for (int i = 1; i <= number_of_all_attributes; i++) {
            if (!Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i, ""), "") && !Objects.equals(sharedPreferences.getString(Constants.SystemParameters.M_ + i + "_disclosed", "0"), "1")) {
                editor.putString("s_m_" + i, FrZeroFiller(s_mz_container[indexHolder], 64));
                indexHolder++;
            }
        }
        editor.commit();
    }

    //This method returns output of SHA-1 hash function
    private String SHA1(String input) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        md.update(input.getBytes());
        byte[] digest = md.digest();
        return Utils.byteArrayToHexString(digest).toUpperCase();
    }

    //This method returns output of SHA-256 hash function
    public String SHA256_Android(String input) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        md.update(input.getBytes());
        byte[] digest = md.digest();
        return toLittleEndian(Utils.byteArrayToHexString(digest).toUpperCase());
    }

    private static String toLittleEndian(String bigEndian) {
        String littleEndian = "";
        int lengthHolder = bigEndian.length();
        for (int i = 0; i < 32; i++) {
            littleEndian += bigEndian.substring(lengthHolder - 2, lengthHolder);
            lengthHolder -= 2;
        }
        return littleEndian;
    }

}