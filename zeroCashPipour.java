package examples.generators;

import util.Util;

import java.math.BigInteger;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.MerkleTreePathGadgetSha2;
import examples.gadgets.hash.SHA256Gadget;

public class zeroCashPipour extends CircuitGenerator {
    /*
        util concat 으로
        input  : x  =  rt, sn_1_old, sn_2_old, cm_1_new, cm_2_new (vPub, info)
        witness: a  =  copath1, copath2, c_1_old, c_2_old, addr_old_sk1, addr_old_sk2, c_1_mew, c_2_new
        
    */

    // input x
    private Wire[] rt;
    private Wire[] sn_old;
    private Wire v_pub;
    // private Wire[] cm_new;    // witness에도 있음
    
    // witness a
    private Wire[] copathIntermediateHash;
    private Wire copathDirectionSelector;

    private Wire[] c_old; //21  =>  0~7 : a,     8 : _enc,     9~12 : v rho r s,     13~20 : cm
    private Wire[] c_new;
 
    private Wire[] addr_old_sk; // 2 => 0 : a,     1 : _enc
    

    private int leafWordBitWidth = 32;  // 각 word의 bit
    private int HashDigestDimension = 8;
    private int treeHeight = 2;


    private MerkleTreePathGadgetSha2 merkleTreeGadgetSha2;
    
    public zeroCashPipour(String circuitName) {
        super(circuitName);
    }

    private SHA256Gadget sha2Gadget;

    @Override
    protected void buildCircuit() {

        rt = createInputWireArray(HashDigestDimension, "Merkle Tree Root");
        sn_old = createInputWireArray(HashDigestDimension, "sn_old");
        v_pub = createInputWire("v_pub");
        // cm_new = createInputWireArray(HashDigestDimension, "cm_new");

        copathIntermediateHash = createProverWitnessWireArray(HashDigestDimension * treeHeight, "intermediateHash of cm old");
        copathDirectionSelector = createProverWitnessWire("direction of cm old");
        c_old = createProverWitnessWireArray(21, "C_old");
        c_new = createProverWitnessWireArray(21, "C_new");
        addr_old_sk = createProverWitnessWireArray(2, "a_old_sk");

        Wire a_old_sk = addr_old_sk[0];
        Wire sk_old_enc = addr_old_sk[1];

        Wire[] a_old_pk = new Wire[8];
        Wire pk_old_enc = c_old[8];
        Wire v_old      = c_old[9];
        Wire rho_old    = c_old[10];
        Wire r_old      = c_old[11];
        Wire s_old      = c_old[12];
        Wire[] cm_old   = new Wire[8];


        Wire[] a_new_pk = new Wire[8];
        Wire pk_new_enc = c_new[8];
        Wire v_new      = c_new[9];
        Wire rho_new    = c_new[10];
        Wire r_new      = c_new[11];
        Wire s_new      = c_new[12];
        Wire[] cm_new   = new Wire[8];

        for (int i=0; i<8; i++){
            a_old_pk[i] = c_old[i];
            cm_old[i]   = c_old[13 + i];

            a_new_pk[i] = c_new[i];
            cm_new[i]   = c_new[13 + i];   
        }

        merkleTreeGadgetSha2 = new MerkleTreePathGadgetSha2(
                copathDirectionSelector, cm_old, copathIntermediateHash, leafWordBitWidth, treeHeight);
        Wire[] actualRoot = merkleTreeGadgetSha2.getOutputWires();

        Wire errorAccumulator = getZeroWire();
        for(int i = 0; i < HashDigestDimension; i++){
            Wire diff = actualRoot[i].sub(rt[i]);
            Wire check = diff.checkNonZero();
            errorAccumulator = errorAccumulator.add(check);
        }
        makeOutput(errorAccumulator.checkNonZero(), "if NON-zero, cm_old is not in MerkleTree");
        // addEqualityAssertion(errorAccumulator.checkNonZero(), new BigInteger("0"), "cm_old is invalid");


        
        /*
        PRF addr x (z) := PRF x (00 || z) := CRH(x || 00 || z) 
        PRF sn x (z) := PRF x (01 || z) := CRH(x || 01 || z)
        PRF pk x (z) := PRF x (10 || z) := CRH(x || 10 || z)
        */

        Wire addrPad = createConstantWire(new BigInteger("0"));
        Wire snPad = createConstantWire(new BigInteger("1"));
        Wire pkPad = createConstantWire(new BigInteger("2"));

        // check a_old_pk
        // PRF addr x (0) := PRF x (00 || 0) := CRH(x || 00 || 0) 
        Wire[] calculated_a_old_pk = new WireArray(_concatAndHash2(
            a_old_sk.getBitWires(256).asArray(),
            addrPad.getBitWires(256).asArray()
        )).packBitsIntoWords(32);

        errorAccumulator = getZeroWire();
        for(int i = 0; i < 8; i++){
            Wire diff = calculated_a_old_pk[i].sub(a_old_pk[i]);
            Wire check = diff.checkNonZero();
            errorAccumulator = errorAccumulator.add(check);
        }
        makeOutput(errorAccumulator.checkNonZero(), "if NON-zero, a_old_pk is invalid");
        // addEqualityAssertion(errorAccumulator.checkNonZero(), new BigInteger("0"), "a_old_pk is invalid");
    

        //check sn_old
        Wire[] calculated_sn_old = new WireArray(_concatAndHash3(
            a_old_sk.getBitWires(256).asArray(),
            snPad.getBitWires(2).asArray(),
            rho_old.getBitWires(254).asArray()
        )).packBitsIntoWords(32);

        errorAccumulator = getZeroWire();
        for(int i = 0; i < 8; i++){
            Wire diff = calculated_sn_old[i].sub(sn_old[i]);
            Wire check = diff.checkNonZero();
            errorAccumulator = errorAccumulator.add(check);
        }
        makeOutput(errorAccumulator.checkNonZero(), "if NON-zero, sn_old is invalid");
    


        /*
        COMM_r(a_pk || rho) = CRH(r || CRH(a_pk || rho))
        COMM_s(v||k) = CRH(k || 0^192 || v)

        cm = COMM_s( COMM_r(a_pk || rho) || v )
        */


        // check cm_old
        Wire[] tmp1 =  truncating(
            _concatAndHash2(
                new WireArray(a_old_pk).getBits(32).asArray(),
                rho_old.getBitWires(256).asArray()
            ),
            128
        );
        Wire[] tmp2 = _concatAndHash2(r_old.getBitWires(256).asArray(), tmp1);
        Wire[] calculated_cm_old = new WireArray( _concatAndHash3(
            tmp2,
            zeroWire.getBitWires(192).asArray(),
            v_old.getBitWires(256).asArray()
        )).packBitsIntoWords(32); 
        
        errorAccumulator = getZeroWire();
        for(int i = 0; i < 8; i++){
            Wire diff = calculated_cm_old[i].sub(cm_old[i]);
            Wire check = diff.checkNonZero();
            errorAccumulator = errorAccumulator.add(check);
        }
        makeOutput(errorAccumulator.checkNonZero(), "if NON-zero, cm_old is invalid");


        //check cm_new
        tmp1 =  truncating(
            _concatAndHash2(
                new WireArray(a_new_pk).getBits(32).asArray(),
                rho_new.getBitWires(256).asArray()
            ),
            128
        );
        tmp2 = _concatAndHash2(r_new.getBitWires(256).asArray(), tmp1);
        Wire[] calculated_cm_new = new WireArray(_concatAndHash3(
            tmp2,
            zeroWire.getBitWires(192).asArray(),
            v_new.getBitWires(256).asArray()
        )).packBitsIntoWords(32); 

        errorAccumulator = getZeroWire();
        for(int i = 0; i < 8; i++){
            Wire diff = calculated_cm_new[i].sub(cm_new[i]);
            Wire check = diff.checkNonZero();
            errorAccumulator = errorAccumulator.add(check);
        }
        makeOutput(errorAccumulator.checkNonZero(), "if NON-zero, cm_new is invalid");

        // value check
        makeOutput(v_new.add(v_pub).sub(v_old), "if NON-zero, value is invalid");
        // addEqualityAssertion(v_new.add(v_pub), v_old, "value is invalid");

    }

    private Wire[] truncating(Wire[] ins, int width){
        Wire[] result = new Wire[width];

        for (int i=0;i<width; i++){
            result[i] = ins[i];
        }

        return result;
    }

    private Wire[] _concatAndHash2(Wire[] A, Wire[] B){
        Wire[] tmp = Util.concat(A, B);
        SHA256Gadget sha2Gadget = new SHA256Gadget(tmp, 1,(int) tmp.length/8, false, true);
        // makeOutputArray(sha2Gadget.getOutputWires(), "in func sha2");
        return new WireArray(sha2Gadget.getOutputWires()).getBits(32).asArray();
    }
    // A, B, C is BitsArray
    private Wire[] _concatAndHash3(Wire[] A, Wire[] B, Wire[] C){
        Wire[] tmp = Util.concat(Util.concat(A, B), C);
        int totlaBitLen = A.length + B.length + C.length;
        SHA256Gadget sha2Gadget = new SHA256Gadget(tmp, 1, (int) (totlaBitLen/8), false, true);
        return new WireArray(sha2Gadget.getOutputWires()).getBits(32).asArray();
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

        circuitEvaluator.setWireValue(sn_old[0], new BigInteger("1269279764"));
        circuitEvaluator.setWireValue(sn_old[1], new BigInteger("435381228"));
        circuitEvaluator.setWireValue(sn_old[2], new BigInteger("3431031467"));
        circuitEvaluator.setWireValue(sn_old[3], new BigInteger("263175973"));
        circuitEvaluator.setWireValue(sn_old[4], new BigInteger("4200785891"));
        circuitEvaluator.setWireValue(sn_old[5], new BigInteger("3977712235"));
        circuitEvaluator.setWireValue(sn_old[6], new BigInteger("3622194261"));
        circuitEvaluator.setWireValue(sn_old[7], new BigInteger("3431151945"));

        circuitEvaluator.setWireValue(rt[0], new BigInteger("453798105"));
        circuitEvaluator.setWireValue(rt[1], new BigInteger("878239615"));
        circuitEvaluator.setWireValue(rt[2], new BigInteger("4269209735"));
        circuitEvaluator.setWireValue(rt[3], new BigInteger("4283957716"));
        circuitEvaluator.setWireValue(rt[4], new BigInteger("826955795"));
        circuitEvaluator.setWireValue(rt[5], new BigInteger("2086453419"));
        circuitEvaluator.setWireValue(rt[6], new BigInteger("684128673"));
        circuitEvaluator.setWireValue(rt[7], new BigInteger("3520138629"));

        // copath Direction Selector
        circuitEvaluator.setWireValue(copathDirectionSelector, new BigInteger("1")); // 0b10

        // copath Intermediate Hash
        circuitEvaluator.setWireValue(copathIntermediateHash[0], new BigInteger("4247211830"));
        circuitEvaluator.setWireValue(copathIntermediateHash[1], new BigInteger("1121653293"));
        circuitEvaluator.setWireValue(copathIntermediateHash[2], new BigInteger("2569514581"));
        circuitEvaluator.setWireValue(copathIntermediateHash[3], new BigInteger("3808238047"));
        circuitEvaluator.setWireValue(copathIntermediateHash[4], new BigInteger("1448877912"));
        circuitEvaluator.setWireValue(copathIntermediateHash[5], new BigInteger("597217703"));
        circuitEvaluator.setWireValue(copathIntermediateHash[6], new BigInteger("3315052872"));
        circuitEvaluator.setWireValue(copathIntermediateHash[7], new BigInteger("1333696385"));

        circuitEvaluator.setWireValue(copathIntermediateHash[8], new BigInteger("411053374"));
        circuitEvaluator.setWireValue(copathIntermediateHash[9], new BigInteger("4279720785"));
        circuitEvaluator.setWireValue(copathIntermediateHash[10], new BigInteger("2179239775"));
        circuitEvaluator.setWireValue(copathIntermediateHash[11], new BigInteger("2089786484"));
        circuitEvaluator.setWireValue(copathIntermediateHash[12], new BigInteger("838163735"));
        circuitEvaluator.setWireValue(copathIntermediateHash[13], new BigInteger("783935235"));
        circuitEvaluator.setWireValue(copathIntermediateHash[14], new BigInteger("2745001805"));
        circuitEvaluator.setWireValue(copathIntermediateHash[15], new BigInteger("3651061592"));

        // v_pub
        circuitEvaluator.setWireValue(v_pub, new BigInteger("100"));


        // addr_old_sk
        circuitEvaluator.setWireValue(addr_old_sk[0], new BigInteger("19960325"));  // a_old_sk
        circuitEvaluator.setWireValue(addr_old_sk[1], new BigInteger("0"));  

        // a_old_pk
        circuitEvaluator.setWireValue(c_old[0], new BigInteger("2216319766"));
        circuitEvaluator.setWireValue(c_old[1], new BigInteger("2179729192"));
        circuitEvaluator.setWireValue(c_old[2], new BigInteger("363646257"));
        circuitEvaluator.setWireValue(c_old[3], new BigInteger("432599018"));
        circuitEvaluator.setWireValue(c_old[4], new BigInteger("1932456256"));
        circuitEvaluator.setWireValue(c_old[5], new BigInteger("3021927113"));
        circuitEvaluator.setWireValue(c_old[6], new BigInteger("910039991"));
        circuitEvaluator.setWireValue(c_old[7], new BigInteger("3367817135"));
        // pk_old_enc
        circuitEvaluator.setWireValue(c_old[8], new BigInteger("0"));
        // v, rho, r, s
        circuitEvaluator.setWireValue(c_old[9], new BigInteger("3000"));
        circuitEvaluator.setWireValue(c_old[10], new BigInteger("100"));
        circuitEvaluator.setWireValue(c_old[11], new BigInteger("101"));
        circuitEvaluator.setWireValue(c_old[12], new BigInteger("0")); // s 사실 필요없음
        // cm_old
        circuitEvaluator.setWireValue(c_old[13], new BigInteger("3105824687"));
        circuitEvaluator.setWireValue(c_old[14], new BigInteger("3862418437"));
        circuitEvaluator.setWireValue(c_old[15], new BigInteger("1212064685"));
        circuitEvaluator.setWireValue(c_old[16], new BigInteger("4072953071"));
        circuitEvaluator.setWireValue(c_old[17], new BigInteger("1622751769"));
        circuitEvaluator.setWireValue(c_old[18], new BigInteger("856301769"));
        circuitEvaluator.setWireValue(c_old[19], new BigInteger("2898601113"));
        circuitEvaluator.setWireValue(c_old[20], new BigInteger("759242631"));



        // a_new_pk
        circuitEvaluator.setWireValue(c_new[0], new BigInteger("2607636775"));
        circuitEvaluator.setWireValue(c_new[1], new BigInteger("3421677843"));
        circuitEvaluator.setWireValue(c_new[2], new BigInteger("3530686348"));
        circuitEvaluator.setWireValue(c_new[3], new BigInteger("1056060037"));
        circuitEvaluator.setWireValue(c_new[4], new BigInteger("4065104312"));
        circuitEvaluator.setWireValue(c_new[5], new BigInteger("1654702294"));
        circuitEvaluator.setWireValue(c_new[6], new BigInteger("3528550683"));
        circuitEvaluator.setWireValue(c_new[7], new BigInteger("750680702"));
        // pk_new_enc
        circuitEvaluator.setWireValue(c_new[8], new BigInteger("0"));
        // v, rho, r, s
        circuitEvaluator.setWireValue(c_new[9], new BigInteger("2900")); // v
        circuitEvaluator.setWireValue(c_new[10], new BigInteger("200")); // rho
        circuitEvaluator.setWireValue(c_new[11], new BigInteger("201")); // r
        circuitEvaluator.setWireValue(c_new[12], new BigInteger("0")); // s 사실 필요없음
        // cm_new
        circuitEvaluator.setWireValue(c_new[13], new BigInteger("1262529718"));
        circuitEvaluator.setWireValue(c_new[14], new BigInteger("2426150587"));
        circuitEvaluator.setWireValue(c_new[15], new BigInteger("1112651795"));
        circuitEvaluator.setWireValue(c_new[16], new BigInteger("161585715"));
        circuitEvaluator.setWireValue(c_new[17], new BigInteger("8980847"));
        circuitEvaluator.setWireValue(c_new[18], new BigInteger("3971858637"));
        circuitEvaluator.setWireValue(c_new[19], new BigInteger("1693911745"));
        circuitEvaluator.setWireValue(c_new[20], new BigInteger("1295006934"));

        
        
    }
    
    /*
        cm  MerkleTree  rt
        [output] Value of Wire # 348174 (outputWires0[0]) :: 453798105
        [output] Value of Wire # 348176 (outputWires0[1]) :: 878239615
        [output] Value of Wire # 348178 (outputWires0[2]) :: 4269209735
        [output] Value of Wire # 348180 (outputWires0[3]) :: 4283957716
        [output] Value of Wire # 348182 (outputWires0[4]) :: 826955795
        [output] Value of Wire # 348184 (outputWires0[5]) :: 2086453419
        [output] Value of Wire # 348186 (outputWires0[6]) :: 684128673
        [output] Value of Wire # 348188 (outputWires0[7]) :: 3520138629

        intermediate Hash

        [output] Value of Wire # 348270 (outputWires6[0]) :: 4247211830
        [output] Value of Wire # 348272 (outputWires6[1]) :: 1121653293
        [output] Value of Wire # 348274 (outputWires6[2]) :: 2569514581
        [output] Value of Wire # 348276 (outputWires6[3]) :: 3808238047
        [output] Value of Wire # 348278 (outputWires6[4]) :: 1448877912
        [output] Value of Wire # 348280 (outputWires6[5]) :: 597217703
        [output] Value of Wire # 348282 (outputWires6[6]) :: 3315052872
        [output] Value of Wire # 348284 (outputWires6[7]) :: 1333696385

        [output] Value of Wire # 348190 (outputWires1[0]) :: 411053374
        [output] Value of Wire # 348192 (outputWires1[1]) :: 4279720785
        [output] Value of Wire # 348194 (outputWires1[2]) :: 2179239775
        [output] Value of Wire # 348196 (outputWires1[3]) :: 2089786484
        [output] Value of Wire # 348198 (outputWires1[4]) :: 838163735
        [output] Value of Wire # 348200 (outputWires1[5]) :: 783935235
        [output] Value of Wire # 348202 (outputWires1[6]) :: 2745001805
        [output] Value of Wire # 348204 (outputWires1[7]) :: 3651061592

    */
    
    /*
        circuitEvaluator.setWireValue(a_old_sk, new BigInteger("19960325"));
        circuitEvaluator.setWireValue(rho_old, new BigInteger("100"));
        circuitEvaluator.setWireValue(r_old, new BigInteger("101"));
        circuitEvaluator.setWireValue(v_old, new BigInteger("3000"));

        circuitEvaluator.setWireValue(a_new_sk, new BigInteger("123456789"));
        circuitEvaluator.setWireValue(rho_new, new BigInteger("200"));
        circuitEvaluator.setWireValue(r_new, new BigInteger("201"));
        circuitEvaluator.setWireValue(v_new, new BigInteger("2900"));

        circuitEvaluator.setWireValue(v_pub, new BigInteger("100"));

        [output] Value of Wire # 67375 (a_old_pk[0]) :: 2216319766
        [output] Value of Wire # 67376 (a_old_pk[1]) :: 2179729192
        [output] Value of Wire # 67377 (a_old_pk[2]) :: 363646257
        [output] Value of Wire # 67378 (a_old_pk[3]) :: 432599018
        [output] Value of Wire # 67379 (a_old_pk[4]) :: 1932456256
        [output] Value of Wire # 67380 (a_old_pk[5]) :: 3021927113
        [output] Value of Wire # 67381 (a_old_pk[6]) :: 910039991
        [output] Value of Wire # 67382 (a_old_pk[7]) :: 3367817135

        [output] Value of Wire # 134068 (a_new_pk[0]) :: 2607636775
        [output] Value of Wire # 134069 (a_new_pk[1]) :: 3421677843
        [output] Value of Wire # 134070 (a_new_pk[2]) :: 3530686348
        [output] Value of Wire # 134071 (a_new_pk[3]) :: 1056060037
        [output] Value of Wire # 134072 (a_new_pk[4]) :: 4065104312
        [output] Value of Wire # 134073 (a_new_pk[5]) :: 1654702294
        [output] Value of Wire # 134074 (a_new_pk[6]) :: 3528550683
        [output] Value of Wire # 134075 (a_new_pk[7]) :: 750680702

        [output] Value of Wire # 197331 (sn_old[0]) :: 1269279764
        [output] Value of Wire # 197332 (sn_old[1]) :: 435381228
        [output] Value of Wire # 197333 (sn_old[2]) :: 3431031467
        [output] Value of Wire # 197334 (sn_old[3]) :: 263175973
        [output] Value of Wire # 197335 (sn_old[4]) :: 4200785891
        [output] Value of Wire # 197336 (sn_old[5]) :: 3977712235
        [output] Value of Wire # 197337 (sn_old[6]) :: 3622194261
        [output] Value of Wire # 197338 (sn_old[7]) :: 3431151945

        [output] Value of Wire # 374646 (cm_old[0]) :: 3105824687
        [output] Value of Wire # 374647 (cm_old[1]) :: 3862418437
        [output] Value of Wire # 374648 (cm_old[2]) :: 1212064685
        [output] Value of Wire # 374649 (cm_old[3]) :: 4072953071
        [output] Value of Wire # 374650 (cm_old[4]) :: 1622751769
        [output] Value of Wire # 374651 (cm_old[5]) :: 856301769
        [output] Value of Wire # 374652 (cm_old[6]) :: 2898601113
        [output] Value of Wire # 374653 (cm_old[7]) :: 759242631

        [output] Value of Wire # 552473 (cm_new[0]) :: 1262529718
        [output] Value of Wire # 552474 (cm_new[1]) :: 2426150587
        [output] Value of Wire # 552475 (cm_new[2]) :: 1112651795
        [output] Value of Wire # 552476 (cm_new[3]) :: 161585715
        [output] Value of Wire # 552477 (cm_new[4]) :: 8980847
        [output] Value of Wire # 552478 (cm_new[5]) :: 3971858637
        [output] Value of Wire # 552479 (cm_new[6]) :: 1693911745
        [output] Value of Wire # 552480 (cm_new[7]) :: 1295006934
    */

    public static void main(String[] args) throws Exception {
        
        zeroCashPipour generator = new zeroCashPipour("zeroCashPipour");
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();        
    }

    
}