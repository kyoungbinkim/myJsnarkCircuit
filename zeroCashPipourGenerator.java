package examples.generators;

import util.Util;

import java.math.BigInteger;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SubsetSumHashGadget;
import examples.gadgets.hash.SHA256Gadget;

public class zeroCashPipourGenerator extends CircuitGenerator {
    /*
        util concat 으로
        input  : x  =  rt, sn_1_old, sn_2_old, cm_1_new, cm_2_new (vPub, info)
        witness: a  =  copath1, copath2, c_1_old, c_2_old, addr_old_sk1, addr_old_sk2, c_1_mew, c_2_new
        
    */


    // input x
    private Wire v_pub;

    // witness a
    private Wire[] copath;

    private Wire[] addr_old_sk; 
    private Wire[] C_1;

    private Wire a_new_sk;
    private Wire a_old_sk;

    private Wire v_old;
    private Wire rho_old;
    private Wire r_old;
    private Wire[] s_old;

    private Wire v_new;
    private Wire rho_new;
    private Wire r_new;
    private Wire s_new;

    
    public zeroCashPipourGenerator(String circuitName) {
        super(circuitName);
    }

    private SHA256Gadget sha2Gadget;

    @Override
    protected void buildCircuit() {

        a_old_sk = createInputWire("a_old_sk");
        rho_old = createInputWire("rho_old");
        r_old = createInputWire("r_old");
        v_old = createInputWire("v_old");

        a_new_sk = createInputWire("a_new_sk");
        rho_new = createInputWire("rho_new");
        r_new = createInputWire("r_new");
        v_new = createInputWire("v_new");

        v_pub = createInputWire("v_pub");

        Wire[] zeroPad = createConstantWire(new BigInteger("0")).getBitWires(2).asArray();
        Wire[] onePad = createConstantWire(new BigInteger("1")).getBitWires(2).asArray();
        Wire[] twoPad = createConstantWire(new BigInteger("2")).getBitWires(2).asArray();

        Wire[] a_old_pk = _concatAndHash2(
            a_old_sk.getBitWires(256).asArray(),
            zeroWire.getBitWires(256).asArray()
        );
        makeOutputArray(new WireArray(a_old_pk).packBitsIntoWords(32), "a_old_pk");

        Wire[] a_new_pk = _concatAndHash2(
            a_new_sk.getBitWires(256).asArray(),
            zeroWire.getBitWires(256).asArray()
        );
        makeOutputArray(new WireArray(a_new_pk).packBitsIntoWords(32), "a_new_pk");



        Wire[] sn_old = _concatAndHash3(
            a_old_sk.getBitWires(256).asArray(),
            onePad,
            rho_old.getBitWires(254).asArray()
        );
        makeOutputArray(new WireArray(sn_old).packBitsIntoWords(32), "sn_old");


        Wire[] tmp1 =  truncating(_concatAndHash2(a_old_pk, rho_old.getBitWires(256).asArray()), 128);
        Wire[] tmp2 = _concatAndHash2(r_old.getBitWires(256).asArray(), tmp1);
        Wire[] cm_old = _concatAndHash3(
            tmp2,
            zeroWire.getBitWires(192).asArray(),
            v_old.getBitWires(256).asArray()
        ); 
        makeOutputArray(new WireArray(cm_old).packBitsIntoWords(32), "cm_old");



        tmp1 =  truncating(_concatAndHash2(a_new_pk, rho_new.getBitWires(256).asArray()), 128);
        tmp2 = _concatAndHash2(r_new.getBitWires(256).asArray(), tmp1);
        Wire[] cm_new = _concatAndHash3(
            tmp2,
            zeroWire.getBitWires(192).asArray(),
            v_new.getBitWires(256).asArray()
        ); 
        makeOutputArray(new WireArray(cm_new).packBitsIntoWords(32), "cm_new");
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
                        
        circuitEvaluator.setWireValue(a_old_sk, new BigInteger("19960325"));
        circuitEvaluator.setWireValue(rho_old, new BigInteger("100"));
        circuitEvaluator.setWireValue(r_old, new BigInteger("101"));
        circuitEvaluator.setWireValue(v_old, new BigInteger("3000"));

        circuitEvaluator.setWireValue(a_new_sk, new BigInteger("123456789"));
        circuitEvaluator.setWireValue(rho_new, new BigInteger("200"));
        circuitEvaluator.setWireValue(r_new, new BigInteger("201"));
        circuitEvaluator.setWireValue(v_new, new BigInteger("2900"));

        circuitEvaluator.setWireValue(v_pub, new BigInteger("100"));
    }
    
    
    public static void main(String[] args) throws Exception {
        
        zeroCashPipourGenerator generator = new zeroCashPipourGenerator("zeroCashPipourGen");
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();        
    }

    
}