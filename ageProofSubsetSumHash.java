package examples.generators;

import java.math.BigInteger;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.config.Config;
import examples.gadgets.hash.SubsetSumHashGadget;


public class ageProofSubsetSumHash extends CircuitGenerator {

    private Wire[] myAgeSubsetSumHash;
    private Wire[] randValue;

    private SubsetSumHashGadget subsetsumHashGadget;


    public ageProofSubsetSumHash(String circuitName) {
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {

        myAgeSubsetSumHash = createInputWireArray(3);
        randValue = createInputWireArray(3);
        // makeOutputArray(myAgeSubsetSumHash, "my Hash !!!");

        Wire result = zeroWire;
        Wire randresult = zeroWire;
        Wire tmp;
        Wire[] tmpArray;
        Wire[] HashOutput;

        for (int i=20 ; i<=100; i++){
            tmp = oneWire.mul(i);
            tmpArray = tmp.getBitWires(128).asArray();
            subsetsumHashGadget = new SubsetSumHashGadget(tmpArray, false,Integer.toString(i) + "old years Hash");
            HashOutput = subsetsumHashGadget.getOutputWires();
            // makeOutputArray(HashOutput, Integer.toString(i)+" SubsetSum");
            
            for (int j=0; j<3 ; j++){
                
                result = result.add( HashOutput[j].isEqualTo(myAgeSubsetSumHash[j]) );
                randresult = randresult.add( HashOutput[j].isEqualTo(randValue[j]) );
                
            }

        }

        result = result.isEqualTo(new BigInteger("3"));
        randresult = randresult.isEqualTo(new BigInteger("3"));
        makeOutput(result, "myAgeHash result (if result == 1 then you're Adult !)");
        makeOutput(randresult, "rand Value result (if result == 1 then you're Adult !");
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        // circuitEvaluator.setWireValue(myAge, 27);
        circuitEvaluator.setWireValue(myAgeSubsetSumHash[0], new BigInteger("15677387567406201372445806426147510158771338445983908671354791663594523098050"));
        circuitEvaluator.setWireValue(myAgeSubsetSumHash[1], new BigInteger("17152463153120130254282260178992631485375602442945265123136355902093201770308"));
        circuitEvaluator.setWireValue(myAgeSubsetSumHash[2], new BigInteger("04525090847101244209138578646217627690235873814080875747132220208866341757730"));

        for (int i=0; i<3; i++){
            circuitEvaluator.setWireValue(randValue[i], Util.nextRandomBigInteger(Config.FIELD_PRIME));
        }
    }

    // [output] Value of Wire # 223 (27old years Hash[0]) :: 15677387567406201372445806426147510158771338445983908671354791663594523098050
    // [output] Value of Wire # 224 (27old years Hash[1]) :: 17152463153120130254282260178992631485375602442945265123136355902093201770308
    // [output] Value of Wire # 225 (27old years Hash[2]) :: 4525090847101244209138578646217627690235873814080875747132220208866341757730

    public static void main(String[] args) throws Exception {

        ageProofSubsetSumHash generator = new ageProofSubsetSumHash("age Proof SubsetSumHash");
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();
    }

}
