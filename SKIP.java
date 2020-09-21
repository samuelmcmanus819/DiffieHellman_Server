import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;

public class SKIP {
    //String representation of the skip number
    private static final String skip1024String =
        "F488FD584E49DBCD" + "20B49DE49107366B" + "336C380D451D0F7C" + "88B31C7C5B2D8EF6" +
        "F3C923C043F0A55B" + "188D8EBB558CB85D" + "38D334FD7C175743" + "A31D186CDE33212C" +
        "B52AFF3CE1B12940" + "18118D7C84A70A72" + "D686C40319C80729" + "7ACA950CD9969FAB" +
        "D00A509B0246D308" + "3D66A45D419F9C7C" + "BD894B221926BAAB" + "A25EC355E92F78C7";
    //P value
    private static final BigInteger Skip1024Modulus = new BigInteger(skip1024String, 16);
    //G value
    private static final BigInteger Skip1024Base = BigInteger.valueOf(2);
    //DH parameter specification
    public static final DHParameterSpec sDHParameterSpec =
            new DHParameterSpec(Skip1024Modulus, Skip1024Base);
}
