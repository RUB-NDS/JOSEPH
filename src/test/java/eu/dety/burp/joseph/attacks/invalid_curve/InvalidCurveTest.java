package eu.dety.burp.joseph.attacks.invalid_curve;

import burp.IBurpExtenderCallbacks;
import eu.dety.burp.joseph.BurpExtenderCallbacksMock;
import org.junit.BeforeClass;

class InvalidCurveTest {
    private static InvalidCurveInfo invalidCurveInfo;
    private static InvalidCurve invalidCurve;
    private static IBurpExtenderCallbacks callbacks;

    @BeforeClass
    public static void setUp() {
        callbacks = new BurpExtenderCallbacksMock();
        invalidCurveInfo = new InvalidCurveInfo(callbacks);
        invalidCurve = new InvalidCurve(callbacks, invalidCurveInfo);
    }

    // @Test
    // public void performAttackTest() {
    // invalidCurve.performAttack();
    // }

}
