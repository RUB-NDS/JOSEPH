package eu.dety.burp.joseph.attacks.invalid_curve;

import eu.dety.burp.joseph.attacks.AttackRequest;

/**
 * Invalid Curve Attack Request represent the request with encapsulated values.
 * 
 * @author Vincent Unsel
 * @version 1.0
 */
public class InvalidCurveAttackRequest extends AttackRequest {
    private Point p;

    private InvalidCurveAttackRequest(byte[] request) {
        super(request, -1);
    }

    InvalidCurveAttackRequest(byte[] request, Point p) {
        this(request);
        this.p = p;
    }

    public Point getPoint() {
        return p;
    }

    public void setPoint(Point p) {
        this.p = p;
    }
}
