/**
 * JOSEPH - JavaScript Object Signing and Encryption Pentesting Helper
 * Copyright (C) 2016 Dennis Detering
 * <p>
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 * <p>
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package eu.dety.burp.joseph.attacks.invalid_curve;

import eu.dety.burp.joseph.utilities.Logger;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Chinese Remainder implementation to calculate the targets private key.
 *
 * @author Vincent Unsel
 * @version 1.0
 */
public class ChineseRemainder implements Subject {
    private static final Logger loggerInstance = Logger.getInstance();
    private static ChineseRemainder instance;
    private BigInteger modulus;
    private BigInteger nSquare;
    private volatile BigInteger calculated = BigInteger.ONE;
    private ECPublicKey ecPublicKey;
    private ECParameterSpec ecParameterSpec;
    private List<Point> pointList;
    private List<Observer> observerList;
    private volatile boolean found = false;
    private boolean pointCollected = false;
    private boolean canceled = false;

    private ChineseRemainder() {
        pointList = new ArrayList<>();

    }

    public static ChineseRemainder getInstance() {
        return instance;
    }

    public static ChineseRemainder startInstance(ECPublicKey publicKey, ECParameterSpec ecParameters) {
        instance = new ChineseRemainder();
        instance.observerList = new ArrayList<>();
        instance.modulus = BigInteger.ONE;
        instance.ecParameterSpec = ecParameters;
        instance.setPublicKey(publicKey);
        instance.nSquare = ecParameters.getN().pow(2);
        loggerInstance.log(instance.getClass(), "Single instance CR started.", Logger.LogLevel.DEBUG);
        return instance;
    }

    public BigInteger calculateModulus(List<Point> moduli) {
        BigInteger n = BigInteger.ONE;
        for (Point modulus : moduli) {
            n = n.multiply(modulus.getOrder());
        }
        return n;
    }

    public BigInteger isqrt(BigInteger integer) {
        if (integer.compareTo(BigInteger.ZERO) < 0 || integer == null)
            return null;
        else if (integer.compareTo(BigInteger.valueOf(2)) < 0)
            return integer;
        else {
            BigInteger floor = isqrt(integer.shiftRight(2)).shiftLeft(1);
            BigInteger ceiling = floor.add(BigInteger.ONE);
            if (ceiling.pow(2).compareTo(integer) > 0)
                return floor;
            else {
                return ceiling;
            }
        }
    }

    /**
     * Set targets public key to compute the private key.
     *
     * @param ecPublicKey
     **/
    public void setPublicKey(ECPublicKey ecPublicKey) {
        this.ecPublicKey = ecPublicKey;
    }

    public synchronized void addPoint(Point point) {
        if (!pointList.contains(point)) {
            pointList.add(point);
            this.pointCollected = true;
            loggerInstance.log(this.getClass(), "Amount of collected points: " + pointList.size(), Logger.LogLevel.DEBUG);
        } else
            return;
        checkResult(calculateSquaredCR(pointList));
    }

    public void lastTry() {
        if (pointList.isEmpty())
            return;
        Thread runner = new Thread(() -> {
            Runnable runnable = () -> {
                while (!(Thread.currentThread().isInterrupted() || this.found || this.canceled)) {
                    trySkip(pointList);
                }
            };
            int threadAmount = 3;
            Thread[] threads = new Thread[threadAmount];
            for (int i = 0; i < threadAmount; ++i) {
                threads[i] = new Thread(runnable);
                threads[i].start();
            }

            while (!(this.found || this.canceled)) {
                try {
                    Thread.currentThread().sleep(100);
                    notifyObservers();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            notifyObservers();
            for (Thread thread : threads)
                thread.interrupt();
            for (int i = 0; i < threadAmount; ++i) {
                try {
                    threads[i].join();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        runner.start();
    }

    public void checkResult(BigInteger calculated) {
        if (this.found || this.canceled)
            return;
        ECPoint point = ecParameterSpec.getG().normalize().multiply(calculated).normalize();
        boolean found = point.equals(ecPublicKey.getQ().normalize());
        if (found)
            synchronized (this) {
                if (this.found)
                    return;
                this.found = found;
                this.calculated = calculated;
                notifyObservers();
            }
    }

    public void trySkip(List<Point> list) {
        ArrayList<Point> points = new ArrayList<>();
        for (Point point : list) {
            if (Math.random() < 0.6) {
                points.add(point);
            }
        }
        checkResult(calculateSquaredCR(points));
    }

    public List<Point> squareCongruences(Collection<Point> collection) {
        List<Point> points = new ArrayList<>();
        for (Point point : collection) {
            BigInteger squaredCongruence = point.getD().modPow(new BigInteger("2"), point.getOrder());
            points.add(new Point(point.getOrder(), squaredCongruence, null, null));
        }
        return points;
    }

    public BigInteger calculateCR(List<Point> points) {
        BigInteger n = BigInteger.ZERO;
        BigInteger modulus = calculateModulus(points);

        for (Point point : points) {
            BigInteger mi = modulus.divide(point.getOrder());
            if (point.getD().equals(BigInteger.ZERO))
                continue;
            n = (n.add(point.getD().multiply(mi.modInverse(point.getOrder())).multiply(mi))).mod(modulus);
        }
        loggerInstance.log(instance.getClass(), "Calculated CR: " + n.toString(), Logger.LogLevel.DEBUG);
        return n.mod(modulus);
    }

    public BigInteger calculateSquaredCR(Collection<Point> collection) {
        return isqrt(calculateCR(squareCongruences(collection)));
    }

    public BigInteger getCalculated() {
        return this.calculated;
    }

    public boolean isFound() {
        return this.found;
    }

    public boolean isCancel() {
        return this.canceled;
    }

    public void setCancel(boolean cancel) {
        this.canceled = cancel;
    }

    public boolean pointCollected() {
        return pointCollected;
    }

    public void resetBoth() {
        this.pointCollected = false;
    }

    /**
     * Add observers to notify.
     *
     * @param observer
     */
    @Override
    public void addObserver(Observer observer) {
        this.observerList.add(observer);
    }

    /**
     * Remove observers that shall not be notified anymore.
     *
     * @param observer
     */
    @Override
    public void removeObserver(Observer observer) {
        this.observerList.remove(observer);
    }

    /**
     * Observer pattern method to notify all registered observers.
     */
    @Override
    public void notifyObservers() {
        for (Observer observer : observerList) {
            observer.update();
        }
    }
}
