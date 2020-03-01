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

import java.math.BigInteger;

/**
 * Point implementation to represent Elliptic Curve points with BigIntegers.
 * 
 * @author Vincent Unsel
 * @version 1.0
 */
public class Point implements IPair<BigInteger, BigInteger>, Comparable<Point> {
    private BigInteger x;
    private BigInteger y;
    private BigInteger order;
    private BigInteger d;

    public Point(BigInteger order, BigInteger d, BigInteger x, BigInteger y) {
        setOrder(order);
        setX(x);
        setY(y);
        setD(d);
    }

    public BigInteger getX() {
        return x;
    }

    public void setX(BigInteger x) {
        this.x = x;
    }

    public BigInteger getY() {
        return y;
    }

    public void setY(BigInteger y) {
        this.y = y;
    }

    public BigInteger getOrder() {
        return order;
    }

    public void setOrder(BigInteger order) {
        this.order = order;
    }

    public BigInteger getD() {
        return d;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    @Override
    public int compareTo(Point point) {
        return (this.getOrder().compareTo(point.getOrder()) + this.getD().compareTo(point.getD()) + this.getX().compareTo(point.getX()) + this.getY()
                .compareTo(point.getY()));
    }

    public int compareToOrder(Point point) {
        return this.getOrder().compareTo(point.getOrder());
    }

    public int compareToX(Point point) {
        return this.getX().compareTo(point.getX());
    }

    public int compareToY(Point point) {
        return this.getY().compareTo(point.getY());
    }

    public int compareToD(Point point) {
        return this.getD().compareTo(point.getD());
    }

    @Override
    public boolean equals(Object object) {
        if (this == object)
            return true;
        if (object instanceof Point) {
            return compareToOrder((Point) object) == 0;
        }
        return false;
    }

    @Override
    public int hashCode() {
        return this.getOrder().hashCode();
    }

    @Override
    public String toString() {
        return this.getD().toString() + " mod " + this.getOrder().toString();
    }
}
