package eu.dety.burp.joseph.attacks.invalid_curve;

/**
 * Pair interface to implement encapsulated tuple objects.
 * 
 * @author Vincent Unsel
 * @version 1.0
 */
public interface IPair<K, V> {
    K getX();

    V getY();

    void setX(K x);

    void setY(V y);
}
