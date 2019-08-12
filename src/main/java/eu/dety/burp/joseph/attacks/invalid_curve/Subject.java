package eu.dety.burp.joseph.attacks.invalid_curve;

/**
 * Subject interface to implement the observer pattern.
 * 
 * @author Vincent Unsel
 * @version 1.0
 */

public interface Subject {
    void addObserver(Observer observer);

    void removeObserver(Observer observer);

    void notifyObservers();
}
