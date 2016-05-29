package eu.dety.burp.joseph.utilities;

import burp.IParameter;
import java.util.List;
import java.util.Set;

/**
 * Functions to search parameter lists.
 * @author Christian Mainka
 * @version 1.0
 */

final public class ParameterUtilities {

    /**
     * Search for the first appearance of a parameter in the list.
     * @param parameterList A list of parameters with string names.
     * @param parameterName The name of the parameter.
     * @return true if the list contains the name otherwise false.
     */
    public static boolean parameterListContainsParameterName(List<IParameter> parameterList, String parameterName) {
        boolean result = false;
        for (IParameter p : parameterList) {
            if (parameterName.equals(p.getName())) {
                result = true;
                break;
            }
        }
        return result;
    }

    /**
     * Search for the first appearance of a parameter in the list.
     * @param parameterList A list of parameters with string names.
     * @param parameterNames A set of names for parameters.
     * @return true if the list contains of of the given names otherwise false.
     */
    public static boolean parameterListContainsParameterName(List<IParameter> parameterList, Set<String> parameterNames) {
        boolean result = false;
        for (IParameter p : parameterList) {
            if (parameterNames.contains(p.getName())) {
                result = true;
                break;
            }
        }
        return result;
    }

    /**
     * Search for the first appearance of a parameter in the list.
     * @param parameterList A list of parameters with string names.
     * @param parameterName The name of the parameter.
     * @return The first parameter with the given name found in the
     * parameter list, or null, if parameterName is not found.
     */
    public static IParameter getFirstParameterByName(List<IParameter> parameterList, String parameterName) {
        IParameter result = null;
        for (IParameter p : parameterList) {
            if (parameterName.equals(p.getName())) {
                result = p;
                break;
            }
        }
        return result;
    }
}