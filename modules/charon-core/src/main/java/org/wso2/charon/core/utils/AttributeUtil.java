package org.wso2.charon.core.utils;

import com.sun.org.apache.xpath.internal.operations.Bool;
import org.wso2.charon.core.exceptions.BadRequestException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.schema.ResourceTypeSchema;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMDefinitions;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
/*
 * This class acts as an utility class for attributes
 */
public class AttributeUtil {

    /**
     * Convert the raw string to SCIM defined data type accordingly
     *
     * @param attributeValue
     * @param dataType
     * @return Object
     */
    public static Object getAttributeValueFromString(Object attributeValue,
                                                     SCIMDefinitions.DataType dataType)
            throws CharonException, BadRequestException {
        if(attributeValue ==null){
            return attributeValue;
        }
        String attributeStringValue = null;
        if(!(attributeValue instanceof Boolean)){
            attributeStringValue= (String) attributeValue;
        }
        try {
            switch (dataType) {
                case STRING:
                    return attributeStringValue.trim();
                case BOOLEAN:
                    return parseBoolean(attributeValue);
                case DECIMAL:
                    return Double.parseDouble(attributeStringValue);
                case INTEGER:
                    return Integer.parseInt(attributeStringValue);
                case DATE_TIME:
                    return parseDateTime(attributeStringValue);
                case BINARY:
                    return new Byte(attributeStringValue);
                case REFERENCE:
                    return parseReference(attributeStringValue);
                case COMPLEX:
                    return parseComplex(attributeStringValue);
            }
        }
        catch(Exception e){
            throw new CharonException("Error in converting string value to attribute type: " + dataType);
        }
        return null;
    }
    /**
     * SCIM spec requires date time to be in yyyy-MM-dd'T'HH:mm:ss
     *
     * @param dateTimeString
     */
    public static Date parseDateTime(String dateTimeString) throws CharonException {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(SCIMConstants.dateTimeFormat);
            return sdf.parse(dateTimeString);
        } catch (ParseException e) {
            throw new CharonException("Error in parsing date time. " +
                    "Date time should adhere to the format: "+SCIMConstants.dateTimeFormat);
        }
    }

    public static URI parseReference(String referenceString) throws CharonException{
        //TODO: Need a better way for doing this. Think of the way to handle reference types
        try{
            URI uri =new URI(referenceString);
            uri.normalize();
            return uri;
        } catch (URISyntaxException e) {
            throw new CharonException("Error in normalization of the URI");
        }
    }
    //this method is for the consistence purpose only
    public static String parseComplex(String complexString){
        return complexString;
    }

    /**
     * SCIM spec requires date time to be adhered to XML Schema Datatypes Specification
     *
     * @param date
     */
    public static String formatDateTime(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat(SCIMConstants.dateTimeFormat);
        String formattedDate = sdf.format(date);
        return formattedDate;
    }

    /**
     * Converts the value to bolean or throw an exception
     *
     * @param booleanValue
     */
    public static Boolean parseBoolean(Object booleanValue) throws BadRequestException {
        if(booleanValue instanceof Boolean){
            return ((Boolean) booleanValue).booleanValue();
        }
        else{
            throw new BadRequestException(ResponseCodeConstants.INVALID_VALUE);
        }
    }

}