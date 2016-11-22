package org.wso2.charon.core.v2.protocol;

import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.schema.AttributeSchema;
import org.wso2.charon.core.v2.schema.SCIMAttributeSchema;
import org.wso2.charon.core.v2.schema.SCIMDefinitions;
import org.wso2.charon.core.v2.schema.SCIMResourceTypeSchema;
import org.wso2.charon.core.v2.utils.CopyUtil;

import java.util.*;

/**
 * This class will act as a support class for endpoints
 */
public class EndpointUtil {

    public static List<String> getOnlyRequiredAttributesURIs(SCIMResourceTypeSchema schema,
                                                                      String requestedAttributes,
                                                                      String requestedExcludingAttributes)
            throws CharonException {

        ArrayList<AttributeSchema> attributeSchemaArrayList = (ArrayList<AttributeSchema>)
                CopyUtil.deepCopy(schema.getAttributesList());

        List<String> requestedAttributesList = null;
        List<String> requestedExcludingAttributesList = null;

        if (requestedAttributes != null) {
            //make a list from the comma separated requestedAttributes
            requestedAttributesList = Arrays.asList(requestedAttributes.split(","));
        }
        if (requestedExcludingAttributes != null) {
            //make a list from the comma separated requestedExcludingAttributes
            requestedExcludingAttributesList = Arrays.asList(requestedExcludingAttributes.split(","));
        }

        ArrayList<AttributeSchema> attributeList = schema.getAttributesList();

        for (AttributeSchema attributeSchema : attributeList) {
            //check for never/request attributes.
            if (attributeSchema.getReturned().equals(SCIMDefinitions.Returned.NEVER)) {
                removeAttributesFromList(attributeSchemaArrayList, attributeSchema.getName());
            }
            //if the returned property is request, need to check whether is it specifically requested by the user.
            // If so return it.
            if (requestedAttributes == null && requestedExcludingAttributes == null) {
                if (attributeSchema.getReturned().equals(SCIMDefinitions.Returned.REQUEST)) {
                    removeAttributesFromList(attributeSchemaArrayList, attributeSchema.getName());
                }
            } else {
                //A request should only contains either attributes or exclude attribute params. Not both
                if (requestedAttributes != null) {
                    //if attributes are set, delete all the request and default attributes
                    //and add only the requested attributes
                    if ((attributeSchema.getReturned().equals(SCIMDefinitions.Returned.DEFAULT)
                            || attributeSchema.getReturned().equals(SCIMDefinitions.Returned.REQUEST))
                            && (!requestedAttributesList.contains(attributeSchema.getName())
                            && !isSubAttributeExistsInList(requestedAttributesList, attributeSchema))) {
                        removeAttributesFromList(attributeSchemaArrayList, attributeSchema.getName());
                    }
                } else if (requestedExcludingAttributes != null) {
                    //removing attributes which has returned as request. This is because no request is made
                    if (attributeSchema.getReturned().equals(SCIMDefinitions.Returned.REQUEST)) {
                        removeAttributesFromList(attributeSchemaArrayList, attributeSchema.getName());
                    }
                    //if exclude attribute is set, set of exclude attributes need to be
                    // removed from the default set of attributes
                    if ((attributeSchema.getReturned().equals(SCIMDefinitions.Returned.DEFAULT))
                            && requestedExcludingAttributesList.contains(attributeSchema.getName())) {
                        removeAttributesFromList(attributeSchemaArrayList, attributeSchema.getName());
                    }
                }
            }
            getOnlyRequiredSubAttributesURIs(attributeSchema, attributeSchemaArrayList,
                    requestedAttributes, requestedExcludingAttributes,
                    requestedAttributesList, requestedExcludingAttributesList);
        }
       return convertSchemasToURIs(attributeSchemaArrayList);
    }


    private static void getOnlyRequiredSubAttributesURIs(AttributeSchema attributeSchema,
                                                         ArrayList<AttributeSchema> attributeSchemaArrayList,
                                                         String requestedAttributes,
                                                         String requestedExcludingAttributes,
                                                         List<String> requestedAttributesList,
                                                         List<String> requestedExcludingAttributesList)
            throws CharonException {
        if (attributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)) {

            AttributeSchema realAttributeSchema = null;

            for (AttributeSchema schema : attributeSchemaArrayList) {
                if (schema.getName().equals(attributeSchema.getName())) {
                    realAttributeSchema = schema;
                    break;
                }
            }
            if (realAttributeSchema != null) {
                List<SCIMAttributeSchema> subAttributeList = attributeSchema.getSubAttributeSchemas();

                for (SCIMAttributeSchema subAttributeSchema : subAttributeList) {

                    //check for never/request attributes.
                    if (subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.NEVER)) {
                        realAttributeSchema.removeSubAttribute(subAttributeSchema.getName());
                    }
                    //if the returned property is request, need to check whether is it specifically requested by the user.
                    // If so return it.
                    if (requestedAttributes == null && requestedExcludingAttributes == null) {
                        if (subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.REQUEST)) {
                            realAttributeSchema.removeSubAttribute(subAttributeSchema.getName());
                        }
                    } else {
                        //A request should only contains either attributes or exclude attribute params. Not both
                        if (requestedAttributes != null) {
                            //if attributes are set, delete all the request and default attributes
                            //and add only the requested attributes
                            if ((subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.DEFAULT)
                                    || subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.REQUEST))
                                    && (!requestedAttributesList.contains(attributeSchema.getName() + "." +
                                    subAttributeSchema.getName())
                                    && !isSubSubAttributeExistsInList(requestedAttributesList,
                                    attributeSchema, subAttributeSchema))
                                    && (!requestedAttributesList.contains(attributeSchema.getName()))) {
                                realAttributeSchema.removeSubAttribute(subAttributeSchema.getName());
                            }
                        } else if (requestedExcludingAttributes != null) {
                            //removing attributes which has returned as request. This is because no request is made
                            if (subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.REQUEST)) {
                                realAttributeSchema.removeSubAttribute(subAttributeSchema.getName());
                            }
                            //if exclude attribute is set, set of exclude attributes need to be
                            // removed from the default set of attributes
                            if ((subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.DEFAULT))
                                    && requestedExcludingAttributesList.contains(subAttributeSchema.getName())) {
                                realAttributeSchema.removeSubAttribute(subAttributeSchema.getName());
                            }
                        }
                    }
                    getOnlyRequiredSubSubAttributesURIs(attributeSchema, subAttributeSchema,
                            attributeSchemaArrayList, requestedAttributes,
                            requestedExcludingAttributes,requestedAttributesList,
                            requestedExcludingAttributesList);
                }
            }
        }
    }

    private static void getOnlyRequiredSubSubAttributesURIs(AttributeSchema attribute,
                                                            AttributeSchema subAttribute,
                                                            ArrayList<AttributeSchema> attributeSchemaArrayList,
                                                            String requestedAttributes,
                                                            String requestedExcludingAttributes,
                                                            List<String> requestedAttributesList,
                                                            List<String> requestedExcludingAttributesList)
            throws CharonException {

        if (subAttribute.getType().equals(SCIMDefinitions.DataType.COMPLEX)) {

            AttributeSchema realAttributeSchema = null;

            if (realAttributeSchema == null) {
                for (AttributeSchema schema : attributeSchemaArrayList) {
                    List<SCIMAttributeSchema> subSchemas = schema.getSubAttributeSchemas();
                    if (subSchemas != null) {
                        for (AttributeSchema subSchema : subSchemas) {
                            if (subSchema.getURI().equals(subAttribute.getURI())) {
                                realAttributeSchema = subSchema;
                                break;
                            }
                        }
                    }
                }
            }
            if (realAttributeSchema != null) {
                List<SCIMAttributeSchema> subAttributeList = subAttribute.getSubAttributeSchemas();

                for (SCIMAttributeSchema subAttributeSchema : subAttributeList) {

                    //check for never/request attributes.
                    if (subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.NEVER)) {
                        realAttributeSchema.removeSubAttribute(subAttributeSchema.getName());
                    }
                    //if the returned property is request, need to check whether is it specifically requested by the user.
                    // If so return it.
                    if (requestedAttributes == null && requestedExcludingAttributes == null) {
                        if (subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.REQUEST)) {
                            realAttributeSchema.removeSubAttribute(subAttributeSchema.getName());
                        }
                    } else {
                        //A request should only contains either attributes or exclude attribute params. Not both
                        if (requestedAttributes != null) {
                            //if attributes are set, delete all the request and default attributes
                            //and add only the requested attributes
                            if ((subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.DEFAULT)
                                    || subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.REQUEST))
                                    && (!requestedAttributesList.contains(attribute.getName() + "." +
                                    subAttribute.getName() + "." + subAttributeSchema.getName()))
                                    && (!requestedAttributesList.contains(attribute.getName()))
                                    && (!requestedAttributesList.contains(attribute.getName() + "." + subAttribute.getName()))) {
                                realAttributeSchema.removeSubAttribute(subAttributeSchema.getName());
                            }
                        } else if (requestedExcludingAttributes != null) {
                            //removing attributes which has returned as request. This is because no request is made
                            if (subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.REQUEST)) {
                                realAttributeSchema.removeSubAttribute(subAttributeSchema.getName());
                            }
                            //if exclude attribute is set, set of exclude attributes need to be
                            // removed from the default set of attributes
                            if ((subAttributeSchema.getReturned().equals(SCIMDefinitions.Returned.DEFAULT))
                                    && requestedExcludingAttributesList.contains(subAttributeSchema.getName())) {
                                realAttributeSchema.removeSubAttribute(subAttributeSchema.getName());
                            }
                        }
                    }
                }
            }
        }
    }


    private static boolean isSubAttributeExistsInList(List<String> requestedAttributes, AttributeSchema attributeSchema) {
        if(attributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)){
            List<SCIMAttributeSchema> subAttributeSchemas = attributeSchema.getSubAttributeSchemas();

            for(SCIMAttributeSchema subAttributeSchema : subAttributeSchemas) {
                if (requestedAttributes.contains(attributeSchema.getName() + "." + subAttributeSchema.getName())) {
                    return true;
                }

                if (subAttributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)) {
                    List<SCIMAttributeSchema> subSubAttributeSchemas = subAttributeSchema.getSubAttributeSchemas();

                    for (SCIMAttributeSchema subSubAttributeSchema : subSubAttributeSchemas) {
                        if (requestedAttributes.contains(
                                attributeSchema.getName() + "." +
                                        subAttributeSchema.getName() + "." +
                                        subSubAttributeSchema.getName())) {
                            return true;
                        }
                    }
                }
            }
            return false;
        } else {
            return false;
        }
     }

    private static boolean isSubSubAttributeExistsInList(List<String> requestedAttributes,
                                                         AttributeSchema attributeSchema,
                                                         AttributeSchema subAttributeSchema) {

        if(subAttributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)){
            List<SCIMAttributeSchema> subSubAttributeSchemas = subAttributeSchema.getSubAttributeSchemas();

            for(SCIMAttributeSchema subSubAttributeSchema : subSubAttributeSchemas) {
                if (requestedAttributes.contains(attributeSchema.getName() + "." +
                        subAttributeSchema.getName()+"."+subSubAttributeSchema.getName())) {
                    return true;
                }
            }
            return false;
        } else {
            return false;
        }
    }

    private static List<String> convertSchemasToURIs(List<AttributeSchema> schemas){

         List<String> URIList = new ArrayList<>();
         for(AttributeSchema schema : schemas){
             if(schema.getType().equals(SCIMDefinitions.DataType.COMPLEX)){
                 List<SCIMAttributeSchema> subAttributeSchemas = schema.getSubAttributeSchemas();
                 for(SCIMAttributeSchema subAttributeSchema : subAttributeSchemas){
                     if(subAttributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)){
                         List<SCIMAttributeSchema> subSubAttributeSchemas = subAttributeSchema.getSubAttributeSchemas();
                         for(SCIMAttributeSchema subSubAttributeSchema : subSubAttributeSchemas){
                             URIList.add(subSubAttributeSchema.getURI());
                         }
                     } else {
                         URIList.add(subAttributeSchema.getURI());
                     }
                 }
             } else {
                 URIList.add(schema.getURI());
             }
         }
         return  URIList;
     }

     private static void removeAttributesFromList(List<AttributeSchema> attributeSchemaList, String attributeName)
             throws CharonException {
         List<AttributeSchema> tempList = (List<AttributeSchema>) CopyUtil.deepCopy(attributeSchemaList);
         int count = 0;
         for(AttributeSchema attributeSchema : tempList){
             if(attributeSchema.getName().equals(attributeName)){
                   attributeSchemaList.remove(count);
             }
             count++;
         }
     }
}
