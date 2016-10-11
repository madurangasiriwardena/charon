package org.wso2.charon.core.schema;

import org.wso2.charon.core.attributes.*;
import org.wso2.charon.core.exceptions.BadRequestException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.AbstractSCIMObject;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceManager;
import org.wso2.charon.core.utils.AttributeUtil;

import java.util.*;

public class ServerSideValidator extends AbstractValidator{

    /**
     * Validate created SCIMObject according to the spec
     *
     * @param scimObject
     * @param resourceSchema
     * @throw CharonException
     * @throw BadRequestException
     * @throw NotFoundException
     */
    public static void validateCreatedSCIMObject(AbstractSCIMObject scimObject, SCIMResourceTypeSchema resourceSchema)
            throws CharonException, BadRequestException, NotFoundException {

        removeAnyReadOnlyAttributes(scimObject,resourceSchema);

        //add created and last modified dates
        String id = UUID.randomUUID().toString();
        scimObject.setId(id);
        Date date = new Date();
        //set the created date and time
        scimObject.setCreatedDate(AttributeUtil.parseDateTime(AttributeUtil.formatDateTime(date)));
        //creates date and the last modified are the same if not updated.
        scimObject.setLastModified(AttributeUtil.parseDateTime(AttributeUtil.formatDateTime(date)));
        //set display names for complex multivalued attributes
        setDisplayNameInComplexMultiValuedAttributes(scimObject,resourceSchema);
        //set location and resourceType
        if (resourceSchema.isSchemaAvailable(SCIMConstants.USER_CORE_SCHEMA_URI)){
            String location = createLocationHeader(AbstractResourceManager.getResourceEndpointURL(
                    SCIMConstants.USER_ENDPOINT), scimObject.getId());
            scimObject.setLocation(location);
            scimObject.setResourceType(SCIMConstants.USER);
        } else if (resourceSchema.isSchemaAvailable(SCIMConstants.GROUP_CORE_SCHEMA_URI)) {
            String location = createLocationHeader(AbstractResourceManager.getResourceEndpointURL(
                    SCIMConstants.GROUP_ENDPOINT), scimObject.getId());
            scimObject.setLocation(location);
            scimObject.setResourceType(SCIMConstants.GROUP);
        }
        //TODO:Are we supporting version ? (E-tag-resource versioning)
        validateSCIMObjectForRequiredAttributes(scimObject, resourceSchema);
        validateSchemaList(scimObject, resourceSchema);
    }

    /**
     * This method is basically for adding display sub attribute to multivalued attributes
     * which has 'display' as a sub attribute in the respective attribute schema
     *
     * @param scimObject
     * @param resourceSchema
     * @throws CharonException
     * @throws BadRequestException
     */
    private static void setDisplayNameInComplexMultiValuedAttributes(
            AbstractSCIMObject scimObject, SCIMResourceTypeSchema resourceSchema) throws CharonException, BadRequestException {

        Map<String, Attribute> attributeList=scimObject.getAttributeList();
        ArrayList<AttributeSchema> attributeSchemaList=resourceSchema.getAttributesList();

        for(AttributeSchema attributeSchema : attributeSchemaList){

            if(attributeSchema.getMultiValued() && attributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)){

                if(attributeSchema.getSubAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY) != null){

                    if(attributeList.containsKey(attributeSchema.getName())){
                        Attribute multiValuedAttribute = attributeList.get(attributeSchema.getName());
                        List<Attribute> subValuesList = ((MultiValuedAttribute)(multiValuedAttribute)).getAttributeValues();

                        for(Attribute subValue : subValuesList){
                            for(AttributeSchema subAttributeSchema : attributeSchema.getSubAttributeSchemas())
                                if(subAttributeSchema.getName().equals(SCIMConstants.CommonSchemaConstants.VALUE)){

                                    if(!subAttributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)
                                            && !subAttributeSchema.getMultiValued()){
                                        //take the value from the value sub attribute and put is as display attribute
                                        SimpleAttribute simpleAttribute = new SimpleAttribute(
                                                SCIMConstants.CommonSchemaConstants.DISPLAY,
                                                ((SimpleAttribute)(subValue.getSubAttribute(subAttributeSchema.getName()))).getValue());
                                        AttributeSchema subSchema = attributeSchema.getSubAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY);
                                        simpleAttribute=(SimpleAttribute) DefaultAttributeFactory.createAttribute(subSchema, simpleAttribute);
                                        ((ComplexAttribute)(subValue)).setSubAttribute(simpleAttribute);
                                    }
                                    else if(!subAttributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)
                                            && subAttributeSchema.getMultiValued()){

                                        Attribute valueSubAttribute= (MultiValuedAttribute)(subValue.getSubAttribute(subAttributeSchema.getName()));
                                        Object displayValue= ((MultiValuedAttribute)(valueSubAttribute)).getAttributePrimitiveValues().get(0);
                                        //if multiple values are available, get the first value and put it as display name
                                        SimpleAttribute simpleAttribute = new SimpleAttribute(
                                                SCIMConstants.CommonSchemaConstants.DISPLAY, displayValue);
                                        AttributeSchema subSchema = attributeSchema.getSubAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY);
                                        simpleAttribute=(SimpleAttribute) DefaultAttributeFactory.createAttribute(subSchema, simpleAttribute);
                                        ((ComplexAttribute)(subValue)).setSubAttribute(simpleAttribute);

                                    }
                                }
                        }


                    }
                }
            }
        }
    }

    private static String createLocationHeader(String location, String resourceID) {
        String locationString = location + "/" + resourceID;
        return locationString;
    }

    public static void validateRetrievedSCIMObject(AbstractSCIMObject scimObject,
                                                   SCIMResourceTypeSchema resourceSchema,String reuqestedAttributes,
                                                   String requestedExcludingAttributes)
            throws BadRequestException, CharonException {
        validateSCIMObjectForRequiredAttributes(scimObject, resourceSchema);
        removeAttributesOnReturn(scimObject,reuqestedAttributes,requestedExcludingAttributes);
        validateSchemaList(scimObject, resourceSchema);
    }

    /**
     * Perform validation on SCIM Object update on service provider side
     *
     * @param oldObject
     * @param newObject
     * @param resourceSchema
     * @return
     * @throws CharonException
     */
    public static AbstractSCIMObject validateUpdatedSCIMObject(AbstractSCIMObject oldObject,
                                                               AbstractSCIMObject newObject,
                                                               SCIMResourceTypeSchema resourceSchema)
            throws CharonException, BadRequestException {

            AbstractSCIMObject validatedObject = null;
            validatedObject = checkIfReadOnlyAndImmutableAttributesModified(oldObject, newObject, resourceSchema);
            //copy meta attribute from old to new
            validatedObject.setAttribute(oldObject.getAttribute(SCIMConstants.CommonSchemaConstants.META));
            //copy id attribute to new group object
            validatedObject.setAttribute(oldObject.getAttribute(SCIMConstants.CommonSchemaConstants.ID));
            //edit last modified date
            Date date = new Date();
            validatedObject.setLastModified(date);
            //set display names for complex multivalued attributes
            setDisplayNameInComplexMultiValuedAttributes(newObject,resourceSchema);
            //check for required attributes.
            validateSCIMObjectForRequiredAttributes(validatedObject, resourceSchema);

        return validatedObject;
        //TODO: if user object, validate name
    }


}


