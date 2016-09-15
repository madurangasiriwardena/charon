package org.wso2.charon.core.scheme;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * This class contains the schema definitions in
 * https://tools.ietf.org/html/rfc7643 as AttributeSchemas.
 * These are used when constructing SCIMObjects from the decoded payload
 */

public class SCIMSchemaDefinitions {

                /*********** SCIM defined common attribute schemas****************************/

    /* the default set of sub-attributes for a multi-valued attribute */

    /* sub-attribute schemas of the attributes defined in SCIM common schema. */

    // sub attributes of the meta attributes

    //The name of the resource type of the resource.
    public static final SCIMAttributeSchema RESOURCE_TYPE =
            SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE,
                    SCIMDefinitions.DataType.STRING,false,SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_DESC,false,true,
                    SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.DEFAULT,
                    SCIMDefinitions.Uniqueness.NONE,null,null,null);

    //The "DateTime" that the resource was added to the service provider.
    public static final SCIMAttributeSchema CREATED =
            SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.CREATED,
                    SCIMDefinitions.DataType.DATE_TIME,false,SCIMConstants.CommonSchemaConstants.CREATED_DESC,false,false,
                    SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.DEFAULT,
                    SCIMDefinitions.Uniqueness.NONE,null,null,null);

    //The most recent DateTime that the details of this resource were updated at the service provider.
    public static final SCIMAttributeSchema LAST_MODIFIED =
            SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED,
                    SCIMDefinitions.DataType.DATE_TIME,false,SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_DESC,false,false,
                    SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.DEFAULT,
                    SCIMDefinitions.Uniqueness.NONE,null,null,null);

    //The URI of the resource being returned
    public static final SCIMAttributeSchema LOCATION =
            SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.LOCATION,
                    SCIMDefinitions.DataType.STRING,false,SCIMConstants.CommonSchemaConstants.LOCATION_DESC,false,false,
                    SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.DEFAULT,
                    SCIMDefinitions.Uniqueness.NONE,null,null,null);

    //The version of the resource being returned.
    //This value must be the same as the entity-tag (ETag) HTTP response header.
    public static final SCIMAttributeSchema VERSION =
            SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VERSION,
                    SCIMDefinitions.DataType.STRING,false,SCIMConstants.CommonSchemaConstants.VERSION_DESC,false,true,
                    SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.DEFAULT,
                    SCIMDefinitions.Uniqueness.NONE,null,null,null);

            /*---------------------------------------------------------------------------------------------*/

    /* attribute schemas of the attributes defined in common schema. */

    //A unique identifier for a SCIM resource as defined by the service provider
    public static final SCIMAttributeSchema ID =
            SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.ID,
                    SCIMDefinitions.DataType.STRING,false,SCIMConstants.CommonSchemaConstants.ID_DESC,true,true,
                    SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.ALWAYS,
                    SCIMDefinitions.Uniqueness.SERVER,null,null,null);

    //A String that is an identifier for the resource as defined by the provisioning client.
    //The service provider MUST always interpret the externalId as scoped to the provisioning domain.
    public static final SCIMAttributeSchema EXTERNAL_ID =
            SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.EXTERNAL_ID,
                    SCIMDefinitions.DataType.STRING,false,SCIMConstants.CommonSchemaConstants.EXTERNAL_ID_DESC,false,true,
                    SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                    SCIMDefinitions.Uniqueness.NONE,null,null,null);

    //A complex attribute containing resource metadata.
    public static final SCIMAttributeSchema META =
            SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.META,
                    SCIMDefinitions.DataType.COMPLEX,false,SCIMConstants.CommonSchemaConstants.META_DESC,false,false,
                    SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.DEFAULT,
                    SCIMDefinitions.Uniqueness.NONE,null,null,
                    new ArrayList<SCIMAttributeSchema>(Arrays.asList(RESOURCE_TYPE,CREATED,LAST_MODIFIED,LOCATION,VERSION)));


    private static class SCIMUserSchemaDefinition{

        /*********** SCIM defined user attribute schemas****************************/

    /* sub-attribute schemas of the attributes defined in SCIM user schema. */

        //sub attributes of email attribute

        //"Email addresses for the user.  The value SHOULD be canonicalized by the service provider, e.g.,\n" +
        //"'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'.Canonical type values of 'work', 'home', and 'other'.";
        public static final SCIMAttributeSchema EMAIL_VALUE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VALUE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.EMAIL_VALUE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A human-readable name, primarily used for display purposes.  READ-ONLY.
        public static final SCIMAttributeSchema EMAIL_DISPLAY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.EMAIL_DISPLAY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A label indicating the attribute's function, e.g., 'work' or 'home'.
        public static final SCIMAttributeSchema EMAIL_TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.EMAIL_TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,
                        new ArrayList<String>(Arrays.asList(SCIMConstants.UserSchemaConstants.WORK,
                                SCIMConstants.UserSchemaConstants.HOME,SCIMConstants.UserSchemaConstants.OTHER)),null,null);

        //A Boolean value indicating the 'primary' or preferred attribute value for this attribute
        public static final SCIMAttributeSchema EMAIL_PRIMARY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.PRIMARY,
                        SCIMDefinitions.DataType.BOOLEAN,false,SCIMConstants.UserSchemaConstants.EMAIL_PRIMARY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //sub attributes of phoneNumbers attribute

        //Phone number of the User.
        public static final SCIMAttributeSchema PHONE_NUMBERS_VALUE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VALUE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.PHONE_NUMBERS_VALUE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A human-readable name, primarily used for display purposes.
        public static final SCIMAttributeSchema PHONE_NUMBERS_DISPLAY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.PHONE_NUMBERS_DISPLAY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A label indicating the attribute's function, e.g., 'work', 'home', 'mobile'.
        public static final SCIMAttributeSchema PHONE_NUMBERS_TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.PHONE_NUMBERS_TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,
                        new ArrayList<String>(Arrays.asList(SCIMConstants.UserSchemaConstants.WORK,
                                SCIMConstants.UserSchemaConstants.HOME,SCIMConstants.UserSchemaConstants.OTHER,
                                SCIMConstants.UserSchemaConstants.FAX, SCIMConstants.UserSchemaConstants.MOBILE,
                                SCIMConstants.UserSchemaConstants.PAGER)),null,null);

        //A Boolean value indicating the 'primary' or preferred attribute value for this attribute
        public static final SCIMAttributeSchema PHONE_NUMBERS_PRIMARY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.PRIMARY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.PHONE_NUMBERS_PRIMARY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //sub attributes of ims attribute

        //Instant messaging address for the User.
        public static final SCIMAttributeSchema IMS_VALUE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VALUE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.IMS_VALUE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A human-readable name, primarily used for display purposes.
        public static final SCIMAttributeSchema IMS_DISPLAY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.IMS_DISPLAY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A label indicating the attribute's function, e.g., 'aim', 'gtalk', 'xmpp'
        public static final SCIMAttributeSchema IMS_TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.IMS_TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,
                        new ArrayList<String>(Arrays.asList(SCIMConstants.UserSchemaConstants.SKYPE,
                                SCIMConstants.UserSchemaConstants.YAHOO,SCIMConstants.UserSchemaConstants.GTALK,
                                SCIMConstants.UserSchemaConstants.AIM, SCIMConstants.UserSchemaConstants.ICQ,
                                SCIMConstants.UserSchemaConstants.XMPP,SCIMConstants.UserSchemaConstants.MSN,
                                SCIMConstants.UserSchemaConstants.QQ)),null,null);

        //A Boolean value indicating the 'primary' or preferred attribute value for this attribute
        public static final SCIMAttributeSchema IMS_PRIMARY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.PRIMARY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.IMS_PRIMARY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //sub attributes of photos attribute

        //URL of a photo of the User.
        public static final SCIMAttributeSchema PHOTOS_VALUE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VALUE,
                        SCIMDefinitions.DataType.REFERENCE,false,SCIMConstants.UserSchemaConstants.PHOTOS_VALUE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,
                        new ArrayList<SCIMDefinitions.ReferenceType>(Arrays.asList(SCIMDefinitions.ReferenceType.EXTERNAL)),null);

        //A human-readable name, primarily used for display purposes.
        public static final SCIMAttributeSchema PHOTOS_DISPLAY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.PHOTOS_DISPLAY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A label indicating the attribute's function, i.e., 'photo' or 'thumbnail'.
        public static final SCIMAttributeSchema PHOTOS_TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.PHOTOS_TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,
                        new ArrayList<String>(Arrays.asList(SCIMConstants.UserSchemaConstants.PHOTO,
                                SCIMConstants.UserSchemaConstants.THUMBNAIL)),null,null);

        //A Boolean value indicating the 'primary' or preferred attribute value for this attribute
        public static final SCIMAttributeSchema PHOTOS_PRIMARY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.PRIMARY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.PHOTOS_PRIMARY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);


        //sub attributes of addresses attribute

        //The full mailing address, formatted for display or use with a mailing label.
        public static final SCIMAttributeSchema ADDRESSES_FORMATTED=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.FORMATTED_ADDRESS,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ADDRESSES_FORMATTED_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The full street address component
        public static final SCIMAttributeSchema ADDRESSES_STREET_ADDRESS=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.STREET_ADDRESS,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ADDRESSES_STREET_ADDRESS_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The city or locality component.
        public static final SCIMAttributeSchema ADDRESSES_LOCALITY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.LOCALITY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ADDRESSES_LOCALITY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The state or region component.
        public static final SCIMAttributeSchema ADDRESSES_REGION=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.REGION,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ADDRESSES_REGION_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The zip code or postal code component
        public static final SCIMAttributeSchema ADDRESSES_POSTAL_CODE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.POSTAL_CODE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ADDRESSES_POSTAL_CODE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The country name component.
        public static final SCIMAttributeSchema ADDRESSES_COUNTRY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.COUNTRY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ADDRESSES_COUNTRY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A label indicating the attribute's function, e.g., 'work' or 'home'.
        public static final SCIMAttributeSchema ADDRESSES_TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ADDRESSES_TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,
                        new ArrayList<String>(Arrays.asList(SCIMConstants.UserSchemaConstants.WORK,
                                SCIMConstants.UserSchemaConstants.HOME,SCIMConstants.UserSchemaConstants.OTHER)),null,null);

        //A Boolean value indicating the 'primary' or preferred attribute value for this attribute
        public static final SCIMAttributeSchema ADDRESSES_PRIMARY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.PRIMARY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ADDRESSES_PRIMARY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //sub attributes of ims attribute

        //The identifier of the User's group.
        public static final SCIMAttributeSchema GROUP_VALUE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VALUE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.GROUP_VALUE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The URI of the corresponding 'Group' resource to which the user belongs.
        public static final SCIMAttributeSchema GROUP_$REF=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.$REF,
                        SCIMDefinitions.DataType.REFERENCE,false,SCIMConstants.UserSchemaConstants.GROUP_$REF_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,new ArrayList<SCIMDefinitions.ReferenceType>
                                (Arrays.asList(SCIMDefinitions.ReferenceType.USER,SCIMDefinitions.ReferenceType.GROUP)),null);

        //A human-readable name, primarily used for display purposes.
        public static final SCIMAttributeSchema GROUP_DISPLAY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.GROUP_DISPLAY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A label indicating the attribute's function, e.g., 'direct' or 'indirect'.
        public static final SCIMAttributeSchema GROUP_TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.GROUP_TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,new ArrayList<String>
                                (Arrays.asList(SCIMConstants.UserSchemaConstants.DIRECT_MEMBERSHIP,
                                        SCIMConstants.UserSchemaConstants.INDIRECT_MEMBERSHIP)),null,null);

        //sub attributes of entitlements attribute

        //The value of an entitlement.
        public static final SCIMAttributeSchema ENTITLEMENTS_VALUE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VALUE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ENTITLEMENTS_VALUE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A human-readable name, primarily used for display purposes.
        public static final SCIMAttributeSchema ENTITLEMENTS_DISPLAY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY,
                        SCIMDefinitions.DataType.REFERENCE,false,SCIMConstants.UserSchemaConstants.ENTITLEMENTS_DISPLAY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,new ArrayList<SCIMDefinitions.ReferenceType>
                                (Arrays.asList(SCIMDefinitions.ReferenceType.USER,SCIMDefinitions.ReferenceType.GROUP)),null);

        //A label indicating the attribute's function.
        public static final SCIMAttributeSchema ENTITLEMENTS_TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ENTITLEMENTS_TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        // Boolean value indicating the 'primary' or preferred attribute value for this attribute.he primary attribute value 'true' MUST appear no more than once.
        public static final SCIMAttributeSchema ENTITLEMENTS_PRIMARY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.PRIMARY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ENTITLEMENTS_PRIMARY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //sub attributes of entitlements attribute

        //The value of a role.
        public static final SCIMAttributeSchema ROLES_VALUE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VALUE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ROLES_VALUE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A human-readable name, primarily used for display purposes.
        public static final SCIMAttributeSchema ROLES_DISPLAY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY,
                        SCIMDefinitions.DataType.REFERENCE,false,SCIMConstants.UserSchemaConstants.ROLES_DISPLAY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A label indicating the attribute's function..
        public static final SCIMAttributeSchema ROLES_TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ROLES_TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A Boolean value indicating the 'primary' or preferred attribute value for this attribute.
        public static final SCIMAttributeSchema ROLES_PRIMARY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.PRIMARY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.ROLES_PRIMARY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //sub attributes of x509certificates attribute

        //The value of an X.509 certificate.
        public static final SCIMAttributeSchema X509CERTIFICATES_VALUE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VALUE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.X509CERTIFICATES_VALUE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A human-readable name, primarily used for display purposes.
        public static final SCIMAttributeSchema X509CERTIFICATES_DISPLAY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.DISPLAY,
                        SCIMDefinitions.DataType.REFERENCE,false,SCIMConstants.UserSchemaConstants.X509CERTIFICATES_DISPLAY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A label indicating the attribute's function..
        public static final SCIMAttributeSchema X509CERTIFICATES_TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.X509CERTIFICATES_TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A Boolean value indicating the 'primary' or preferred attribute value for this attribute.
        public static final SCIMAttributeSchema X509CERTIFICATES_PRIMARY=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.PRIMARY,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.X509CERTIFICATES_PRIMARY_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);


        //sub attributes of name attribute

        //The full name, including all middle names, titles, and suffixes as appropriate, formatted for display
        public static final SCIMAttributeSchema FORMATTED=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.FORMATTED_NAME,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.FORMATTED_NAME_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The family name of the User, or last name in most Western languages
        public static final SCIMAttributeSchema FAMILY_NAME=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.FAMILY_NAME,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.FAMILY_NAME_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The given name of the User, or first name in most Western languages.
        public static final SCIMAttributeSchema GIVEN_NAME=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.GIVEN_NAME,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.GIVEN_NAME_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The middle name(s) of the User.
        public static final SCIMAttributeSchema MIDDLE_NAME=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.MIDDLE_NAME,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.MIDDLE_NAME_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);//honorificPrefix

        //The honorific prefix(es) of the User, or title in most Western languages.
        public static final SCIMAttributeSchema HONORIFIC_PREFIX=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.HONORIFIC_PREFIX,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.HONORIFIC_PREFIX_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The honorific suffix(es) of the User, or suffix in most Western languages.
        public static final SCIMAttributeSchema HONORIFIC_SUFFIX=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.HONORIFIC_SUFFIX,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.HONORIFIC_SUFFIX_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

            /*-------------------------------------------------------------------------------------*/

            /* attribute schemas of the attributes defined in user schema. */

        //A service provider's unique identifier for the user, typically used by the user to directly
        //authenticate to the service provider.
        public static final SCIMAttributeSchema USERNAME=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.USER_NAME,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.USERNAME_DESC,true,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.SERVER,null,null,null);

        //The components of the user's real name.
        public static final SCIMAttributeSchema NAME=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.NAME,
                        SCIMDefinitions.DataType.COMPLEX,false,SCIMConstants.UserSchemaConstants.NAME_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,
                        new ArrayList<SCIMAttributeSchema>(Arrays.asList(FORMATTED,FAMILY_NAME,GIVEN_NAME,MIDDLE_NAME,
                                HONORIFIC_PREFIX,HONORIFIC_SUFFIX)));

        //The name of the User, suitable for display to end-users
        public static final SCIMAttributeSchema DISPLAY_NAME=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.DISPLAY_NAME,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.DISPLAY_NAME_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The casual way to address the user in real life
        public static final SCIMAttributeSchema NICK_NAME=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.NICK_NAME,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.NICK_NAME_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A fully qualified URL pointing to a page representing the User's online profile.
        public static final SCIMAttributeSchema PROFILE_URL=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.PROFILE_URL,
                        SCIMDefinitions.DataType.REFERENCE,false,SCIMConstants.UserSchemaConstants.PROFILE_URL_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,
                        new ArrayList<SCIMDefinitions.ReferenceType>(Arrays.asList(SCIMDefinitions.ReferenceType.EXTERNAL)),null);

        //The user's title, such as \"Vice President.\"
        public static final SCIMAttributeSchema TITLE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.TITLE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.TITLE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //Used to identify the relationship between the organization and the user.
        public static final SCIMAttributeSchema USER_TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.USER_TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.USER_TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //Indicates the User's preferred written or spoken language.
        public static final SCIMAttributeSchema PREFERRED_LANGUAGE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.PREFERRED_LANGUAGE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.PREFERRED_LANGUAGE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //Used to indicate the User's default location for purposes of localizing items such as currency,
        // date time format, or numerical representations.
        public static final SCIMAttributeSchema LOCALE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.LOCALE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.LOCALE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The User's time zone in the 'Olson' time zone database format, e.g., 'America/Los_Angeles'.
        public static final SCIMAttributeSchema TIME_ZONE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.TIME_ZONE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.UserSchemaConstants.TIME_ZONE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A Boolean value indicating the User's administrative status.
        public static final SCIMAttributeSchema ACTIVE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.ACTIVE,
                        SCIMDefinitions.DataType.BOOLEAN,false,SCIMConstants.UserSchemaConstants.ACTIVE_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The User's cleartext password.
        public static final SCIMAttributeSchema PASSWORD=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.PASSWORD,
                        SCIMDefinitions.DataType.BOOLEAN,false,SCIMConstants.UserSchemaConstants.PASSWORD_DESC,false,false,
                        SCIMDefinitions.Mutability.WRITE_ONLY,SCIMDefinitions.Returned.NEVER,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //Email addresses for the user.
        public static final SCIMAttributeSchema EMAILS=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.EMAILS,
                        SCIMDefinitions.DataType.COMPLEX,true,SCIMConstants.UserSchemaConstants.EMAILS_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,
                        new ArrayList<SCIMAttributeSchema>(Arrays.asList(EMAIL_VALUE, EMAIL_DISPLAY, EMAIL_TYPE, EMAIL_PRIMARY)));

        //Phone numbers for the User.
        public static final SCIMAttributeSchema PHONE_NUMBERS=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.PHONE_NUMBERS,
                        SCIMDefinitions.DataType.COMPLEX,true,SCIMConstants.UserSchemaConstants.PHONE_NUMBERS_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,
                        new ArrayList<SCIMAttributeSchema>(Arrays.asList(PHONE_NUMBERS_VALUE, PHONE_NUMBERS_DISPLAY,
                                PHONE_NUMBERS_TYPE, PHONE_NUMBERS_PRIMARY)));

        //Instant messaging addresses for the User.
        public static final SCIMAttributeSchema IMS=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.IMS,
                        SCIMDefinitions.DataType.COMPLEX,true,SCIMConstants.UserSchemaConstants.IMS_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,
                        new ArrayList<SCIMAttributeSchema>(Arrays.asList(IMS_VALUE, IMS_DISPLAY, IMS_TYPE, IMS_PRIMARY)));

        //URLs of photos of the User.
        public static final SCIMAttributeSchema PHOTOS=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.PHOTOS,
                        SCIMDefinitions.DataType.COMPLEX,true,SCIMConstants.UserSchemaConstants.PHOTOS_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,
                        new ArrayList<SCIMAttributeSchema>(Arrays.asList(PHOTOS_VALUE, PHOTOS_DISPLAY, PHOTOS_TYPE, PHOTOS_PRIMARY)));

        //A physical mailing address for this User.
        public static final SCIMAttributeSchema ADDRESSES=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.ADDRESSES,
                        SCIMDefinitions.DataType.COMPLEX,true,SCIMConstants.UserSchemaConstants.ADDRESSES_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,
                        new ArrayList<SCIMAttributeSchema>(Arrays.asList(ADDRESSES_FORMATTED,ADDRESSES_STREET_ADDRESS, ADDRESSES_LOCALITY,
                                ADDRESSES_REGION,ADDRESSES_POSTAL_CODE,ADDRESSES_COUNTRY,ADDRESSES_TYPE,ADDRESSES_PRIMARY)));

        //A list of groups to which the user belongs, either through direct membership, through nested groups, or dynamically calculated.
        public static final SCIMAttributeSchema GROUPS=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.GROUPS,
                        SCIMDefinitions.DataType.COMPLEX,true,SCIMConstants.UserSchemaConstants.GROUPS_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_ONLY,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,
                        new ArrayList<SCIMAttributeSchema>(Arrays.asList(GROUP_VALUE,GROUP_$REF,GROUP_DISPLAY,GROUP_TYPE)));

        //A list of entitlements for the User that represent a thing the User has.
        public static final SCIMAttributeSchema ENTITLEMENTS=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.ENTITLEMENTS,
                        SCIMDefinitions.DataType.COMPLEX,true,SCIMConstants.UserSchemaConstants.ENTITLEMENTS_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,
                        new ArrayList<SCIMAttributeSchema>(Arrays.asList(ENTITLEMENTS_VALUE,ENTITLEMENTS_DISPLAY,
                                ENTITLEMENTS_TYPE,ENTITLEMENTS_PRIMARY)));

        //A list of roles for the User that collectively represent who the User is, e.g., 'Student', 'Faculty'.
        public static final SCIMAttributeSchema ROLES=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.ROLES,
                        SCIMDefinitions.DataType.COMPLEX,true,SCIMConstants.UserSchemaConstants.ROLES_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,
                        new ArrayList<SCIMAttributeSchema>(Arrays.asList(ROLES_VALUE,ROLES_DISPLAY,
                                ROLES_TYPE,ROLES_PRIMARY)));

        //A list of roles for the User that collectively represent who the User is, e.g., 'Student', 'Faculty'.
        public static final SCIMAttributeSchema X509CERTIFICATES=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.UserSchemaConstants.X509CERTIFICATES,
                        SCIMDefinitions.DataType.COMPLEX,true,SCIMConstants.UserSchemaConstants.X509CERTIFICATES_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,
                        new ArrayList<SCIMAttributeSchema>(Arrays.asList(X509CERTIFICATES_VALUE,X509CERTIFICATES_DISPLAY,
                                X509CERTIFICATES_TYPE,X509CERTIFICATES_PRIMARY)));

    }

    private static class SCIMGroupSchemaDefinition{

        /*********** SCIM defined group attribute schemas ****************************/

    /* sub-attribute schemas of the attributes defined in SCIM group schema. */

        //sub attributes of members attribute

        //Identifier of the member of this Group.
        public static final SCIMAttributeSchema VALUE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VALUE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.GroupchemaConstants.VALUE_DESC,false,false,
                        SCIMDefinitions.Mutability.IMMUTABLE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The URI corresponding to a SCIM resource that is a member of this Group.
        public static final SCIMAttributeSchema $REF=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.$REF,
                        SCIMDefinitions.DataType.REFERENCE,false,SCIMConstants.GroupchemaConstants.$REF_DESC,false,false,
                        SCIMDefinitions.Mutability.IMMUTABLE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,new ArrayList<SCIMDefinitions.ReferenceType>
                                (Arrays.asList(SCIMDefinitions.ReferenceType.USER,SCIMDefinitions.ReferenceType.GROUP)),null);

        //A label indicating the type of resource, e.g., 'User' or 'Group'.
        public static final SCIMAttributeSchema TYPE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.TYPE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.GroupchemaConstants.TYPE_DESC,false,false,
                        SCIMDefinitions.Mutability.IMMUTABLE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,new ArrayList<String>(Arrays.asList(SCIMConstants.GroupchemaConstants.USER,
                                SCIMConstants.GroupchemaConstants.GROUP)),null,null);

    /*------------------------------------------------------------------------------------------------------*/

                /* attribute schemas of the attributes defined in group schema. */

        //A human-readable name for the Group. REQUIRED.
        public static final SCIMAttributeSchema DISPLAY_NAME=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.GroupchemaConstants.DISPLAY_NAME,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.GroupchemaConstants.DISPLAY_NAME_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //A list of members of the Group.
        public static final SCIMAttributeSchema MEMBERS=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.GroupchemaConstants.MEMBERS,
                        SCIMDefinitions.DataType.COMPLEX,true,SCIMConstants.GroupchemaConstants.MEMBERS_DESC,false,false,
                        SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,new ArrayList<SCIMAttributeSchema>(Arrays.asList(VALUE,$REF,TYPE)));
    }


    private static class SCIMEnterpriseUserSchemaDefinition{

        /*********** SCIM defined Enterprise User attribute schemas ****************************/

        /* sub-attribute schemas of the attributes defined in SCIM Enterprise User schema. */

        //sub attributes of manager attribute

        //Identifies the name of a cost center.
        public static final SCIMAttributeSchema VALUE=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.VALUE,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.EnterpriseUserSchemaConstants.VALUE_DESC,
                        false,false, SCIMDefinitions.Mutability.IMMUTABLE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The URI of the SCIM resource representing the User's manager.  REQUIRED.
        public static final SCIMAttributeSchema $REF=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.CommonSchemaConstants.$REF,
                        SCIMDefinitions.DataType.REFERENCE,false,SCIMConstants.EnterpriseUserSchemaConstants.$REF_DESC,
                        false,false, SCIMDefinitions.Mutability.IMMUTABLE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The displayName of the User's manager.OPTIONAL and READ-ONLY.
        public static final SCIMAttributeSchema DISPLAY_NAME=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.EnterpriseUserSchemaConstants.DISPLAY_NAME,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.EnterpriseUserSchemaConstants.DISPLAY_NAME_DESC,
                        false,false, SCIMDefinitions.Mutability.IMMUTABLE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

    /*------------------------------------------------------------------------------------------------------*/

                /* attribute schemas of the attributes defined in Enterprise User schema. */

        //Numeric or alphanumeric identifier assigned to a person, typically based on order of hire or association with an organization.
        public static final SCIMAttributeSchema EMPLOYEE_NUMBER=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.EnterpriseUserSchemaConstants.EMPLOYEE_NUMBER,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.EnterpriseUserSchemaConstants.EMPLOYEE_NUMBER_DESC,
                        false,false, SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //Identifies the name of a cost center.
        public static final SCIMAttributeSchema COST_CENTER=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.EnterpriseUserSchemaConstants.COST_CENTER,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.EnterpriseUserSchemaConstants.COST_CENTER_DESC,
                        false,false, SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //Identifies the name of an organization.
        public static final SCIMAttributeSchema ORGANIZATION=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.EnterpriseUserSchemaConstants.ORGANIZATION,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.EnterpriseUserSchemaConstants.ORGANIZATION_DESC,
                        false,false, SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //Identifies the name of a division.
        public static final SCIMAttributeSchema DIVISION=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.EnterpriseUserSchemaConstants.DIVISION,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.EnterpriseUserSchemaConstants.DIVISION_DESC,
                        false,false, SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //Identifies the name of a department.
        public static final SCIMAttributeSchema DEPARTMENT=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.EnterpriseUserSchemaConstants.DEPARTMENT,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.EnterpriseUserSchemaConstants.DEPARTMENT_DESC,
                        false,false, SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,null);

        //The User's manager.
        public static final SCIMAttributeSchema MANAGER=
                SCIMAttributeSchema.createSCIMAttributeSchema(SCIMConstants.EnterpriseUserSchemaConstants.DEPARTMENT,
                        SCIMDefinitions.DataType.STRING,false,SCIMConstants.EnterpriseUserSchemaConstants.DEPARTMENT_DESC,
                        false,false, SCIMDefinitions.Mutability.READ_WRITE,SCIMDefinitions.Returned.DEFAULT,
                        SCIMDefinitions.Uniqueness.NONE,null,null,new ArrayList<SCIMAttributeSchema>(Arrays.asList(
                                SCIMEnterpriseUserSchemaDefinition.VALUE, SCIMEnterpriseUserSchemaDefinition.$REF,
                                SCIMEnterpriseUserSchemaDefinition.DISPLAY_NAME)));
    }

    /**
     * **********SCIM defined User Resource Schema****************************
     */

    public static final SCIMResourceTypeSchema SCIM_USER_SCHEMA =
            SCIMResourceTypeSchema.createSCIMResourceSchema(
                    SCIMConstants.USER_CORE_SCHEMA_URI,
                    ID,EXTERNAL_ID,META,
                    SCIMUserSchemaDefinition.USERNAME,
                    SCIMUserSchemaDefinition.NAME,
                    SCIMUserSchemaDefinition.DISPLAY_NAME,
                    SCIMUserSchemaDefinition.NICK_NAME,
                    SCIMUserSchemaDefinition.PROFILE_URL,
                    SCIMUserSchemaDefinition.TITLE,
                    SCIMUserSchemaDefinition.USER_TYPE,
                    SCIMUserSchemaDefinition.PREFERRED_LANGUAGE,
                    SCIMUserSchemaDefinition.LOCALE,
                    SCIMUserSchemaDefinition.TIME_ZONE,
                    SCIMUserSchemaDefinition.ACTIVE,
                    SCIMUserSchemaDefinition.PASSWORD,
                    SCIMUserSchemaDefinition.EMAILS,
                    SCIMUserSchemaDefinition.PHONE_NUMBERS,
                    SCIMUserSchemaDefinition.IMS,
                    SCIMUserSchemaDefinition.PHOTOS,
                    SCIMUserSchemaDefinition.ADDRESSES,
                    SCIMUserSchemaDefinition.GROUPS,
                    SCIMUserSchemaDefinition.ENTITLEMENTS,
                    SCIMUserSchemaDefinition.ROLES,
                    SCIMUserSchemaDefinition.X509CERTIFICATES);

    /**
     * **********SCIM defined Group Resource Schema****************************
     */

    public static final SCIMResourceTypeSchema SCIM_GROUP_SCHEMA =
            SCIMResourceTypeSchema.createSCIMResourceSchema(
                    SCIMConstants.GROUP_CORE_SCHEMA_URI,
                    ID,EXTERNAL_ID,META,
                    SCIMGroupSchemaDefinition.DISPLAY_NAME,
                    SCIMGroupSchemaDefinition.MEMBERS);

    /**
     * **********SCIM defined EnterpriseUser Resource Schema****************************
     */

    public static final SCIMResourceTypeSchema SCIM_EnterpriseUser_SCHEMA =
            SCIMResourceTypeSchema.createSCIMResourceSchema(
                    SCIMConstants.GROUP_CORE_SCHEMA_URI,
                    ID,EXTERNAL_ID,META,
                    SCIMGroupSchemaDefinition.DISPLAY_NAME,
                    SCIMGroupSchemaDefinition.MEMBERS);
}