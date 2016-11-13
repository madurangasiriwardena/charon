package org.wso2.charon.core.v2.protocol.endpoints;


import org.wso2.charon.core.v2.attributes.SimpleAttribute;
import org.wso2.charon.core.v2.config.CharonConfiguration;
import org.wso2.charon.core.v2.encoder.JSONDecoder;
import org.wso2.charon.core.v2.encoder.JSONEncoder;
import org.wso2.charon.core.v2.exceptions.*;
import org.wso2.charon.core.v2.extensions.UserManager;
import org.wso2.charon.core.v2.objects.ListedResource;
import org.wso2.charon.core.v2.objects.User;
import org.wso2.charon.core.v2.protocol.ResponseCodeConstants;
import org.wso2.charon.core.v2.protocol.SCIMResponse;
import org.wso2.charon.core.v2.schema.SCIMResourceSchemaManager;
import org.wso2.charon.core.v2.schema.SCIMResourceTypeSchema;
import org.wso2.charon.core.v2.utils.AttributeUtil;
import org.wso2.charon.core.v2.utils.codeutils.FilterTreeManager;
import org.wso2.charon.core.v2.utils.codeutils.Node;
import org.wso2.charon.core.v2.utils.codeutils.PatchOperation;
import org.wso2.charon.core.v2.attributes.Attribute;
import org.wso2.charon.core.v2.objects.PaginatedListedResource;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;
import org.wso2.charon.core.v2.schema.SCIMConstants;
import org.wso2.charon.core.v2.schema.ServerSideValidator;
import org.wso2.charon.core.v2.utils.CopyUtil;
import org.wso2.charon.core.v2.utils.codeutils.SearchRequest;

import java.io.IOException;
import java.util.*;

/**
 * REST API exposed by Charon-Core to perform operations on UserResource.
 * Any SCIM service provider can call this API perform relevant CRUD operations on USER ,
 * based on the HTTP requests received by SCIM Client.
 */

public class UserResourceManager extends AbstractResourceManager {

    private Log logger;

    public UserResourceManager() {
        logger = LogFactory.getLog(UserResourceManager.class);
    }

    /**
     * Retrieves a user resource given an unique user id. Mapped to HTTP GET request.
     *
     * @param id          - unique resource id
     * @param userManager - userManager instance defined by the external implementor of charon
     * @return SCIM response to be returned.
     */
    public SCIMResponse get(String id, UserManager userManager, String attributes, String excludeAttributes) {
        JSONEncoder encoder = null;
        try {
            //obtain the json encoder
            encoder = getEncoder();
            //obtain the  URIs for attributes
            ArrayList<String> attributesURIList = getAttributeURIs(attributes);
            //obtain the  URIs for excludedAttributes
            ArrayList<String> excludedAttributesURIList = getAttributeURIs(excludeAttributes);

            /*API user should pass a UserManager impl to UserResourceEndpoint.
            retrieve the user from the provided UM handler.*/
            User user = ((UserManager) userManager).getUser(id, attributesURIList, excludedAttributesURIList);

            //if user not found, return an error in relevant format.
            if (user == null) {
                String error = "User not found in the user store.";
                throw new NotFoundException(error);
            }
            //obtain the schema corresponding to user
            // unless configured returns core-user schema or else returns extended user schema)
            SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
            //perform service provider side validation.
            ServerSideValidator.validateRetrievedSCIMObject(user, schema, attributes, excludeAttributes);
            //convert the user into requested format.
            String encodedUser = encoder.encodeSCIMObject(user);
            //if there are any http headers to be added in the response header.
            Map<String, String> ResponseHeaders = new HashMap<String, String>();
            ResponseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
            ResponseHeaders.put(SCIMConstants.LOCATION_HEADER, getResourceEndpointURL(
                    SCIMConstants.USER_ENDPOINT) + "/" + user.getId());
            return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedUser, ResponseHeaders);

        } catch (NotFoundException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (CharonException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (BadRequestException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        }
    }

    /**
     * Returns SCIMResponse based on the sucess or failure of the create user operation
     *
     * @param scimObjectString -raw string containing user info
     * @return userManager - userManager instance defined by the external implementor of charon
     */
    public SCIMResponse create(String scimObjectString, UserManager userManager,
                               String attributes, String excludeAttributes)  {

        JSONEncoder encoder =null;
        try {
            //obtain the json encoder
            encoder = getEncoder();

            //obtain the json decoder
            JSONDecoder decoder = getDecoder();
            //obtain the  URIs for attributes
            ArrayList<String> attributesURIList = getAttributeURIs(attributes);
            //obtain the  URIs for excludedAttributes
            ArrayList<String> excludedAttributesURIList = getAttributeURIs(excludeAttributes);

            //obtain the schema corresponding to user
            // unless configured returns core-user schema or else returns extended user schema)
            SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
            //decode the SCIM User object, encoded in the submitted payload.
            User user = (User) decoder.decodeResource(scimObjectString, schema, new User());
            //validate the created user.
            ServerSideValidator.validateCreatedSCIMObject(user, schema);

            User createdUser ;

            if (userManager != null) {
            /*handover the SCIM User object to the user storage provided by the SP.
            need to send back the newly created user in the response payload*/
                createdUser = userManager.createUser(user, attributesURIList, excludedAttributesURIList);
            }
            else{
                String error = "Provided user manager handler is null.";
                //throw internal server error.
                throw new InternalErrorException(error);
            }
            //encode the newly created SCIM user object and add id attribute to Location header.
            String encodedUser;
            Map<String, String> ResponseHeaders = new HashMap<String, String>();

            if (createdUser != null) {
                //create a deep copy of the user object since we are going to change it.
                User copiedUser = (User) CopyUtil.deepCopy(createdUser);
                //need to remove password before returning
                ServerSideValidator.removeAttributesOnReturn(copiedUser, attributes, excludeAttributes);
                encodedUser = encoder.encodeSCIMObject(copiedUser);
                //add location header
                ResponseHeaders.put(SCIMConstants.LOCATION_HEADER, getResourceEndpointURL(
                        SCIMConstants.USER_ENDPOINT) + "/" + createdUser.getId());
                ResponseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);

            } else {
                String error = "Newly created User resource is null.";
                throw new InternalErrorException(error);
            }

            //put the URI of the User object in the response header parameter.
            return new SCIMResponse(ResponseCodeConstants.CODE_CREATED,
                    encodedUser, ResponseHeaders);

        } catch (CharonException e) {
            //we have charon exceptions also, instead of having only internal server error exceptions,
            //because inside API code throws CharonException.
            if (e.getStatus() == -1) {
                e.setStatus(ResponseCodeConstants.CODE_INTERNAL_ERROR);
            }
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (BadRequestException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (ConflictException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (InternalErrorException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotFoundException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        }
    }

    /**
     * Method of the ResourceManager that is mapped to HTTP Delete method..
     *
     * @param id - unique resource id
     * @param userManager - userManager instance defined by the external implementor of charon
     * @return
     */

    public SCIMResponse delete(String id,UserManager userManager) {
        JSONEncoder encoder = null;
        try {
            if (userManager != null) {
            /*handover the SCIM User object to the user storage provided by the SP for the delete operation*/
                userManager.deleteUser(id);
                //on successful deletion SCIMResponse only has 204 No Content status code.
                return new SCIMResponse(ResponseCodeConstants.CODE_NO_CONTENT, null, null);
            }
            else{
                String error = "Provided user manager handler is null.";
                //throw internal server error.
                throw new InternalErrorException(error);
            }
        } catch (NotFoundException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (CharonException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (InternalErrorException e) {
            return AbstractResourceManager.encodeSCIMException(e);
      } catch (NotImplementedException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (BadRequestException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        }
    }


    /**
     * Method that maps to HTTP GET with URL query parameter: "filter=filterString"
     * This is to filter a sub set of resources matching the filter string
     *
     * @param filterString
     * @param userManager
     * @param attributes
     * @param  excludeAttributes
     * @return
     */
    @Override
    public SCIMResponse listByFilter(String filterString, UserManager userManager,
                                     String attributes, String excludeAttributes) {

        JSONEncoder encoder = null;

        FilterTreeManager filterTreeManager = null;
        try {
            // unless configured returns core-user schema or else returns extended user schema)
            SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

            filterTreeManager = new FilterTreeManager(filterString, schema);
            Node rootNode = filterTreeManager.buildTree();

            //obtain the  URIs for attributes
            ArrayList<String> attributesURIList = getAttributeURIs(attributes);
            //obtain the  URIs for excludedAttributes
            ArrayList<String> excludedAttributesURIList = getAttributeURIs(excludeAttributes);

            //obtain the json encoder
            encoder = getEncoder();

            List<User> returnedUsers;
            int totalResults=0;
            //API user should pass a UserManager storage to UserResourceEndpoint.
            if (userManager != null) {
                returnedUsers = userManager.filterUsers(rootNode, attributesURIList, excludedAttributesURIList);

                //if user not found, return an error in relevant format.
                if (returnedUsers == null || returnedUsers.isEmpty()) {
                    String error = "No filter results are found";
                    //throw resource not found.
                    throw new NotFoundException(error);
                }

                for(User user:returnedUsers){
                    //perform service provider side validation.
                    ServerSideValidator.validateRetrievedSCIMObjectInList(user, schema, attributes, excludeAttributes);
                }
                //create a listed resource object out of the returned users list.
                ListedResource listedResource = createListedResource(returnedUsers);
                //convert the listed resource into specific format.
                String encodedListedResource = encoder.encodeSCIMObject(listedResource);
                //if there are any http headers to be added in the response header.
                Map<String, String> ResponseHeaders = new HashMap<String, String>();
                ResponseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
                return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedListedResource, ResponseHeaders);

            } else {
                String error = "Provided user manager handler is null.";
                //throw internal server error.
                throw new InternalErrorException(error);
            }
        } catch (BadRequestException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        }catch (IOException e) {
            String error = "Error in tokenization of the input filter";
            CharonException charonException =new CharonException(error);
            return AbstractResourceManager.encodeSCIMException(charonException);
        } catch (CharonException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotFoundException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (InternalErrorException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotImplementedException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        }
    }

    /**
     * Method that maps to HTTP GET with URL query parameter: "sortBy=attributeName&sortOrder=ascending"
     * This is to sort the resources in the given criteria
     *
     * @param sortBy
     * @param sortOrder
     * @param usermanager
     * @param attributes
     * @param excludeAttributes
     */
    @Override
    public SCIMResponse listBySort(String sortBy, String sortOrder, UserManager usermanager,
                                   String attributes, String excludeAttributes) {
        try {
            //check whether provided sortOrder is valid or not
            if(sortOrder != null ){
                if(!(sortOrder.equalsIgnoreCase(SCIMConstants.OperationalConstants.ASCENDING)
                        || sortOrder.equalsIgnoreCase(SCIMConstants.OperationalConstants.DESCENDING))){
                    String error = " Invalid sortOrder value is specified";
                    throw new BadRequestException(error, ResponseCodeConstants.INVALID_VALUE);
                }
            }
            //If a value for "sortBy" is provided and no "sortOrder" is specified, "sortOrder" SHALL default to ascending.
            if(sortOrder == null && sortBy != null){
                sortOrder = SCIMConstants.OperationalConstants.ASCENDING;
            }
            JSONEncoder encoder = null;
            //obtain the json encoder
            encoder = getEncoder();
            //obtain the  URIs for attributes
            ArrayList<String> attributesURIList = getAttributeURIs(attributes);
            //obtain the  URIs for excludedAttributes
            ArrayList<String> excludedAttributesURIList = getAttributeURIs(excludeAttributes);

            List<User> returnedUsers;

            //API user should pass a UserManager storage to UserResourceEndpoint.
            if (usermanager != null) {
                // unless configured returns core-user schema or else returns extended user schema)
                SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

                String sortByAttributeURI = null;

                if(sortBy != null){
                    sortByAttributeURI = AttributeUtil.getAttributeURI(sortBy,schema);
                }
                returnedUsers = usermanager.sortUsers(sortByAttributeURI, sortOrder.toLowerCase(),
                        attributesURIList, excludedAttributesURIList);

                //if user not found, return an error in relevant format.
                if (returnedUsers == null || returnedUsers.isEmpty()) {
                    String error = "Users not found in the user store.";
                    //throw resource not found.
                    throw new NotFoundException(error);
                }

                for(User user:returnedUsers){
                    //perform service provider side validation.
                    ServerSideValidator.validateRetrievedSCIMObjectInList(user, schema, attributes, excludeAttributes);
                }
                //create a listed resource object out of the returned users list.
                ListedResource listedResource = createListedResource(returnedUsers);
                //convert the listed resource into specific format.
                String encodedListedResource = encoder.encodeSCIMObject(listedResource);
                //if there are any http headers to be added in the response header.
                Map<String, String> ResponseHeaders = new HashMap<String, String>();
                ResponseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
                return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedListedResource, ResponseHeaders);

            } else {
                String error = "Provided user manager handler is null.";
                //log the error as well.
                //throw internal server error.
                throw new InternalErrorException(error);
            }
        } catch (CharonException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotFoundException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (InternalErrorException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (BadRequestException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotImplementedException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        }
    }

    /**
     * To list all the resources of resource endpoint with pagination.
     *
     * @param startIndex
     * @param count
     * @param userManager
     * @param attributes
     * @param excludeAttributes
     * @return
     */
    public SCIMResponse listWithPagination(int startIndex, int count, UserManager userManager,
                                           String attributes, String excludeAttributes) {
        //A value less than one shall be interpreted as 1
        if(startIndex<1){
            startIndex=1;
        }
        //If count is not set, server default should be taken
        if(count == 0){
            count = CharonConfiguration.getInstance().getCountValueForPagination();
        }
        JSONEncoder encoder = null;
        try {
            //obtain the json encoder
            encoder = getEncoder();

            //obtain the  URIs for attributes
            ArrayList<String> attributesURIList = getAttributeURIs(attributes);
            //obtain the  URIs for excludedAttributes
            ArrayList<String> excludedAttributesURIList = getAttributeURIs(excludeAttributes);

            List<User> returnedUsers;
            int totalResults=0;
            //API user should pass a UserManager storage to UserResourceEndpoint.
            if (userManager != null) {
                returnedUsers = userManager.listUsersWithPagination(
                        startIndex, count, attributesURIList, excludedAttributesURIList);

                //TODO: Are we having this method support from user core
                totalResults =userManager.getUserCount();

                //if user not found, return an error in relevant format.
                if (returnedUsers == null || returnedUsers.isEmpty()) {
                    String error = "Users not found in the user store.";
                    //throw resource not found.
                    throw new NotFoundException(error);
                }

                // unless configured returns core-user schema or else returns extended user schema)
                SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

                for(User user:returnedUsers){
                    //perform service provider side validation.
                    ServerSideValidator.validateRetrievedSCIMObjectInList(user, schema, attributes, excludeAttributes);
                }
                //create a listed resource object out of the returned users list.
                PaginatedListedResource listedResource = createPaginatedListedResource(
                        returnedUsers,startIndex,totalResults);
                //convert the listed resource into specific format.
                String encodedListedResource = encoder.encodeSCIMObject(listedResource);
                //if there are any http headers to be added in the response header.
                Map<String, String> ResponseHeaders = new HashMap<String, String>();
                ResponseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
                return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedListedResource, ResponseHeaders);

            } else {
                String error = "Provided user manager handler is null.";
                //throw internal server error.
                throw new InternalErrorException(error);
            }
        } catch (CharonException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotFoundException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (InternalErrorException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (BadRequestException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotImplementedException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        }
    }

    /**
     * To list all the resources of resource endpoint.
     *
     * @param userManager
     * @param attributes
     * @param excludeAttributes
     * @return
     */

    public SCIMResponse list(UserManager userManager, String attributes, String excludeAttributes)
    {
        JSONEncoder encoder = null;
        try {
            //obtain the json encoder
            encoder = getEncoder();
            //obtain the  URIs for attributes
            ArrayList<String> attributesURIList = getAttributeURIs(attributes);
            //obtain the  URIs for excludedAttributes
            ArrayList<String> excludedAttributesURIList = getAttributeURIs(excludeAttributes);

            List<User> returnedUsers;
            //API user should pass a UserManager storage to UserResourceEndpoint.
            if (userManager != null) {
                returnedUsers = userManager.listUsers(attributesURIList, excludedAttributesURIList);

                //if user not found, return an error in relevant format.
                if (returnedUsers == null || returnedUsers.isEmpty()) {
                    String error = "Users not found in the user store.";
                    //throw resource not found.
                    throw new NotFoundException(error);
                }
                // unless configured returns core-user schema or else returns extended user schema)
                SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

                for(User user:returnedUsers){
                    //perform service provider side validation.
                    ServerSideValidator.validateRetrievedSCIMObjectInList(user, schema, attributes, excludeAttributes);
                }
                //create a listed resource object out of the returned users list.
                ListedResource listedResource = createListedResource(returnedUsers);
                //convert the listed resource into specific format.
                String encodedListedResource = encoder.encodeSCIMObject(listedResource);
                //if there are any http headers to be added in the response header.
                Map<String, String> ResponseHeaders = new HashMap<String, String>();
                ResponseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
                return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedListedResource, ResponseHeaders);

            } else {
                String error = "Provided user manager handler is null.";
                //log the error as well.
                //throw internal server error.
                throw new InternalErrorException(error);
            }
        } catch (CharonException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotFoundException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (InternalErrorException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (BadRequestException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotImplementedException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        }
    }

    /*
     * this facilitates the querying using HTTP POST
     * @param resourceString
     * @param userManager
     * @return
     */

    public SCIMResponse listUsersWithPOST(String resourceString, UserManager userManager)
    {
        JSONEncoder encoder = null;
        JSONDecoder decoder = null;
        try {
            //obtain the json encoder
            encoder = getEncoder();

            //obtain the json decoder
            decoder = getDecoder();

            //create the search request object
            SearchRequest searchRequest = decoder.decodeSearchRequestBody(resourceString);

            //A value less than one shall be interpreted as 1
            if(searchRequest.getStartIndex() < 1){
                searchRequest.setStartIndex(1);
            }
            //If count is not set, server default should be taken
            if(searchRequest.getCount() == 0){
                searchRequest.setCount(CharonConfiguration.getInstance().getCountValueForPagination());
            }

                List<User> returnedUsers;
                int totalResults=0;
                //API user should pass a UserManager storage to UserResourceEndpoint.
                if (userManager != null) {
                    returnedUsers = userManager.listUsersWithPost(searchRequest);

                    //TODO: Are we having this method support from user core
                    totalResults = userManager.getUserCount();

                    //if user not found, return an error in relevant format.
                    if (returnedUsers == null || returnedUsers.isEmpty()) {
                        String error = "Users not found in the user store.";
                        //throw resource not found.
                        throw new NotFoundException(error);
                    }

                    // unless configured returns core-user schema or else returns extended user schema)
                    SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

                    for(User user:returnedUsers){
                        //perform service provider side validation.
                        ServerSideValidator.validateRetrievedSCIMObjectInList(user, schema,
                                searchRequest.getAttributesAsString(), searchRequest.getExcludedAttributesAsString());
                    }
                    //create a listed resource object out of the returned users list.
                    PaginatedListedResource listedResource = createPaginatedListedResource(
                            returnedUsers, searchRequest.getStartIndex(), totalResults);
                    //convert the listed resource into specific format.
                    String encodedListedResource = encoder.encodeSCIMObject(listedResource);
                    //if there are any http headers to be added in the response header.
                    Map<String, String> ResponseHeaders = new HashMap<String, String>();
                    ResponseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
                    return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedListedResource, ResponseHeaders);

                } else {
                    String error = "Provided user manager handler is null.";
                    //throw internal server error.
                    throw new InternalErrorException(error);
                }
            } catch (CharonException e) {
                return AbstractResourceManager.encodeSCIMException(e);
            } catch (NotFoundException e) {
                return AbstractResourceManager.encodeSCIMException(e);
            } catch (InternalErrorException e) {
                return AbstractResourceManager.encodeSCIMException(e);
            } catch (BadRequestException e) {
                return AbstractResourceManager.encodeSCIMException(e);
            } catch (NotImplementedException e) {
                return AbstractResourceManager.encodeSCIMException(e);
            }
    }

    /**
     * To update the user by giving entire attribute set
     * @param existingId
     * @param scimObjectString
     * @param userManager
     * @return
     */
    public SCIMResponse updateWithPUT(String existingId, String scimObjectString, UserManager userManager,
                                      String attributes, String excludeAttributes) {
        //needs to validate the incoming object. eg: id can not be set by the consumer.

        JSONEncoder encoder = null;
        JSONDecoder decoder = null;

        try {
            //obtain the json encoder
            encoder = getEncoder();
            //obtain the json decoder.
            decoder = getDecoder();
            //obtain the  URIs for attributes
            ArrayList<String> attributesURIList = getAttributeURIs(attributes);
            //obtain the  URIs for excludedAttributes
            ArrayList<String> excludedAttributesURIList = getAttributeURIs(excludeAttributes);

            SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

            //decode the SCIM User object, encoded in the submitted payload.
            User user = (User) decoder.decodeResource(scimObjectString, schema, new User());
            User updatedUser = null;
            if (userManager != null) {
                //retrieve the old object
                User oldUser = userManager.getUser(existingId, null, null);
                if (oldUser != null) {
                    User validatedUser = (User) ServerSideValidator.validateUpdatedSCIMObject(oldUser, user, schema);
                    updatedUser = userManager.updateUser(validatedUser, attributesURIList, excludedAttributesURIList);

                } else {
                    String error = "No user exists with the given id: " + existingId;
                    throw new NotFoundException(error);
                }

            } else {
                String error = "Provided user manager handler is null.";
                throw new InternalErrorException(error);
            }
            //encode the newly created SCIM user object and add id attribute to Location header.
            String encodedUser;
            Map<String, String> httpHeaders = new HashMap<String, String>();
            if (updatedUser != null) {
                //create a deep copy of the user object since we are going to change it.
                User copiedUser = (User) CopyUtil.deepCopy(updatedUser);
                //need to remove password before returning
                ServerSideValidator.removeAttributesOnReturn(copiedUser,attributes,excludeAttributes);
                encodedUser = encoder.encodeSCIMObject(copiedUser);
                //add location header
                httpHeaders.put(SCIMConstants.LOCATION_HEADER, getResourceEndpointURL(
                        SCIMConstants.USER_ENDPOINT) + "/" + updatedUser.getId());
                httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);

            } else {
                String error = "Updated User resource is null.";
                throw new CharonException(error);
            }

            //put the URI of the User object in the response header parameter.
            return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedUser, httpHeaders);

        } catch (NotFoundException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (BadRequestException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (CharonException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (InternalErrorException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotImplementedException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        }
    }

    /**
     * Update the user resource by sequence of operations
     *
     * @param existingId
     * @param scimObjectString
     * @param userManager
     * @param attributes
     * @param excludeAttributes
     * @return
     */
    public SCIMResponse updateWithPATCH(String existingId, String scimObjectString, UserManager userManager,
                                        String attributes, String excludeAttributes) {

        JSONEncoder encoder = null;
        JSONDecoder decoder = null;

        ArrayList<PatchOperation> operationList = new ArrayList<PatchOperation>();
        try {
            //obtain the json encoder
            encoder = getEncoder();
            //obtain the json decoder.
            decoder = getDecoder();
            //obtain the  URIs for attributes
            ArrayList<String> attributesURIList = getAttributeURIs(attributes);
            //obtain the  URIs for excludedAttributes
            ArrayList<String> excludedAttributesURIList = getAttributeURIs(excludeAttributes);

            if (existingId != null) {
                //retrieve the old object
                User oldUser = userManager.getUser(existingId, attributesURIList, excludedAttributesURIList);
                if (oldUser == null) {
                    String error = "No user exists with the given id: " + existingId;
                    throw new NotFoundException(error);
                }
                operationList = decoder.decodeRequest(scimObjectString);
                for(PatchOperation patchOperation : operationList){
                    if(patchOperation.getOperation().equals(SCIMConstants.OperationalConstants.ADD)){
                        patchOperationAdd(oldUser, patchOperation);
                    }
                    else if(patchOperation.getOperation().equals(SCIMConstants.OperationalConstants.REMOVE)){
                        patchOperationRemove(oldUser, patchOperation);
                    }
                    else if(patchOperation.getOperation().equals(SCIMConstants.OperationalConstants.REPLACE)){
                        patchOperationReplace(oldUser, patchOperation);
                    }
                }
            }
            else{
                //PATCH is for modifying resources, not endpoints, hence if existing id is not specified,
                // an error need to be thrown
                String error = "No user resource is specified in the request";
                throw new BadRequestException(error, ResponseCodeConstants.NO_TARGET);
            }
        } catch (CharonException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (NotFoundException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (BadRequestException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (InternalErrorException e) {
            return AbstractResourceManager.encodeSCIMException(e);
        }
        return null;
    }

    /**
     * Creates the Listed Resource.
     *
     * @param users
     * @return
     */
    public ListedResource createListedResource(List<User> users)
            throws CharonException, NotFoundException {
        ListedResource listedResource = new ListedResource();
        listedResource.setSchema(SCIMConstants.LISTED_RESOURCE_CORE_SCHEMA_URI);
        listedResource.setTotalResults(users.size());
        for (User user : users) {
            Map<String, Attribute> userAttributes = user.getAttributeList();
            listedResource.setResources(userAttributes);
        }
        return listedResource;
    }


    /**
     * Creates the Paginated Listed Resource.
     *
     * @param users
     * @return
     */
    private PaginatedListedResource createPaginatedListedResource(List<User> users,int startIndex, int totalResults)
            throws CharonException, NotFoundException {
        PaginatedListedResource paginatedListedResource = new PaginatedListedResource();
        paginatedListedResource.setSchema(SCIMConstants.LISTED_RESOURCE_CORE_SCHEMA_URI);
        paginatedListedResource.setTotalResults(totalResults);
        paginatedListedResource.setItemsPerPage(users.size());
        paginatedListedResource.setStartIndex(startIndex);

        for (User user : users) {
            Map<String, Attribute> userAttributes = user.getAttributeList();
            paginatedListedResource.setResources(userAttributes);
        }
        return paginatedListedResource;
    }


    private void patchOperationAdd(User oldUser, PatchOperation patchOperation) throws CharonException,
            BadRequestException, InternalErrorException {
        //obtain the json decoder.
        JSONDecoder decoder = getDecoder();
        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        User newUser = (User) decoder.decodeResource((String) patchOperation.getValues().toString(), schema, new User());
        Map<String,Attribute> attributeMap = newUser.getAttributeList();

        for(Attribute attribute : attributeMap.values()){
            if(attribute instanceof SimpleAttribute){

            }
        }

    }

    private void patchOperationReplace(User oldUser, PatchOperation patchOperation) throws CharonException {

        //obtain the json decoder.
        JSONDecoder decoder = getDecoder();

    }

    private void patchOperationRemove(User oldUser, PatchOperation patchOperation) throws CharonException {

        //obtain the json decoder.
        JSONDecoder decoder = getDecoder();


    }
}
