/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.charon3.core.protocol.endpoints;

import org.json.JSONObject;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.charon3.core.encoder.JSONDecoder;
import org.wso2.charon3.core.encoder.JSONEncoder;
import org.wso2.charon3.core.exceptions.AbstractCharonException;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.InternalErrorException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.schema.ServerSideValidator;
import org.wso2.charon3.core.utils.CopyUtil;
import org.wso2.charon3.core.utils.ResourceManagerUtil;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Test class of UserResourceManager.
 */
@PrepareForTest({AbstractResourceManager.class})
public class UserResourceManagerTest extends PowerMockTestCase {

    private final String userID = "123";
    private final String newUserSCIMObjectString = "{\n" +
            "  \"schemas\": \n" +
            "    [\"urn:ietf:params:scim:schemas:core:2.0:User\",\n" +
            "    \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\"\n" +
            "    ],\n" +
            "\"meta\": {\n" +
            "    \"created\": \"2018-08-17T10:34:29Z\",\n" +
            "    \"location\": \"ENDPOINT/008bba85-451d-414b-87de-c03b5a1f4217\",\n" +
            "    \"lastModified\": \"2018-08-17T10:34:29Z\",\n" +
            "    \"resourceType\": \"User\"\n" +
            "},\n" +
            " \"name\": {\n" +
            "    \"givenName\": \"Kim\",\n" +
            "    \"familyName\": \"Berry\",\n" +
            "    \"formatted\": \"Kim Berry\"\n" +
            "  },\n" +
            "  \"userName\": \"kimjohn  \",\n" +
            "  \"password\": \"kim123\",\n" +
            "  \"id\": \"" + userID + "\",\n" +
            "  \"emails\": [\n" +
            "      {\n" +
            "        \"type\": \"home\",\n" +
            "        \"value\": \"john@gmail.com\",\n" +
            "         \"primary\": true\n" +
            "      }\n" +
            "  ]\n" +
            "}";

    private final String newUserSCIMObjectStringUpdate = "{\n" +
            "  \"schemas\": \n" +
            "    [\"urn:ietf:params:scim:schemas:core:2.0:User\",\n" +
            "    \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\"\n" +
            "    ],\n" +
            "\"meta\": {\n" +
            "    \"created\": \"2018-08-17T10:34:29Z\",\n" +
            "    \"location\": \"ENDPOINT/008bba85-451d-414b-87de-c03b5a1f4217\",\n" +
            "    \"lastModified\": \"2018-08-17T10:34:29Z\",\n" +
            "    \"resourceType\": \"User\"\n" +
            "},\n" +
            " \"name\": {\n" +
            "    \"givenName\": \"Kim\",\n" +
            "    \"familyName\": \"Berry\",\n" +
            "    \"formatted\": \"Kim Berry\"\n" +
            "  },\n" +
            "  \"userName\": \"kimjohn  \",\n" +
            "  \"password\": \"kim123\",\n" +
            "  \"id\": \"" + userID + "\",\n" +
            "  \"emails\": [\n" +
            "      {\n" +
            "        \"type\": \"home\",\n" +
            "        \"value\": \"john2@gmail.com\",\n" +
            "         \"primary\": true\n" +
            "      }\n" +
            "  ]\n" +
            "}";

    private final String newUserSCIMObjectStringPatch = "{\n" +
            "  \"schemas\": \n" +
            "    [\"urn:ietf:params:scim:schemas:core:2.0:User\",\n" +
            "    \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\",\n" +
            "    \"urn:ietf:params:scim:api:messages:2.0:PatchOp\"\n" +
            "    ],\n" +
            "\"meta\": {\n" +
            "    \"created\": \"2018-08-17T10:34:29Z\",\n" +
            "    \"location\": \"ENDPOINT/008bba85-451d-414b-87de-c03b5a1f4217\",\n" +
            "    \"lastModified\": \"2018-08-17T10:34:29Z\",\n" +
            "    \"resourceType\": \"User\"\n" +
            "},\n" +
            "  \"Operations\": [\n" +
            "    {\n" +
            "      \"op\": \"add\",\n" +
            "      \"value\": {\n" +
            "        \"nickName\": \"shaggy\"\n" +
            "      }\n" +
            "    }\n" +
            "  ],   \n" +
            " \"name\": {\n" +
            "    \"givenName\": \"Kim\",\n" +
            "    \"familyName\": \"Berry\",\n" +
            "    \"formatted\": \"Kim Berry\"\n" +
            "  },\n" +
            "  \"userName\": \"kimjohn  \",\n" +
            "  \"password\": \"kim123\",\n" +
            "  \"id\": \"" + userID + "\",\n" +
            "  \"emails\": [\n" +
            "      {\n" +
            "        \"type\": \"home\",\n" +
            "        \"value\": \"john@gmail.com\",\n" +
            "         \"primary\": true\n" +
            "      }\n" +
            "  ]\n" +
            "}";

    private final String newUserSCIMObjectStringPatchUpdate = "{\n" +
            "  \"schemas\": \n" +
            "    [\"urn:ietf:params:scim:schemas:core:2.0:User\",\n" +
            "    \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\",\n" +
            "    \"urn:ietf:params:scim:api:messages:2.0:PatchOp\"\n" +
            "    ],\n" +
            "\"meta\": {\n" +
            "    \"created\": \"2018-08-17T10:34:29Z\",\n" +
            "    \"location\": \"ENDPOINT/008bba85-451d-414b-87de-c03b5a1f4217\",\n" +
            "    \"lastModified\": \"2018-08-17T10:34:29Z\",\n" +
            "    \"resourceType\": \"User\"\n" +
            "},\n" +
            "  \"Operations\": [\n" +
            "    {\n" +
            "      \"op\": \"add\",\n" +
            "      \"value\": {\n" +
            "        \"nickName\": \"shaggy\"\n" +
            "      }\n" +
            "    }\n" +
            "  ],   \n" +
            " \"name\": {\n" +
            "    \"givenName\": \"Kim\",\n" +
            "    \"familyName\": \"Berry\",\n" +
            "    \"formatted\": \"Kim Berry\"\n" +
            "  },\n" +
            "  \"userName\": \"kimjohn  \",\n" +
            "  \"password\": \"kim123\",\n" +
            "  \"id\": \"" + userID + "\",\n" +
            "  \"emails\": [\n" +
            "      {\n" +
            "        \"type\": \"home\",\n" +
            "        \"value\": \"johnnew@gmail.com\",\n" +
            "         \"primary\": true\n" +
            "      }\n" +
            "  ]\n" +
            "}";

    private final String endpoint = "https://localhost:9443/scim2/User";

    private final int internalError = 500;
    private final int notImplemented = 501;
    private final int badRequest = 400;
    private final int charon = 500;
    private final int notFound = 404;
    private final int success = 200;
    private final int createSuccess = 201;
    private final int conflict = 409;
    private final int deleteSuccess = 204;

    private UserResourceManager userResourceManager;
    private UserManager userManager;

    @BeforeMethod
    public void setUp() {

        userResourceManager = new UserResourceManager();
        userManager = mock(UserManager.class);
    }

    @AfterMethod
    public void tearDown() {

    }

    private SCIMResponse getEncodeSCIMExceptionObject(AbstractCharonException exception) {

        JSONEncoder encoder = new JSONEncoder();
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
        return new SCIMResponse(exception.getStatus(), encoder.encodeSCIMException(exception), responseHeaders);
    }

    private User getNewUser() throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        return decoder.decodeResource(newUserSCIMObjectString, schema, new User());
    }

    @DataProvider(name = "dataForGetSuccess")
    public Object[][] dataToGetSuccess() throws CharonException, InternalErrorException, BadRequestException {

        User user = getNewUser();
        String id = user.getId();

        return new Object[][]{
                {id, "userName", null, 200, user}
        };
    }

    @Test(dataProvider = "dataForGetSuccess")
    public void testGetSuccess(String id, String attributes,
                               String excludeAttributes, int expectedScimResponseStatus, Object objectUser)
            throws BadRequestException, NotFoundException, CharonException {

        User user = (User) objectUser;

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        Map<String, Boolean> requiredAttributes = ResourceManagerUtil.getOnlyRequiredAttributesURIs(
                (SCIMResourceTypeSchema) CopyUtil.deepCopy(schema), attributes, excludeAttributes);

        mockStatic(AbstractResourceManager.class);
        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn("https://localhost:9443/scim2/Users");
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(userManager.getUser(id, requiredAttributes)).thenReturn(user);

        SCIMResponse outputScimResponse = userResourceManager.get(id, userManager, attributes, excludeAttributes);
        JSONObject obj = new JSONObject(outputScimResponse.getResponseMessage());

        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);
        Assert.assertEquals(obj.getString("id"), id);
    }

    @DataProvider(name = "dataForGetThrowingExceptions")
    public Object[][] dataToGetThrowingExceptions() {

        return new Object[][]{
                {"1234", "userName", null}
        };
    }

    @Test(dataProvider = "dataForGetThrowingExceptions")
    public void testGetThrowingExceptions(String id, String attributes,
                                          String excludeAttributes)
            throws CharonException, BadRequestException, NotFoundException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        Map<String, Boolean> requiredAttributes = ResourceManagerUtil.getOnlyRequiredAttributesURIs(
                (SCIMResourceTypeSchema) CopyUtil.deepCopy(schema), attributes, excludeAttributes);

        mockStatic(AbstractResourceManager.class);
        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn("https://localhost:9443/scim2/Users");
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(userManager.getUser(id, requiredAttributes)).thenReturn(null);

        SCIMResponse outputScimResponse = userResourceManager.get(id, userManager, attributes, excludeAttributes);

        Assert.assertNull(outputScimResponse);
    }

    @DataProvider(name = "dataForListWithGetInt")
    public Object[][] dataToGetListInt() throws CharonException, BadRequestException, InternalErrorException {

        return new Object[][]{
                {null, 1, 2, null, null, "PRIMARY", "emails", null, 200}
        };
    }

    @Test(dataProvider = "dataForListWithGetInt")
    public void testListWithGetInt(String filter, int startIndexInt, int countInt,
                                   String sortBy, String sortOrder, String domainName, String attributes,
                                   String excludeAttributes, int expectedScimResponseStatus) {

        SCIMResponse outputScimResponse = userResourceManager.listWithGET(userManager, filter, startIndexInt,
                countInt, sortBy, sortOrder, domainName, attributes, excludeAttributes);

        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);
    }

    @DataProvider(name = "dataForListWithGetInteger")
    public Object[][] dataToGetListInteger() throws CharonException, BadRequestException, InternalErrorException {

        return new Object[][]{
                {null, 1, 2, null, null, "PRIMARY", "emails", null, 200},
                {"userName sw Rash", 1, 2, null, null, "PRIMARY", "userName,name.familyName",
                        "emails", 200}
        };
    }

    @Test(dataProvider = "dataForListWithGetInteger")
    public void testListWithGetInteger(String filter, Integer startIndexInt,
                                       Integer countInt, String sortBy, String sortOrder, String domainName,
                                       String attributes, String excludeAttributes, int expectedScimResponseStatus) {

        SCIMResponse outputScimResponse = userResourceManager.listWithGET(userManager, filter, startIndexInt,
                countInt, sortBy, sortOrder, domainName, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);
    }

    @DataProvider(name = "dataForGetNotFoundException")
    public Object[][] dataToGetNotFoundException() {

        return new Object[][]{
                {"Obama", "userName", null, notFound}
        };
    }

    @Test(dataProvider = "dataForGetNotFoundException")
    public void testGetUserNotFoundException(String name, String attributes, String excludeAttributes,
                                             int expectedScimResponseStatus)
            throws CharonException, BadRequestException, NotFoundException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        Map<String, Boolean> requiredAttributes = ResourceManagerUtil.getOnlyRequiredAttributesURIs(
                (SCIMResourceTypeSchema)
                        CopyUtil.deepCopy(schema), attributes, excludeAttributes);

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(NotFoundException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new NotFoundException()));
        when(userManager.getUser(name, requiredAttributes)).thenReturn(null);

        SCIMResponse outputScimResponse = userResourceManager.get(name, userManager, attributes, excludeAttributes);

        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);
    }

    @DataProvider(name = "dataForGetCharonException")
    public Object[][] dataToGetCharonException() {

        return new Object[][]{
                {"Obama", "userName", null, charon}
        };
    }

    @Test(dataProvider = "dataForGetCharonException")
    public void testGetUserCharonException(String name, String attributes, String excludeAttributes,
                                           int expectedScimResponseStatus)
            throws CharonException, BadRequestException, NotFoundException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        Map<String, Boolean> requiredAttributes = ResourceManagerUtil.getOnlyRequiredAttributesURIs(
                (SCIMResourceTypeSchema)
                        CopyUtil.deepCopy(schema), attributes, excludeAttributes);

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(CharonException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new CharonException()));
        when(userManager.getUser(name, requiredAttributes)).thenThrow(CharonException.class);

        SCIMResponse outputScimResponse = userResourceManager.get(name, userManager, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForGetBadRequestException")
    public Object[][] dataToGetCharonBadRequestException() {

        return new Object[][]{
                {"Obama", "userName", null, badRequest}
        };
    }

    @Test(dataProvider = "dataForGetBadRequestException")
    public void testGetUserBadRequestException(String name, String attributes, String excludeAttributes,
                                               int expectedScimResponseStatus)
            throws CharonException, BadRequestException, NotFoundException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        Map<String, Boolean> requiredAttributes = ResourceManagerUtil.getOnlyRequiredAttributesURIs(
                (SCIMResourceTypeSchema)
                        CopyUtil.deepCopy(schema), attributes, excludeAttributes);

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(BadRequestException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new BadRequestException()));
        when(userManager.getUser(name, requiredAttributes)).thenThrow(BadRequestException.class);

        SCIMResponse outputScimResponse = userResourceManager.get(name, userManager, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestCreateSuccess")
    public Object[][] dataToTestCreateSuccess() throws BadRequestException, CharonException, InternalErrorException {

        User user = getNewUser();

        return new Object[][]{
                {newUserSCIMObjectString, "userName", null, user, createSuccess}
        };
    }

    @Test(dataProvider = "dataForTestCreateSuccess")
    public void testCreateSuccess(String scimObjectString, String attributes, String excludeAttributes,
                                  Object objectUser, int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, ConflictException {

        User user = (User) objectUser;
        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());

        when(userManager.createUser(anyObject(), anyObject())).thenReturn(user);

        SCIMResponse outputScimResponse = userResourceManager.create(scimObjectString, userManager,
                attributes, excludeAttributes);
        JSONObject obj = new JSONObject(outputScimResponse.getResponseMessage());

        //Assertions
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

        String returnedURI = outputScimResponse.getHeaderParamMap().get("Location");
        String expectedURI = endpoint + "/" + obj.getString("id");
        Assert.assertEquals(returnedURI, expectedURI);

    }

    //InternalErrorException
    @DataProvider(name = "dataForTestCreateProvidedUserManagerHandlerIsNull")
    public Object[][] dataToTestCreateProvidedUserManagerHandlerIsNull()
            throws BadRequestException, CharonException, InternalErrorException {

        User user = getNewUser();

        return new Object[][]{
                {newUserSCIMObjectString, "userName", null, user, internalError}
        };
    }

    //InternalErrorException
    @Test(dataProvider = "dataForTestCreateProvidedUserManagerHandlerIsNull")
    public void testCreateProvidedUserManagerHandlerIsNull(String scimObjectString, String attributes,
                                                           String excludeAttributes, Object objectUser,
                                                           int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, ConflictException {

        User user = (User) objectUser;
        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(InternalErrorException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new InternalErrorException()));
        when(userManager.createUser(anyObject(), anyObject())).thenReturn(user);

        SCIMResponse outputScimResponse = userResourceManager.create(scimObjectString,
                null, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    //InternalErrorException
    @DataProvider(name = "dataForTestCreateNewlyCreatedUserResourceIsNull")
    public Object[][] dataToTestCreateNewlyCreatedUserResourceIsNull() {

        return new Object[][]{
                {newUserSCIMObjectString, "userName", null, internalError}
        };
    }

    //InternalErrorException
    @Test(dataProvider = "dataForTestCreateNewlyCreatedUserResourceIsNull")
    public void testCreateNewlyCreatedUserResourceIsNull(String scimObjectString, String attributes,
                                                         String excludeAttributes,
                                                         int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, ConflictException {

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(InternalErrorException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new InternalErrorException()));
        when(userManager.createUser(anyObject(), anyObject())).thenReturn(null);

        SCIMResponse outputScimResponse = userResourceManager.create(scimObjectString,
                userManager, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestCreateBadRequestException")
    public Object[][] dataToTestCreatBadRequestException() {

        return new Object[][]{
                {newUserSCIMObjectString, "userName", null, badRequest}
        };
    }

    @Test(dataProvider = "dataForTestCreateBadRequestException")
    public void testCreateBadRequestException(String scimObjectString, String attributes,
                                              String excludeAttributes,
                                              int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, ConflictException {

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(BadRequestException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new BadRequestException()));
        when(userManager.createUser(anyObject(), anyObject())).thenThrow(BadRequestException.class);

        SCIMResponse outputScimResponse = userResourceManager.create(scimObjectString,
                userManager, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestCreateConflictException")
    public Object[][] dataToTestCreatConflictException() {

        return new Object[][]{
                {newUserSCIMObjectString, "userName", null, conflict}
        };
    }

    @Test(dataProvider = "dataForTestCreateConflictException")
    public void testCreateConflictException(String scimObjectString, String attributes,
                                            String excludeAttributes,
                                            int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, ConflictException {

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(ConflictException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new ConflictException()));
        when(userManager.createUser(anyObject(), anyObject())).thenThrow(ConflictException.class);

        SCIMResponse outputScimResponse = userResourceManager.create(scimObjectString, userManager,
                attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestCreateNotFoundException")
    public Object[][] dataToTestCreateNotFoundException() {

        return new Object[][]{
                {newUserSCIMObjectString, "userName", null, notFound}
        };
    }

    @Test(dataProvider = "dataForTestCreateNotFoundException")
    public void testCreateNotFoundException(String scimObjectString, String attributes,
                                            String excludeAttributes,
                                            int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, ConflictException {

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(NotFoundException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new NotFoundException()));
        when(userManager.createUser(anyObject(), anyObject())).thenThrow(NotFoundException.class);

        SCIMResponse outputScimResponse = userResourceManager.create(scimObjectString, userManager,
                attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestCreateCharonException")
    public Object[][] dataToTestCreateCharonException() {

        return new Object[][]{
                {newUserSCIMObjectString, "userName", null, charon}
        };
    }

    @Test(dataProvider = "dataForTestCreateCharonException")
    public void testCreateCharonException(String scimObjectString, String attributes,
                                          String excludeAttributes,
                                          int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, ConflictException {

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(ConflictException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new CharonException()));
        when(userManager.createUser(anyObject(), anyObject())).thenThrow(CharonException.class);

        SCIMResponse outputScimResponse = userResourceManager.create(scimObjectString, userManager,
                attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestDeleteSuccess")
    public Object[][] dataToTestDeleteSuccess()
            throws BadRequestException, CharonException, InternalErrorException {

        User user = getNewUser();
        String id = user.getId();
        return new Object[][]{
                {id, deleteSuccess}
        };
    }

    @Test(dataProvider = "dataForTestDeleteSuccess")
    public void testDeleteSuccess(String id, int expectedScimResponseStatus)
            throws NotFoundException {

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);

        SCIMResponse outputScimResponse = userResourceManager.delete(id, userManager);

        //Assertions
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestDeleteFails")
    public Object[][] dataToTestDeleteFails()
            throws BadRequestException, CharonException, InternalErrorException {

        User user = getNewUser();
        String id = user.getId();
        return new Object[][]{
                {id, internalError},
                {id, notFound},
                {id, notImplemented},
                {id, badRequest}
        };
    }

    @Test(dataProvider = "dataForTestDeleteFails")
    public void testDeleteFails(String id, int expectedScimResponseStatus)
            throws NotFoundException, NotImplementedException, BadRequestException, CharonException {

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);

        if (expectedScimResponseStatus == internalError) {

            when(AbstractResourceManager.encodeSCIMException(any(InternalErrorException.class)))
                    .thenReturn(getEncodeSCIMExceptionObject(new InternalErrorException()));

            SCIMResponse outputScimResponse = userResourceManager.delete(id, null);
            Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

        } else if (expectedScimResponseStatus == notFound) {

            doThrow(new NotFoundException()).when(userManager).deleteUser(id);

            when(AbstractResourceManager.encodeSCIMException(any(NotFoundException.class)))
                    .thenReturn(getEncodeSCIMExceptionObject(new NotFoundException()));

            SCIMResponse outputScimResponse = userResourceManager.delete(id, userManager);
            Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

        } else if (expectedScimResponseStatus == notImplemented) {

            doThrow(new NotImplementedException()).when(userManager).deleteUser(id);

            when(AbstractResourceManager.encodeSCIMException(any(NotFoundException.class)))
                    .thenReturn(getEncodeSCIMExceptionObject(new NotImplementedException()));

            SCIMResponse outputScimResponse = userResourceManager.delete(id, userManager);
            Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

        } else if (expectedScimResponseStatus == badRequest) {

            doThrow(new BadRequestException()).when(userManager).deleteUser(id);

            when(AbstractResourceManager.encodeSCIMException(any(BadRequestException.class)))
                    .thenReturn(getEncodeSCIMExceptionObject(new BadRequestException()));

            SCIMResponse outputScimResponse = userResourceManager.delete(id, userManager);
            Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);
        }

    }

    @DataProvider(name = "dataForTestDeleteFailsINCharonExceptionOnly")
    public Object[][] dataToTestDeleteCharonExceptionOnly()
            throws BadRequestException, CharonException, InternalErrorException {

        User user = getNewUser();
        String username = user.getUsername();
        return new Object[][]{
                {username, charon}
        };
    }

    @Test(dataProvider = "dataForTestDeleteFailsINCharonExceptionOnly")
    public void testDeleteCharonExceptionOnly(String id, int expectedScimResponseStatus)
            throws NotFoundException, NotImplementedException, BadRequestException, CharonException {

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);

        doThrow(new CharonException()).when(userManager).deleteUser(id);

        when(AbstractResourceManager.encodeSCIMException(any(CharonException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new CharonException()));

        SCIMResponse outputScimResponse = userResourceManager.delete(id, userManager);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestUpdateWithPUTSuccess")
    public Object[][] dataToTestUpdateWithPUTSuccess()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectString, schema, new User());
        String id = userOld.getId();

        User userNew = decoder.decodeResource(newUserSCIMObjectStringUpdate, schema, new User());

        return new Object[][]{
                {id, newUserSCIMObjectStringUpdate, "userName", null, userNew, userOld, success}
        };
    }

    @Test(dataProvider = "dataForTestUpdateWithPUTSuccess")
    public void testUpdateWithPUTSuccess(String existingId, String scimObjectString, String
            attributes, String excludeAttributes, Object objectNEWUser,
                                         Object objectOLDUser, int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, NotImplementedException {

        User userNew = (User) objectNEWUser;
        User userOld = (User) objectOLDUser;

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenReturn(userOld);

        User validatedUser = (User) ServerSideValidator.validateUpdatedSCIMObject(userOld, userNew, schema);
        when(userManager.updateUser(anyObject(), anyObject())).thenReturn(validatedUser);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPUT(existingId, scimObjectString, userManager,
                attributes, excludeAttributes);
        JSONObject obj = new JSONObject(outputScimResponse.getResponseMessage());

        //Assertions
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestUpdateWithPUTProvidedUserManagerHandlerIsNull")
    public Object[][] dataToTestUpdateWithPUTProvidedUserManagerHandlerIsNull()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectString, schema, new User());
        String id = userOld.getId();

        User userNew = decoder.decodeResource(newUserSCIMObjectStringUpdate, schema, new User());

        return new Object[][]{
                {id, newUserSCIMObjectStringUpdate, "userName", null, userNew, userOld, internalError}
        };
    }

    //InternalErrorException
    @Test(dataProvider = "dataForTestUpdateWithPUTProvidedUserManagerHandlerIsNull")
    public void testUpdateWithPUTProvidedUserManagerHandlerIsNull(String existingId, String scimObjectString, String
            attributes, String excludeAttributes, Object objectNEWUser, Object objectOLDUser,
                                                                  int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, NotImplementedException {

        User userNew = (User) objectNEWUser;
        User userOld = (User) objectOLDUser;

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(InternalErrorException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new InternalErrorException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenReturn(userOld);

        User validatedUser = (User) ServerSideValidator.validateUpdatedSCIMObject(userOld, userNew, schema);
        when(userManager.updateUser(anyObject(), anyObject())).thenReturn(validatedUser);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPUT(existingId, scimObjectString, null,
                attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestUpdateWithPUTNotFoundException")
    public Object[][] dataToTestUpdateWithPUTNotFoundException()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectString, schema, new User());
        String id = userOld.getId();

        User userNew = decoder.decodeResource(newUserSCIMObjectStringUpdate, schema, new User());

        return new Object[][]{
                {id, newUserSCIMObjectStringUpdate, "userName", null, userNew, userOld, notFound}
        };
    }

    //NotFoundException
    @Test(dataProvider = "dataForTestUpdateWithPUTNotFoundException")
    public void testUpdateWithPUTNoUserExistsWithTheGivenUserName(String existingId, String scimObjectString, String
            attributes, String excludeAttributes, Object objectNEWUser,
                                                                  Object objectOLDUser, int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, NotImplementedException {

        User userNew = (User) objectNEWUser;
        User userOld = (User) objectOLDUser;

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(NotFoundException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new NotFoundException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenReturn(null);

        User validatedUser = (User) ServerSideValidator.validateUpdatedSCIMObject(userOld, userNew, schema);
        when(userManager.updateUser(anyObject(), anyObject())).thenReturn(validatedUser);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPUT(existingId, scimObjectString, userManager,
                attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestUpdateWithPUTCharonException")
    public Object[][] dataToTestUpdateWithPUTCharonException()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectString, schema, new User());
        String id = userOld.getUserName();

        return new Object[][]{
                {id, newUserSCIMObjectStringUpdate, "userName", null, userOld, charon}
        };
    }

    // CharonException
    @Test(dataProvider = "dataForTestUpdateWithPUTCharonException")
    public void testUpdateWithPUTUpdatedUserResourceIsNull(String existingId, String scimObjectString, String
            attributes, String excludeAttributes, Object objectOLDUser, int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, NotImplementedException {

        User userOld = (User) objectOLDUser;

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(CharonException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new CharonException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenReturn(userOld);

        when(userManager.updateUser(anyObject(), anyObject())).thenReturn(null);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPUT(existingId, scimObjectString, userManager,
                attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestUpdateWithPUTNotImplementedException")
    public Object[][] dataToTestUpdateWithPUTNotImplementedException()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectString, schema, new User());
        String id = userOld.getUserName();

        return new Object[][]{
                {id, newUserSCIMObjectStringUpdate, "userName", null, notImplemented}
        };
    }

    //NotImplementedException
    @Test(dataProvider = "dataForTestUpdateWithPUTNotImplementedException")
    public void testUpdateWithPUTNotImplementedException(String existingId, String scimObjectString, String
            attributes, String excludeAttributes, int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(NotImplementedException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new NotImplementedException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenThrow(NotImplementedException.class);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPUT(existingId, scimObjectString, userManager,
                attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForTestUpdateWithPUTBadRequestException")
    public Object[][] dataToTestUpdateWithPUTBadRequestException()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectString, schema, new User());
        String name = userOld.getUserName();

        return new Object[][]{
                {name, newUserSCIMObjectStringUpdate, "userName", null, badRequest}
        };
    }

    // BadRequestException
    @Test(dataProvider = "dataForTestUpdateWithPUTBadRequestException")
    public void testUpdateWithPUTBadRequestException(String existingId, String scimObjectString, String
            attributes, String excludeAttributes, int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(BadRequestException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new BadRequestException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenThrow(BadRequestException.class);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPUT(existingId, scimObjectString, userManager,
                attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @Test(dataProvider = "dataForUpdateWithPATCH")
    public void testUpdateWithPATCH(String existingId, String scimObjectString,
                                    String attributes, String excludeAttributes, Object objectNEWUser,
                                    Object objectOLDUser, int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, NotImplementedException {

        User userNew = (User) objectNEWUser;
        User userOld = (User) objectOLDUser;

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenReturn(userOld);

        User validatedUser = (User) ServerSideValidator.validateUpdatedSCIMObject(userOld, userNew, schema);
        when(userManager.updateUser(anyObject(), anyObject())).thenReturn(validatedUser);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPATCH(existingId, scimObjectString,
                userManager, attributes, excludeAttributes);
        JSONObject obj = new JSONObject(outputScimResponse.getResponseMessage());

        //Assertions
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

        String returnedURI = outputScimResponse.getHeaderParamMap().get("Location");
        String expectedURI = endpoint + "/" + obj.getString("id");
        Assert.assertEquals(returnedURI, expectedURI);

    }

    @DataProvider(name = "dataForUpdateWithPATCHProvidedUserManagerHandlerIsNull")
    public Object[][] dataToUpdateWithPATCHInProvidedUserManagerHandlerIsNull()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectStringPatch, schema, new User());
        String id = userOld.getId();

        User userNew = decoder.decodeResource(newUserSCIMObjectStringPatchUpdate, schema, new User());

        return new Object[][]{
                {id, newUserSCIMObjectStringPatchUpdate, "userName", null, userNew, userOld, internalError}
        };
    }

    //InternalErrorException
    @Test(dataProvider = "dataForUpdateWithPATCHProvidedUserManagerHandlerIsNull")
    public void testUpdateWithPATCHProvidedUserManagerHandlerIsNull(String existingId, String scimObjectString,
                                                                    String attributes, String excludeAttributes,
                                                                    Object objectNEWUser,
                                                                    Object objectOLDUser,
                                                                    int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, NotImplementedException {

        User userNew = (User) objectNEWUser;
        User userOld = (User) objectOLDUser;

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(InternalErrorException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new InternalErrorException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenReturn(userOld);

        User validatedUser = (User) ServerSideValidator.validateUpdatedSCIMObject(userOld, userNew, schema);
        when(userManager.updateUser(anyObject(), anyObject())).thenReturn(validatedUser);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPATCH(existingId, scimObjectString,
                null, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);
    }

    @DataProvider(name = "dataForUpdateWithPATCHNotFoundException")
    public Object[][] dataToUpdateWithPATCHNotFoundException()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectStringPatch, schema, new User());
        String id = userOld.getId();

        User userNew = decoder.decodeResource(newUserSCIMObjectStringPatchUpdate, schema, new User());

        return new Object[][]{
                {id, newUserSCIMObjectStringPatchUpdate, "userName", null, userNew, userOld, notFound}
        };
    }

    //NotFoundException
    @Test(dataProvider = "dataForUpdateWithPATCHNotFoundException")
    public void testUpdateWithPATCHNoAssociatedUserExitsInTheUserStore(String existingId, String scimObjectString,
                                                                       String attributes, String excludeAttributes,
                                                                       Object objectNEWUser,
                                                                       Object objectOLDUser,
                                                                       int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, NotImplementedException {

        User userNew = (User) objectNEWUser;
        User userOld = (User) objectOLDUser;

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(NotFoundException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new NotFoundException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenReturn(null);

        User validatedUser = (User) ServerSideValidator.validateUpdatedSCIMObject(userOld, userNew, schema);
        when(userManager.updateUser(anyObject(), anyObject())).thenReturn(validatedUser);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPATCH(existingId, scimObjectString,
                userManager, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForUpdateWithPATCHCharonException")
    public Object[][] dataToUpdateWithPATCHCharonException()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectStringPatch, schema, new User());
        String id = userOld.getId();

        return new Object[][]{
                {id, newUserSCIMObjectStringPatchUpdate, "userName", null, userOld, charon}
        };
    }

    //CharonException
    @Test(dataProvider = "dataForUpdateWithPATCHCharonException")
    public void testUpdateWithPATCHUpdatedUserResourceIsNull(String existingId, String scimObjectString,
                                                             String attributes, String excludeAttributes,
                                                             Object objectOLDUser, int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException, NotImplementedException {

        User userOld = (User) objectOLDUser;

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(CharonException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new CharonException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenReturn(userOld);

        when(userManager.updateUser(anyObject(), anyObject())).thenReturn(null);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPATCH(existingId, scimObjectString,
                userManager, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForUpdateWithPATCHBadRequestException")
    public Object[][] dataToUpdateWithPATCHBadRequestException()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectStringPatch, schema, new User());
        String id = userOld.getId();

        return new Object[][]{
                {id, newUserSCIMObjectStringPatchUpdate, "userName", null, badRequest}
        };
    }

    //BadRequestException
    @Test(dataProvider = "dataForUpdateWithPATCHBadRequestException")
    public void testUpdateWithPATCHBadRequestException(String existingId, String scimObjectString,
                                                       String attributes, String excludeAttributes,
                                                       int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(BadRequestException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new BadRequestException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenThrow(BadRequestException.class);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPATCH(existingId, scimObjectString,
                userManager, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForUpdateWithPATCHNotImplementedException")
    public Object[][] dataToUpdateWithPATCHNotImplementedException()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectStringPatch, schema, new User());
        String id = userOld.getId();

        return new Object[][]{
                {id, newUserSCIMObjectStringPatchUpdate, "userName", null, notImplemented}
        };
    }

    //NotImplementedException
    @Test(dataProvider = "dataForUpdateWithPATCHNotImplementedException")
    public void testUpdateWithPATCHNotImplementedException(String existingId, String scimObjectString,
                                                           String attributes, String excludeAttributes,
                                                           int expectedScimResponseStatus)
            throws BadRequestException, NotFoundException, CharonException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(NotImplementedException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new NotImplementedException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenThrow(NotImplementedException.class);
        SCIMResponse outputScimResponse = userResourceManager.updateWithPATCH(existingId, scimObjectString,
                userManager, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

    @DataProvider(name = "dataForUpdateWithPATCHInternalErrorException")
    public Object[][] dataToUpdateWithPATCHInternalErrorException()
            throws BadRequestException, CharonException, InternalErrorException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        JSONDecoder decoder = new JSONDecoder();

        User userOld = decoder.decodeResource(newUserSCIMObjectStringPatch, schema, new User());
        String id = userOld.getId();

        return new Object[][]{
                {id, newUserSCIMObjectStringPatchUpdate, "userName", null, internalError}
        };
    }

    //InternalErrorException
    @Test(dataProvider = "dataForUpdateWithPATCHInternalErrorException")
    public void testUpdateWithPATCHInternalErrorException(String existingId, String scimObjectString,
                                                          String attributes, String excludeAttributes,
                                                          int expectedScimResponseStatus
    )
            throws BadRequestException, NotFoundException, CharonException {

        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

        mockStatic(AbstractResourceManager.class);

        when(AbstractResourceManager.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT))
                .thenReturn(endpoint + "/" + userID);
        when(AbstractResourceManager.getEncoder()).thenReturn(new JSONEncoder());
        when(AbstractResourceManager.getDecoder()).thenReturn(new JSONDecoder());
        when(AbstractResourceManager.encodeSCIMException(any(InternalErrorException.class)))
                .thenReturn(getEncodeSCIMExceptionObject(new InternalErrorException()));

        when(userManager.getUser(existingId,
                ResourceManagerUtil.getAllAttributeURIs(schema))).thenThrow(InternalErrorException.class);

        SCIMResponse outputScimResponse = userResourceManager.updateWithPATCH(existingId, scimObjectString,
                userManager, attributes, excludeAttributes);
        Assert.assertEquals(outputScimResponse.getResponseStatus(), expectedScimResponseStatus);

    }

}
