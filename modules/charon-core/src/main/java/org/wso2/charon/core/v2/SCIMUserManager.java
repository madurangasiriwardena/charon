/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.charon.core.v2;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.charon.core.v2.attributes.Attribute;
import org.wso2.charon.core.v2.attributes.SimpleAttribute;
import org.wso2.charon.core.v2.exceptions.BadRequestException;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.exceptions.ConflictException;
import org.wso2.charon.core.v2.exceptions.NotFoundException;
import org.wso2.charon.core.v2.exceptions.NotImplementedException;
import org.wso2.charon.core.v2.extensions.UserManager;
import org.wso2.charon.core.v2.objects.Group;
import org.wso2.charon.core.v2.objects.User;
import org.wso2.charon.core.v2.utils.codeutils.ExpressionNode;
import org.wso2.charon.core.v2.utils.codeutils.Node;
import org.wso2.charon.core.v2.utils.codeutils.SearchRequest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * SCIM User Manager
 */
public class SCIMUserManager implements UserManager {

    public static final String USER_NAME_STRING = "userName";
    public static final String SCIM_ENABLED = "SCIMEnabled";
    public static final String APPLICATION_DOMAIN = "Application";
    public static final String INTERNAL_DOMAIN = "Internal";
    private static final Logger logger = LoggerFactory.getLogger(SCIMUserManager.class);


    public SCIMUserManager() {
    }

    public User createUser(User user, Map<String, Boolean> requiredAttributes) throws CharonException {

        //TODO: Get the E-Tag(version) and add as a attribute of the cretated user
        try {
            FileOutputStream fileOut =
                    new FileOutputStream("/home/vindula/Desktop/Charon/Storage/" + user.getId() + ".ser");
            ObjectOutputStream out = new ObjectOutputStream(fileOut);
            out.writeObject(user);
            out.close();
            fileOut.close();
        } catch (IOException i) {
            logger.error(i.getMessage(), i);
        }
        return user;
    }

    @Override

    public User getUser(String id, Map<String, Boolean> requiredAttributes) {

        User e = null;
        try {
            FileInputStream fileIn = new FileInputStream("/home/vindula/Desktop/Charon/Storage/" + id + ".ser");
            ObjectInputStream in = new ObjectInputStream(fileIn);
            e = (User) in.readObject();
            in.close();
            fileIn.close();
        } catch (IOException i) {
            return null;
        } catch (ClassNotFoundException c) {
            logger.error("Employee class not found", c);
            return null;
        }
        return e;
    }

    @Override
    public void deleteUser(String userId) throws NotFoundException, CharonException {
        try {
            File file = new File("/home/vindula/Desktop/Charon/Storage/" + userId + ".ser");

            if (file.delete()) {

            } else {
                throw new CharonException("Error occurred while deleting");

            }
        } catch (Exception e) {
            throw new NotFoundException();
        }
    }

    @Override
    public List<Object> listUsersWithGET(Node node, int startIndex, int count, String sortBy, String sortOrder,
                                         Map<String, Boolean> requiredAttributes) throws CharonException,
            NotImplementedException, BadRequestException {
        return null;
    }


    public List<User> listUsers() throws CharonException {
        final File folder = new File("/home/vindula/Desktop/Charon/Storage/");
        List<User> userList = new ArrayList<User>();
        for (final File fileEntry : folder.listFiles()) {
            if (fileEntry.isDirectory()) {
                //listFilesForFolder(fileEntry);
            } else {
                User e = null;
                try {
                    FileInputStream fileIn = new FileInputStream("/home/vindula/Desktop/Charon/Storage/" + fileEntry
                            .getName());
                    ObjectInputStream in = new ObjectInputStream(fileIn);
                    e = (User) in.readObject();
                    in.close();
                    fileIn.close();
                } catch (FileNotFoundException e1) {
                    logger.error(e1.getMessage(), e1);
                } catch (IOException e1) {
                    logger.error(e1.getMessage(), e1);
                } catch (ClassNotFoundException e1) {
                    logger.error(e1.getMessage(), e1);
                }
                userList.add(e);
            }

        }
        return userList;
    }

    @Override
    public List<Object> listUsersWithPost(SearchRequest searchRequest, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {
        return null;

    }


    public List<User> listUsersWithPagination(int startIndex, int count) {
        final File folder = new File("/home/vindula/Desktop/Charon/Storage/");
        List<User> userList = new ArrayList<User>();
        for (final File fileEntry : folder.listFiles()) {
            if (fileEntry.isDirectory()) {
                //listFilesForFolder(fileEntry);
            } else {
                User e = null;
                try {
                    FileInputStream fileIn = new FileInputStream("/home/vindula/Desktop/Charon/Storage/" + fileEntry
                            .getName());
                    ObjectInputStream in = new ObjectInputStream(fileIn);
                    e = (User) in.readObject();
                    in.close();
                    fileIn.close();
                } catch (FileNotFoundException e1) {
                    logger.error(e1.getMessage(), e1);
                } catch (IOException e1) {
                    logger.error(e1.getMessage(), e1);
                } catch (ClassNotFoundException e1) {
                    logger.error(e1.getMessage(), e1);
                }
                userList.add(e);
            }

        }
        List<User> userListNew = new ArrayList<User>();
        for (int i = startIndex - 1; i < startIndex - 1 + count; i++) {
            userListNew.add(userList.get(i));
        }
        return userListNew;
    }

    public int getUserCount() {
        try {
            return listUsers().size();
        } catch (CharonException e) {
            logger.error(e.getMessage(), e);
            return 0;
        }
    }

    @Override
    public User updateUser(User validatedUser, Map<String, Boolean> requiredAttributes) {
        try {
            User user = createUser(validatedUser, null);
            return user;
        } catch (CharonException e) {
            logger.error(e.getMessage(), e);
            return null;
        }
    }


    public List<User> filterUsers(Node rootNode) {
        return null;
    }


    public List<User> sortUsers(String sortBy, String sortOrder) {
        //let the user core to handle the sorting
        try {
            return listUsers();
        } catch (CharonException e) {
            return null;
        }
    }

    @Override
    public User getMe(String userName, Map<String, Boolean> requiredAttributes) throws CharonException {
        return null;
    }

    @Override
    public User createMe(User user, Map<String, Boolean> requiredAttributes) throws CharonException,
            ConflictException, BadRequestException {
        return null;
    }

    @Override
    public void deleteMe(String userName) throws NotFoundException, CharonException, NotImplementedException {

    }

    @Override
    public User updateMe(User updatedUser, Map<String, Boolean> requiredAttributes) throws NotImplementedException {
        return null;
    }

    @Override
    public Group createGroup(Group group, Map<String, Boolean> requiredAttributes) throws CharonException,
            ConflictException {
        //TODO: Get the E-Tag(version) and add as a attribute of the cretated user
        try {
            FileOutputStream fileOut =
                    new FileOutputStream("/home/vindula/Desktop/Charon/GroupStorage/" + group.getId() + ".ser");
            ObjectOutputStream out = new ObjectOutputStream(fileOut);
            out.writeObject(group);
            out.close();
            fileOut.close();
        } catch (IOException i) {
            logger.error(i.getMessage(), i);
        }
        return group;
    }

    @Override
    public Group getGroup(String id, Map<String, Boolean> requiredAttributes) {
        Group e = null;
        try {
            FileInputStream fileIn = new FileInputStream("/home/vindula/Desktop/Charon/GroupStorage/" + id + ".ser");
            ObjectInputStream in = new ObjectInputStream(fileIn);
            e = (Group) in.readObject();
            in.close();
            fileIn.close();
        } catch (IOException i) {
            return null;
        } catch (ClassNotFoundException c) {
            logger.error(c.getMessage(), c);
            return null;
        }
        return e;
    }

    @Override
    public void deleteGroup(String id) throws NotFoundException {
        try {
            File file = new File("/home/vindula/Desktop/Charon/GroupStorage/" + id + ".ser");

            if (file.delete()) {

            } else {
                throw new CharonException("Error occurred while deleting");

            }
        } catch (Exception e) {
            throw new NotFoundException();
        }
    }

    @Override
    public List<Object> listGroupsWithGET(Node node, int startIndex, int count, String sortBy, String sortOrder,
                                          Map<String, Boolean> requiredAttributes) throws CharonException,
            NotImplementedException, BadRequestException {
        return null;
    }


    public List<Group> listGroups() throws CharonException {
        final File folder = new File("/home/vindula/Desktop/Charon/GroupStorage/");
        List<Group> userList = new ArrayList<Group>();
        for (final File fileEntry : folder.listFiles()) {
            if (fileEntry.isDirectory()) {
                //listFilesForFolder(fileEntry);
            } else {
                Group e = null;
                try {
                    FileInputStream fileIn = new FileInputStream("/home/vindula/Desktop/Charon/GroupStorage/" +
                            fileEntry.getName());
                    ObjectInputStream in = new ObjectInputStream(fileIn);
                    e = (Group) in.readObject();
                    in.close();
                    fileIn.close();
                } catch (FileNotFoundException e1) {
                    logger.error(e1.getMessage(), e1);
                } catch (IOException e1) {
                    logger.error(e1.getMessage(), e1);
                } catch (ClassNotFoundException e1) {
                    logger.error(e1.getMessage(), e1);
                }
                userList.add(e);
            }

        }
        return userList;
    }


    public int getGroupCount() {
        try {
            return listGroups().size();
        } catch (CharonException e) {
            logger.error(e.getMessage(), e);
        }
        return 0;
    }


    public List<Group> listGroupsWithPagination(int startIndex, int count) {
        final File folder = new File("/home/vindula/Desktop/Charon/GroupStorage/");
        List<Group> groupList = new ArrayList<Group>();
        for (final File fileEntry : folder.listFiles()) {
            if (fileEntry.isDirectory()) {
                //listFilesForFolder(fileEntry);
            } else {
                Group e = null;
                try {
                    FileInputStream fileIn = new FileInputStream("/home/vindula/Desktop/Charon/GroupStorage/" +
                            fileEntry.getName());
                    ObjectInputStream in = new ObjectInputStream(fileIn);
                    e = (Group) in.readObject();
                    in.close();
                    fileIn.close();
                } catch (FileNotFoundException e1) {
                    logger.error(e1.getMessage(), e1);
                } catch (IOException e1) {
                    logger.error(e1.getMessage(), e1);
                } catch (ClassNotFoundException e1) {
                    logger.error(e1.getMessage(), e1);
                }
                groupList.add(e);
            }

        }
        List<Group> groupListNew = new ArrayList<Group>();
        for (int i = startIndex - 1; i < startIndex - 1 + count; i++) {
            groupListNew.add(groupList.get(i));
        }
        return groupListNew;

    }


    public List<Group> filterGroups(Node rootNode) {
        if (rootNode instanceof ExpressionNode) {
            ExpressionNode en = (ExpressionNode) rootNode;
            String value = en.getValue();
            try {
                List<Group> list = listGroups();
                List<Group> newList = new ArrayList<Group>();
                for (Group group : list) {
                    Map<String, Attribute> attributeList = group.getAttributeList();
                    Attribute checkAttribute = attributeList.get("displayName");
                    if (checkAttribute != null) {
                        if (((SimpleAttribute) checkAttribute).getValue().equals(value)) {
                            newList.add(group);
                        }
                    }
                }
                return newList;
            } catch (CharonException e) {
                logger.error(e.getMessage(), e);
            }
        }
        return null;
    }


    public List<Group> sortGroups(String sortByAttributeURI, String sortOrder) {
        //let the user core to handle the sorting
        try {
            return listGroups();
        } catch (CharonException e) {
            return null;
        }
    }

    @Override
    public Group updateGroup(Group oldGroup, Group validatedGroup, Map<String, Boolean> requiredAttributes) {
        try {
            Group group = createGroup(validatedGroup, requiredAttributes);
            return group;
        } catch (CharonException e) {
            logger.error(e.getMessage(), e);
            return null;
        } catch (ConflictException e) {
            logger.error(e.getMessage(), e);
            return null;
        }
    }

    @Override
    public List<Object> listGroupsWithPost(SearchRequest searchRequest, Map<String, Boolean> requiredAttributes)
            throws NotImplementedException, BadRequestException, CharonException {
        return null;
    }
}


