/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.charon.core.v2.attributes;

import org.wso2.charon.core.v2.exceptions.CharonException;

import java.util.HashMap;
import java.util.Map;

/*
 * This class is a blueprint of ComplexAttribute defined in SCIM Core Schema Spec.
 */
public class ComplexAttribute extends AbstractAttribute{

    //If it is a complex attribute, it has a list of sub attributes.
    protected Map<String, Attribute> subAttributesList = new HashMap<String, Attribute>();

    public ComplexAttribute(String name) { this.name=name; }

    public ComplexAttribute() {}

    /**
     * Retrieve the map of sub attributes.
     *
     * @return Map of Attributes
     */
    public Map<String, Attribute> getSubAttributesList() {
            return subAttributesList;
        }

    /**
     * Set the map of sub attributes.
     *
     * @param subAttributesList
     */
    public void setSubAttributesList(Map<String, Attribute> subAttributesList) {
        this.subAttributesList = subAttributesList;
    }

    /**
     * Retrieve one attribute given the attribute name.
     *
     * @param attributeName
     * @return Attribute
     */
    public Attribute getSubAttribute(String attributeName) throws CharonException {
        if (subAttributesList.containsKey(attributeName)) {
            return subAttributesList.get(attributeName);
        } else {
            return null;
        }
    }

    @Override
    public void deleteSubAttributes() throws CharonException {
        subAttributesList.clear();
    }

    /**
     * Remove a sub attribute from the complex attribute given the sub attribute name.
     *
     * @param attributeName
     */
    public void removeSubAttribute(String attributeName) {
        if (subAttributesList.containsKey(attributeName)) {
            subAttributesList.remove(attributeName);
        }
    }

    /**
     * look for the existence of a sub attribute
     *
     * @param attributeName
     */
    public boolean isSubAttributeExist(String attributeName) {
        return subAttributesList.containsKey(attributeName);
    }

    /**
     * Set a sub attribute of the complex attribute's sub attribute list.
     *
     * @param subAttribute
     * @throws CharonException
     */
    public void setSubAttribute(Attribute subAttribute)
            throws CharonException {
        subAttributesList.put(subAttribute.getName(), subAttribute);
    }
    }
