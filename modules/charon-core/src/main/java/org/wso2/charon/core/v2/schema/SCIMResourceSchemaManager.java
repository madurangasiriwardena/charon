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
package org.wso2.charon.core.v2.schema;

/*
* This is to check for extension schema for the user and buildTree a
* custom user schema with it. Unless a extension is defined,
* core-user schema need to be returned.
*/

import org.wso2.charon.core.v2.config.SCIMUserSchemaExtensionBuilder;

import java.util.ArrayList;
import java.util.Arrays;

public class SCIMResourceSchemaManager {

	private static SCIMResourceSchemaManager manager = new SCIMResourceSchemaManager();

	public static SCIMResourceSchemaManager getInstance() {
		return manager;
	}

	/**
	 * Return the SCIM User Resource Schema
	 *
	 * @return SCIMResourceTypeSchema
	 */
	public SCIMResourceTypeSchema getUserResourceSchema() {


		SCIMAttributeSchema schemaExtension = SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema();
		if (schemaExtension != null) {
			return SCIMResourceTypeSchema.createSCIMResourceSchema(
					new ArrayList<String>(Arrays.asList(SCIMConstants.USER_CORE_SCHEMA_URI, schemaExtension.getURI())),
					SCIMSchemaDefinitions.ID, SCIMSchemaDefinitions.EXTERNAL_ID, SCIMSchemaDefinitions.META,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.USERNAME,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.NAME,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.DISPLAY_NAME,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.NICK_NAME,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.PROFILE_URL,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.TITLE,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.USER_TYPE,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.PREFERRED_LANGUAGE,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.LOCALE,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.TIME_ZONE,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.ACTIVE,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.PASSWORD,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.EMAILS,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.PHONE_NUMBERS,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.IMS,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.PHOTOS,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.ADDRESSES,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.GROUPS,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.ENTITLEMENTS,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.ROLES,
					SCIMSchemaDefinitions.SCIMUserSchemaDefinition.X509CERTIFICATES,
					schemaExtension);
		}
		return SCIMSchemaDefinitions.SCIM_USER_SCHEMA;
	}

	public Boolean isExtensionSet() {
		int numOfCoreAttributes = SCIMSchemaDefinitions.SCIM_USER_SCHEMA.getAttributesList().size();

		SCIMAttributeSchema schemaExtension = SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema();
		if (schemaExtension != null) {
			return true;
		} else {
			return false;
		}
	}

	public String getExtensionName() {
		SCIMAttributeSchema schemaExtension = SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema();
		if (schemaExtension == null) {
			return null;
		}
		return schemaExtension.getName();
	}

	public String getExtensionURI() {
		SCIMAttributeSchema schemaExtension = SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema();
		if (schemaExtension == null) {
			return null;
		}
		return schemaExtension.getURI();
	}

	public boolean getExtensionRequired() {
		SCIMAttributeSchema schemaExtension = SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema();
		if (schemaExtension == null) {
			return false;
		}
		return schemaExtension.getRequired();
	}

	/**
	 * return service provider config resource schema
	 * @return
     */
	public SCIMResourceTypeSchema getServiceProviderConfigResourceSchema() {
		return SCIMSchemaDefinitions.SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA;
	}

	/**
	 * return group resource schema
	 * @return
	 */
	public SCIMResourceTypeSchema getGroupResourceSchema() {
		return SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA;
	}

	/**
	 * return resource type resource schema
	 * @return
	 */
	public SCIMResourceTypeSchema getResourceTypeResourceSchema() {
		return SCIMSchemaDefinitions.SCIM_RESOURCE_TYPE_SCHEMA;
	}

}