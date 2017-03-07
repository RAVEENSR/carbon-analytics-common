/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.analytics.data.commons.exception;

/**
 * This exception represents a situation when the requested analytics data source table is not available.
 */
public class AnalyticsTableNotAvailableException extends AnalyticsException {

    private static final long serialVersionUID = -3197293684263626136L;
    private String tableName;

    public AnalyticsTableNotAvailableException(String tableName) {
        this(tableName, null);
    }

    public AnalyticsTableNotAvailableException(String tableName, Throwable cause) {
        super("Table: " + tableName + " does not exist", cause);
        this.tableName = tableName;
    }

    public String getTableName() {
        return tableName;
    }
}
